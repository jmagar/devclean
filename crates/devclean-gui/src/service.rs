use camino::{Utf8Path, Utf8PathBuf};
use devclean::config::{Config, Presentation, ScanLimits};
use devclean::private_store::PrivateStore;
use devclean::report::{ReportStore, ScanReportV1, write_redacted};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const REPORT_LIMIT: u64 = 256 * 1024 * 1024;
const CONFIG_IMPORT_LIMIT: u64 = 1024 * 1024;

const SCAN_INCOMPLETE_EXIT_CODE: i32 = 2;
const SCANNER_PROTOCOL_VERSION: &str = "1";

#[derive(Debug, Default)]
struct ActiveScanner(Mutex<ActiveScannerState>);

#[derive(Debug, Default)]
struct ActiveScannerState {
    pid: Option<u32>,
    cancel_requested: bool,
}

impl ActiveScanner {
    fn cancel(&self) {
        if let Ok(mut active) = self.0.lock() {
            active.cancel_requested = true;
            if let Some(pid) = active.pid {
                unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
            }
        }
    }

    fn register(&self, pid: u32) {
        if let Ok(mut active) = self.0.lock() {
            active.pid = Some(pid);
            if active.cancel_requested {
                unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
            }
        }
    }

    fn clear(&self) {
        if let Ok(mut active) = self.0.lock() {
            active.pid = None;
            active.cancel_requested = false;
        }
    }
}

impl Drop for ActiveScanner {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct ChildGuard {
    child: Option<Child>,
    active: Arc<ActiveScanner>,
}

impl ChildGuard {
    fn wait(mut self) -> std::io::Result<(std::process::ExitStatus, Vec<u8>)> {
        let child = self.child.as_mut().expect("child guard owns process");
        let stderr = child.stderr.take();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = stderr {
                std::io::Read::by_ref(&mut pipe)
                    .take(1024 * 1024)
                    .read_to_end(&mut bytes)?;
                std::io::copy(&mut pipe, &mut std::io::sink())?;
            }
            Ok::<_, std::io::Error>(bytes)
        });
        let status = child.wait()?;
        let stderr = reader
            .join()
            .map_err(|_| std::io::Error::other("scanner stderr reader panicked"))??;
        self.child = None;
        self.active.clear();
        Ok((status, stderr))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            self.active.cancel();
            let _ = child.wait();
        }
        self.active.clear();
    }
}

#[derive(Clone, Debug)]
struct ScannerProcessAdapter {
    binary: Utf8PathBuf,
    active: Arc<ActiveScanner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScannerCompletion {
    Complete,
    Incomplete,
}

impl ScannerProcessAdapter {
    fn run(
        &self,
        config: &Utf8Path,
        store: &Utf8Path,
        scan_id: &str,
    ) -> Result<ScannerCompletion, String> {
        if !self.binary.is_file() {
            return Err(format!(
                "Scanner binary not found at {}. Build the workspace or set DEVCLEAN_BIN.",
                self.binary
            ));
        }
        let protocol = Command::new(&self.binary)
            .arg("protocol-version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        if !protocol.status.success()
            || String::from_utf8_lossy(&protocol.stdout).trim() != SCANNER_PROTOCOL_VERSION
        {
            return Err("Scanner protocol is incompatible with this app".into());
        }
        let mut command = Command::new(&self.binary);
        command
            .args(["scan", config.as_str(), store.as_str(), scan_id])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn().map_err(|e| e.to_string())?;
        self.active.register(child.id());
        let (status, stderr) = ChildGuard {
            child: Some(child),
            active: Arc::clone(&self.active),
        }
        .wait()
        .map_err(|e| e.to_string())?;
        match (status.success(), status.code()) {
            (true, _) => Ok(ScannerCompletion::Complete),
            (false, Some(SCAN_INCOMPLETE_EXIT_CODE)) => Ok(ScannerCompletion::Incomplete),
            _ => {
                let message = String::from_utf8_lossy(&stderr);
                Err(if message.trim().is_empty() {
                    format!("scan exited with {status}")
                } else {
                    message.trim().to_owned()
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppPaths {
    pub store: Utf8PathBuf,
    pub config: Utf8PathBuf,
}

impl AppPaths {
    pub fn default_for_home(home: &Utf8Path) -> Self {
        let store = home.join("Library/Application Support/devclean");
        Self {
            config: store.join("config.toml"),
            store,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppService {
    pub paths: AppPaths,
    pub devclean_binary: Utf8PathBuf,
    active_scanner: Arc<ActiveScanner>,
}

impl AppService {
    pub fn discover() -> Result<Self, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME is unavailable".to_string())?;
        let home = Utf8PathBuf::from(home);
        let current = std::env::current_exe().map_err(|e| e.to_string())?;
        let current = Utf8PathBuf::from_path_buf(current)
            .map_err(|_| "application path is not UTF-8".to_string())?;
        let binary = std::env::var("DEVCLEAN_BIN")
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|_| current.with_file_name("devclean"));
        Ok(Self {
            paths: AppPaths::default_for_home(&home),
            devclean_binary: binary,
            active_scanner: Arc::default(),
        })
    }

    pub fn ensure_initialized(&self) -> Result<(), String> {
        let _ = PrivateStore::create(&self.paths.store).map_err(|e| e.to_string())?;
        if !self.paths.config.exists() {
            self.save_config(&Config {
                approved_roots: BTreeSet::new(),
                approved_caches: BTreeSet::new(),
                exclusions: BTreeSet::new(),
                docker: None,
                presentation: Presentation { terminal_rows: 20 },
                limits: ScanLimits::default(),
            })?;
        }
        Ok(())
    }

    pub fn load_config(&self) -> Result<Config, String> {
        let source = fs::read_to_string(&self.paths.config).map_err(|e| e.to_string())?;
        Config::parse(&source).map_err(|e| e.to_string())
    }

    pub fn save_config(&self, config: &Config) -> Result<(), String> {
        let source = toml::to_string_pretty(config).map_err(|e| e.to_string())?;
        let store = PrivateStore::create(&self.paths.store).map_err(|e| e.to_string())?;
        store
            .replace_atomic("config.toml", |file| {
                file.write_all(source.as_bytes())?;
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn add_root(&self, path: Utf8PathBuf) -> Result<Config, String> {
        let canonical = fs::canonicalize(&path).map_err(|e| e.to_string())?;
        let canonical = Utf8PathBuf::from_path_buf(canonical)
            .map_err(|_| "selected path is not UTF-8".to_string())?;
        let mut config = self.load_config()?;
        config.approved_roots.insert(canonical);
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn remove_root(&self, path: &Utf8Path) -> Result<Config, String> {
        let mut config = self.load_config()?;
        config.approved_roots.remove(path);
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn import_config(&self, path: &Utf8Path) -> Result<Config, String> {
        let source = read_bounded_config(path)?;
        let config = Config::import_proposed(&source, true)?;
        config.authorized_traversal_scope()?;
        config.approved_docker()?;
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn scan(&self) -> Result<ScanReportV1, String> {
        let scan_id = format!(
            "scan-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis()
        );
        ScannerProcessAdapter {
            binary: self.devclean_binary.clone(),
            active: Arc::clone(&self.active_scanner),
        }
        .run(&self.paths.config, &self.paths.store, &scan_id)?;
        self.report_store()?
            .read(&scan_id)
            .map_err(|e| e.to_string())
    }

    pub fn cancel_scan(&self) {
        self.active_scanner.cancel();
    }

    pub fn load_latest(&self) -> Result<Option<ScanReportV1>, String> {
        let store = self.report_store()?;
        let Some(scan_id) = store.latest_valid_report_id().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        store.read(&scan_id).map(Some).map_err(|e| e.to_string())
    }

    pub fn export_redacted(&self, report: &ScanReportV1, path: &Utf8Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "export destination has no parent directory".to_string())?;
        let file_name = path
            .file_name()
            .ok_or_else(|| "export destination has no file name".to_string())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let temp = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        let result = (|| {
            write_redacted(report, &mut file).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temp, path).map_err(|e| e.to_string())?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn report_store(&self) -> Result<ReportStore, String> {
        let store = PrivateStore::create(&self.paths.store).map_err(|e| e.to_string())?;
        Ok(ReportStore::new(store, REPORT_LIMIT))
    }
}

#[cfg(test)]
fn is_full_report_name(name: &str) -> bool {
    devclean::report::full_report_id(name).is_some()
}

fn read_bounded_config(path: &Utf8Path) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("configuration must be a regular file".into());
    }
    if metadata.len() > CONFIG_IMPORT_LIMIT {
        return Err("configuration exceeds the 1 MiB import limit".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(CONFIG_IMPORT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > CONFIG_IMPORT_LIMIT {
        return Err("configuration exceeds the 1 MiB import limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "configuration is not valid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use devclean_core::CoverageStatus;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn config_round_trip_and_root_guard_are_safe() {
        let temp = tempfile::Builder::new()
            .prefix("devclean-gui-test-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let home = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let service = AppService {
            paths: AppPaths {
                store: home.join("store"),
                config: home.join("store/config.toml"),
            },
            devclean_binary: home.join("devclean"),
            active_scanner: Arc::default(),
        };
        service.ensure_initialized().unwrap();
        let config = service.load_config().unwrap();
        assert!(config.approved_roots.is_empty());
        assert_eq!(
            service.add_root(home.clone()).unwrap().approved_roots.len(),
            1
        );
        assert!(
            service
                .remove_root(&home)
                .unwrap()
                .approved_roots
                .is_empty()
        );
    }

    #[test]
    fn import_rejects_oversized_and_symlinked_configs() {
        let temp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let oversized = base.join("oversized.toml");
        fs::write(&oversized, vec![b'x'; CONFIG_IMPORT_LIMIT as usize + 1]).unwrap();
        assert!(
            read_bounded_config(&oversized)
                .unwrap_err()
                .contains("1 MiB")
        );

        let target = base.join("target.toml");
        fs::write(&target, b"approved_roots=[]\n").unwrap();
        let link = base.join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded_config(&link).is_err());
    }

    #[test]
    fn report_name_filter_excludes_redacted_and_malformed_neighbors() {
        assert!(is_full_report_name("scan-123456.json"));
        assert!(!is_full_report_name("scan-123456-redacted.json"));
        assert!(!is_full_report_name("scan-latest.json"));
        assert!(!is_full_report_name("scan-123456.json.tmp"));
    }

    #[test]
    fn scanner_process_adapter_has_typed_complete_and_incomplete_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let binary = Utf8PathBuf::from_path_buf(temp.path().join("scanner")).unwrap();
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = protocol-version ]; then echo 1; exit 0; fi\nexit \"${DEVCLEAN_TEST_EXIT:-0}\"\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let adapter = ScannerProcessAdapter {
            binary,
            active: Arc::default(),
        };
        let root = Utf8Path::from_path(temp.path()).unwrap();
        assert_eq!(
            adapter.run(root, root, "scan").unwrap(),
            ScannerCompletion::Complete
        );
        // Exercise the public process contract's named incomplete status by
        // using a second deterministic fixture executable.
        let incomplete = root.join("incomplete");
        fs::write(
            &incomplete,
            "#!/bin/sh\nif [ \"$1\" = protocol-version ]; then echo 1; exit 0; fi\nexit 2\n",
        )
        .unwrap();
        fs::set_permissions(&incomplete, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            ScannerProcessAdapter {
                binary: incomplete,
                active: Arc::default(),
            }
            .run(root, root, "scan")
            .unwrap(),
            ScannerCompletion::Incomplete
        );
    }

    #[test]
    fn scanner_process_adapter_cancels_and_reaps_the_process_group() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let binary = root.join("scanner");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = protocol-version ]; then echo 1; exit 0; fi\nsleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let active = Arc::new(ActiveScanner::default());
        let adapter = ScannerProcessAdapter {
            binary,
            active: Arc::clone(&active),
        };
        let scan_root = root.clone();
        let worker = std::thread::spawn(move || adapter.run(&scan_root, &scan_root, "scan"));
        for _ in 0..100 {
            if active.0.lock().unwrap().pid.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(active.0.lock().unwrap().pid.is_some());
        active.cancel();
        assert!(worker.join().unwrap().is_err());
        assert!(active.0.lock().unwrap().pid.is_none());
    }

    #[test]
    fn scanner_process_adapter_drains_large_stderr_without_deadlock() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let binary = root.join("scanner");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = protocol-version ]; then echo 1; exit 0; fi\ni=0; while [ $i -lt 12000 ]; do echo 'progress progress progress progress' >&2; i=$((i+1)); done\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            ScannerProcessAdapter {
                binary,
                active: Arc::default(),
            }
            .run(&root, &root, "scan")
            .unwrap(),
            ScannerCompletion::Complete
        );
    }

    #[test]
    fn scanner_process_adapter_honors_cancel_before_registration() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let binary = root.join("scanner");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = protocol-version ]; then echo 1; exit 0; fi\nsleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let active = Arc::new(ActiveScanner::default());
        active.cancel();
        let result = ScannerProcessAdapter {
            binary,
            active: Arc::clone(&active),
        }
        .run(&root, &root, "scan");
        assert!(result.is_err());
        assert!(active.0.lock().unwrap().pid.is_none());
    }

    fn empty_report(scan_id: &str) -> ScanReportV1 {
        ScanReportV1 {
            schema_version: 1,
            scan_id: scan_id.into(),
            safety_fingerprint: "safe".into(),
            scope_fingerprint: "scope".into(),
            coverage: CoverageStatus::Complete,
            candidates: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn latest_report_skips_a_newer_corrupt_neighbor() {
        let temp = tempfile::Builder::new()
            .prefix("devclean-gui-report-test-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store_path = root.join("store");
        let private = PrivateStore::create(&store_path).unwrap();
        ReportStore::new(private, REPORT_LIMIT)
            .write(&empty_report("scan-1"))
            .unwrap();
        fs::write(store_path.join("scan-2.json"), b"not-json").unwrap();
        fs::set_permissions(
            store_path.join("scan-2.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let service = AppService {
            paths: AppPaths {
                config: store_path.join("config.toml"),
                store: store_path,
            },
            devclean_binary: root.join("devclean"),
            active_scanner: Arc::default(),
        };
        assert_eq!(service.load_latest().unwrap().unwrap().scan_id, "scan-1");
    }

    #[test]
    fn redacted_export_atomically_replaces_a_confirmed_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let destination = root.join("report.json");
        fs::write(&destination, b"old").unwrap();
        let service = AppService {
            paths: AppPaths {
                config: root.join("config.toml"),
                store: root.join("store"),
            },
            devclean_binary: root.join("devclean"),
            active_scanner: Arc::default(),
        };
        service
            .export_redacted(&empty_report("scan-1"), &destination)
            .unwrap();
        let exported = fs::read_to_string(destination).unwrap();
        assert!(exported.contains("\"usable_for_cleanup\":false"));
    }
}
