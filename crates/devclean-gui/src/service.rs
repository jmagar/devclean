use camino::{Utf8Path, Utf8PathBuf};
use devclean::config::{Config, Presentation};
use devclean::private_store::PrivateStore;
use devclean::report::{ReportStore, ScanReportV1, write_redacted};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const REPORT_LIMIT: u64 = 256 * 1024 * 1024;

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
        })
    }

    pub fn ensure_initialized(&self) -> Result<(), String> {
        fs::create_dir_all(&self.paths.store).map_err(|e| e.to_string())?;
        fs::set_permissions(&self.paths.store, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let _ = PrivateStore::create(&self.paths.store).map_err(|e| e.to_string())?;
        if !self.paths.config.exists() {
            self.save_config(&Config {
                approved_roots: BTreeSet::new(),
                approved_caches: BTreeSet::new(),
                exclusions: BTreeSet::new(),
                docker: None,
                presentation: Presentation { terminal_rows: 20 },
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
        let temp = self.paths.config.with_extension("toml.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        if let Err(error) = file
            .write_all(source.as_bytes())
            .and_then(|_| file.sync_all())
        {
            let _ = fs::remove_file(&temp);
            return Err(error.to_string());
        }
        fs::rename(&temp, &self.paths.config).map_err(|e| e.to_string())?;
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
        let source = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let config = Config::import_proposed(&source, true)?;
        config.authorized_traversal_scope()?;
        config.approved_docker()?;
        self.save_config(&config)?;
        Ok(config)
    }

    pub fn scan(&self) -> Result<ScanReportV1, String> {
        if !self.devclean_binary.is_file() {
            return Err(format!(
                "Scanner binary not found at {}. Build the workspace or set DEVCLEAN_BIN.",
                self.devclean_binary
            ));
        }
        let scan_id = format!(
            "scan-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_millis()
        );
        let output = Command::new(&self.devclean_binary)
            .args([
                "scan",
                self.paths.config.as_str(),
                self.paths.store.as_str(),
                &scan_id,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() && output.status.code() != Some(2) {
            let message = String::from_utf8_lossy(&output.stderr);
            return Err(if message.trim().is_empty() {
                format!("scan exited with {}", output.status)
            } else {
                message.trim().to_owned()
            });
        }
        self.report_store()?
            .read(&scan_id)
            .map_err(|e| e.to_string())
    }

    pub fn load_latest(&self) -> Result<Option<ScanReportV1>, String> {
        let mut reports = fs::read_dir(&self.paths.store)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                (name.starts_with("scan-") && name.ends_with(".json")).then_some(name)
            })
            .collect::<Vec<_>>();
        reports.sort();
        let Some(name) = reports.pop() else {
            return Ok(None);
        };
        let scan_id = name.trim_end_matches(".json");
        self.report_store()?
            .read(scan_id)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub fn export_redacted(&self, report: &ScanReportV1, path: &Utf8Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        write_redacted(report, &mut file).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())
    }

    fn report_store(&self) -> Result<ReportStore, String> {
        let store = PrivateStore::create(&self.paths.store).map_err(|e| e.to_string())?;
        Ok(ReportStore::new(store, REPORT_LIMIT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
