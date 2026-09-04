use camino::{Utf8Path, Utf8PathBuf};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct MetadataReader {
    allowed: BTreeMap<String, MetadataFormat>,
    max_bytes: u64,
    max_entries: usize,
    max_nesting: usize,
    max_parse_time: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataFormat {
    Json,
    Toml,
    Text,
}

#[derive(Clone, Debug)]
pub struct MetadataRequest {
    pub path: Utf8PathBuf,
    pub format: MetadataFormat,
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_nesting: usize,
    pub max_parse_time: Duration,
}

impl MetadataRequest {
    pub fn development(path: Utf8PathBuf, format: MetadataFormat, max_bytes: u64) -> Self {
        Self {
            path,
            format,
            max_bytes,
            max_entries: 10_000,
            max_nesting: 64,
            max_parse_time: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataStatus {
    Complete,
    Truncated,
    Malformed,
    ParseTimedOut,
    Unsupported,
    Stale,
}

#[derive(Clone, Debug)]
pub struct MetadataOutcome {
    pub path: Utf8PathBuf,
    pub status: MetadataStatus,
    pub bytes: Vec<u8>,
    pub digest: String,
}

impl MetadataReader {
    pub fn development_defaults(max_bytes: u64) -> Self {
        Self {
            allowed: [
                ("Cargo.toml", MetadataFormat::Toml),
                ("Cargo.lock", MetadataFormat::Toml),
                ("package.json", MetadataFormat::Json),
                ("package-lock.json", MetadataFormat::Json),
                ("pnpm-lock.yaml", MetadataFormat::Text),
                ("yarn.lock", MetadataFormat::Text),
                ("pyproject.toml", MetadataFormat::Toml),
                ("uv.lock", MetadataFormat::Toml),
                ("requirements.txt", MetadataFormat::Text),
                ("mix.exs", MetadataFormat::Text),
                ("mix.lock", MetadataFormat::Text),
                ("rebar.config", MetadataFormat::Text),
                ("go.mod", MetadataFormat::Text),
                ("go.sum", MetadataFormat::Text),
                ("pom.xml", MetadataFormat::Text),
                ("build.gradle", MetadataFormat::Text),
                ("build.gradle.kts", MetadataFormat::Text),
                ("Package.swift", MetadataFormat::Text),
                (".gitignore", MetadataFormat::Text),
            ]
            .into_iter()
            .map(|(name, format)| (name.to_owned(), format))
            .collect(),
            max_bytes,
            max_entries: 10_000,
            max_nesting: 64,
            max_parse_time: Duration::from_millis(100),
        }
    }

    pub fn read(&self, request: MetadataRequest) -> io::Result<MetadataOutcome> {
        self.read_with_hook(request, || {})
    }

    fn read_with_hook(
        &self,
        request: MetadataRequest,
        after_read: impl FnOnce(),
    ) -> io::Result<MetadataOutcome> {
        let path = &request.path;
        let Some(name) = path.file_name() else {
            return Ok(unsupported(path));
        };
        if self.allowed.get(name) != Some(&request.format) {
            return Ok(unsupported(path));
        }
        if request.max_bytes > self.max_bytes
            || request.max_entries > self.max_entries
            || request.max_nesting > self.max_nesting
            || request.max_parse_time > self.max_parse_time
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "metadata request exceeds reader policy",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file() || fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "metadata must be a regular no-follow file",
            ));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(request.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        after_read();
        let held = file.metadata()?;
        let current = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(stale(path)),
            Err(error) => return Err(error),
        };
        if !same_metadata(&before, &held)
            || !same_metadata(&held, &current)
            || !current.is_file()
            || current.file_type().is_symlink()
        {
            return Ok(stale(path));
        }
        let status = if bytes.len() as u64 > request.max_bytes {
            bytes.truncate(request.max_bytes as usize);
            MetadataStatus::Truncated
        } else {
            self.validate(&request, &bytes)
        };
        let digest = blake3::hash(&bytes).to_hex().to_string();
        Ok(MetadataOutcome {
            path: path.to_owned(),
            status,
            bytes,
            digest,
        })
    }

    fn validate(&self, request: &MetadataRequest, bytes: &[u8]) -> MetadataStatus {
        let started = Instant::now();
        if std::str::from_utf8(bytes).is_err() {
            return MetadataStatus::Malformed;
        }
        if bytes.contains(&0) {
            return MetadataStatus::Malformed;
        }
        let mut depth = 0usize;
        let mut entries = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for byte in bytes {
            if started.elapsed() > request.max_parse_time {
                return MetadataStatus::ParseTimedOut;
            }
            if quoted {
                if escaped {
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            if *byte == b'"' {
                quoted = true;
                continue;
            }
            match byte {
                b'{' | b'[' | b'(' => {
                    depth += 1;
                    if depth > request.max_nesting {
                        return MetadataStatus::Malformed;
                    }
                }
                b'}' | b']' | b')' => depth = depth.saturating_sub(1),
                b',' | b'\n' | b'=' | b':' | b'<' => {
                    entries += 1;
                    if entries > request.max_entries {
                        return MetadataStatus::Malformed;
                    }
                }
                _ => {}
            }
        }
        if depth != 0 || quoted {
            return MetadataStatus::Malformed;
        }
        let remaining = request.max_parse_time.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return MetadataStatus::ParseTimedOut;
        }
        let parsed = if request.format == MetadataFormat::Text {
            true
        } else {
            let (sender, receiver) = mpsc::sync_channel(1);
            let owned = bytes.to_vec();
            let format = request.format;
            std::thread::spawn(move || {
                let valid = match format {
                    MetadataFormat::Json => {
                        serde_json::from_slice::<serde_json::Value>(&owned).is_ok()
                    }
                    MetadataFormat::Toml => std::str::from_utf8(&owned).is_ok_and(|value| {
                        !value.trim().is_empty() && toml::from_str::<toml::Table>(value).is_ok()
                    }),
                    MetadataFormat::Text => true,
                };
                let _ = sender.send(valid);
            });
            match receiver.recv_timeout(remaining) {
                Ok(valid) if started.elapsed() <= request.max_parse_time => valid,
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {
                    return MetadataStatus::ParseTimedOut;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => false,
            }
        };
        if parsed {
            MetadataStatus::Complete
        } else {
            MetadataStatus::Malformed
        }
    }
}

fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file() == right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn stale(path: &Utf8Path) -> MetadataOutcome {
    MetadataOutcome {
        path: path.to_owned(),
        status: MetadataStatus::Stale,
        bytes: vec![],
        digest: blake3::hash(&[]).to_hex().to_string(),
    }
}

fn unsupported(path: &Utf8Path) -> MetadataOutcome {
    MetadataOutcome {
        path: path.to_owned(),
        status: MetadataStatus::Unsupported,
        bytes: vec![],
        digest: blake3::hash(&[]).to_hex().to_string(),
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn request(path: Utf8PathBuf) -> MetadataRequest {
        MetadataRequest::development(path, MetadataFormat::Toml, 4096)
    }

    #[test]
    fn replacement_disappearance_and_content_mutation_are_stale() {
        for case in ["replace", "disappear", "mutate"] {
            let temp = tempfile::tempdir().unwrap();
            let path = Utf8PathBuf::from_path_buf(temp.path().join("Cargo.toml")).unwrap();
            fs::write(&path, "[package]\nname='before'\n").unwrap();
            let hook_path = path.clone();
            let outcome = MetadataReader::development_defaults(4096)
                .read_with_hook(request(path.clone()), move || match case {
                    "replace" => {
                        fs::rename(&hook_path, hook_path.with_extension("old")).unwrap();
                        fs::write(&hook_path, "[package]\nname='replacement'\n").unwrap();
                    }
                    "disappear" => fs::remove_file(&hook_path).unwrap(),
                    "mutate" => {
                        fs::write(&hook_path, "[package]\nname='changed-longer'\n").unwrap()
                    }
                    _ => unreachable!(),
                })
                .unwrap();
            assert_eq!(outcome.status, MetadataStatus::Stale, "{case}");
            assert!(outcome.bytes.is_empty(), "{case}");
        }
    }

    #[test]
    fn unrelated_concurrent_change_does_not_invalidate_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let path = root.join("Cargo.toml");
        fs::write(&path, "[package]\nname='stable'\n").unwrap();
        let unrelated = root.join("unrelated");
        let outcome = MetadataReader::development_defaults(4096)
            .read_with_hook(request(path), || fs::write(unrelated, b"changed").unwrap())
            .unwrap();
        assert_eq!(outcome.status, MetadataStatus::Complete);
    }
}
