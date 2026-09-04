use camino::Utf8PathBuf;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub executable: Utf8PathBuf,
    pub args: Vec<String>,
    pub cwd: Utf8PathBuf,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Success,
    Exit(i32),
    TimedOut,
    OutputTruncated,
}

#[derive(Clone, Debug)]
pub struct CommandOutcome {
    pub status: CommandStatus,
    pub stdout: Vec<u8>,
    pub stderr_was_present: bool,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("executable must be an absolute regular file")]
    UntrustedExecutable,
    #[error("working directory must be a directory")]
    InvalidCwd,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct CommandRunner;

impl CommandRunner {
    pub fn run(&self, spec: &CommandSpec) -> Result<CommandOutcome, CommandError> {
        if !spec.executable.is_absolute() {
            return Err(CommandError::UntrustedExecutable);
        }
        let before = fs::symlink_metadata(&spec.executable)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(CommandError::UntrustedExecutable);
        }
        if !["/bin", "/usr/bin", "/usr/sbin"]
            .iter()
            .any(|root| spec.executable.starts_with(root))
        {
            return Err(CommandError::UntrustedExecutable);
        }
        if before.uid() != 0 || before.permissions().mode() & 0o022 != 0 {
            return Err(CommandError::UntrustedExecutable);
        }
        let parent = spec
            .executable
            .parent()
            .ok_or(CommandError::UntrustedExecutable)?;
        for ancestor in parent.ancestors() {
            let metadata = fs::metadata(ancestor)?;
            if !metadata.is_dir()
                || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
                || (metadata.permissions().mode() & 0o022 != 0
                    && metadata.permissions().mode() & u32::from(libc::S_ISVTX) == 0)
            {
                return Err(CommandError::UntrustedExecutable);
            }
        }
        let canonical_cwd = fs::canonicalize(&spec.cwd)?;
        let cwd_before = fs::metadata(&canonical_cwd)?;
        if !cwd_before.is_dir() {
            return Err(CommandError::InvalidCwd);
        }
        let executable = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&spec.executable)?;
        let verified = executable.metadata()?;
        if !same_identity(&before, &verified) {
            return Err(CommandError::UntrustedExecutable);
        }
        let before_spawn = fs::symlink_metadata(&spec.executable)?;
        if !same_identity(&verified, &before_spawn) {
            return Err(CommandError::UntrustedExecutable);
        }
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&canonical_cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let held_after = executable.metadata()?;
        let after_spawn = fs::symlink_metadata(&spec.executable)?;
        if !same_identity(&verified, &held_after) || !same_identity(&verified, &after_spawn) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CommandError::UntrustedExecutable);
        }
        let cwd_after = fs::metadata(&canonical_cwd)?;
        if cwd_before.dev() != cwd_after.dev() || cwd_before.ino() != cwd_after.ino() {
            let _ = child.kill();
            return Err(CommandError::InvalidCwd);
        }
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let limit = spec.output_limit;
        let out_thread = thread::spawn(move || read_bounded(stdout, limit));
        let err_thread = thread::spawn(move || read_bounded(stderr, limit));
        let deadline = Instant::now() + spec.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status.code().map_or(CommandStatus::Exit(-1), |code| {
                    if code == 0 {
                        CommandStatus::Success
                    } else {
                        CommandStatus::Exit(code)
                    }
                });
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGTERM);
                }
                thread::sleep(Duration::from_millis(20));
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                break CommandStatus::TimedOut;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let (stdout, out_truncated) = out_thread.join().unwrap_or_default();
        let (stderr, err_truncated) = err_thread.join().unwrap_or_default();
        let status =
            if !matches!(status, CommandStatus::TimedOut) && (out_truncated || err_truncated) {
                CommandStatus::OutputTruncated
            } else {
                status
            };
        Ok(CommandOutcome {
            status,
            stdout,
            stderr_was_present: !stderr.is_empty(),
        })
    }
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn read_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let _ = reader
        .by_ref()
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes);
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    (bytes, truncated)
}

#[cfg(test)]
mod identity_tests {
    use super::same_identity;

    #[test]
    fn executable_replacement_identity_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tool");
        std::fs::write(&path, b"before").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, b"after").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert!(!same_identity(&before, &after));
    }
}
