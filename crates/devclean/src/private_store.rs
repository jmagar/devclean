use camino::{Utf8Path, Utf8PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PrivateStore {
    root: Utf8PathBuf,
}

impl PrivateStore {
    pub fn temporary_child(&self) -> Result<(tempfile::TempDir, Self), StoreError> {
        validate(&self.root, true)?;
        let directory = tempfile::Builder::new()
            .prefix("scan-spill-")
            .tempdir_in(&self.root)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = Utf8PathBuf::from_path_buf(directory.path().to_path_buf())
            .map_err(|_| StoreError::InvalidName)?;
        let store = Self::create(&path)?;
        Ok((directory, store))
    }

    pub fn create(root: &Utf8Path) -> Result<Self, StoreError> {
        let parent = root
            .parent()
            .ok_or_else(|| StoreError::Insecure(root.to_owned()))?;
        if parent.ancestors().any(|ancestor| {
            fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink())
        }) {
            return Err(StoreError::Insecure(parent.to_owned()));
        }
        let canonical_parent = fs::canonicalize(parent)?;
        let canonical_parent =
            Utf8PathBuf::from_path_buf(canonical_parent).map_err(|_| StoreError::InvalidName)?;
        let name = root.file_name().ok_or(StoreError::InvalidName)?;
        let root = canonical_parent.join(name);
        validate_ancestor_chain(&root)?;
        if fs::symlink_metadata(&root).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
            return Err(StoreError::Insecure(root));
        }
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        validate_ancestor_chain(&root)?;
        validate(&root, true)?;
        Ok(Self { root })
    }

    pub fn create_new(&self, name: &str, bytes: &[u8]) -> Result<Utf8PathBuf, StoreError> {
        if name.contains('/') || name.chars().any(char::is_control) {
            return Err(StoreError::InvalidName);
        }
        validate(&self.root, true)?;
        let path = self.root.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate(&path, false)?;
        Ok(path)
    }

    pub fn read_if_exists(
        &self,
        name: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.member(name)?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate(&path, false)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max_bytes {
            return Err(StoreError::TooLarge(path));
        }
        Ok(Some(bytes))
    }

    pub fn open_read(&self, name: &str) -> Result<fs::File, StoreError> {
        let path = self.member(name)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        validate(&path, false)?;
        Ok(file)
    }

    pub fn open_lock(&self, name: &str) -> Result<fs::File, StoreError> {
        let path = self.member(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        validate(&path, false)?;
        Ok(file)
    }

    pub fn append(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.member(name)?;
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        validate(&path, false)?;
        file.write_all(bytes)?;
        file.sync_data()?;
        Ok(())
    }

    pub fn replace_atomic(
        &self,
        name: &str,
        write: impl FnOnce(&mut fs::File) -> Result<(), StoreError>,
    ) -> Result<Utf8PathBuf, StoreError> {
        let path = self.member(name)?;
        let temp_name = format!(".{name}.{}.tmp", std::process::id());
        let temp = self.member(&temp_name)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        if let Err(error) = write(&mut file) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        file.sync_all()?;
        validate(&temp, false)?;
        fs::rename(&temp, &path)?;
        fs::File::open(&self.root)?.sync_all()?;
        validate(&path, false)?;
        Ok(path)
    }

    fn member(&self, name: &str) -> Result<Utf8PathBuf, StoreError> {
        if name.contains('/') || name.chars().any(char::is_control) {
            return Err(StoreError::InvalidName);
        }
        validate(&self.root, true)?;
        Ok(self.root.join(name))
    }
}

fn validate(path: &Utf8Path, directory: bool) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    let kind_ok = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !kind_ok
        || metadata.file_type().is_symlink()
        || (!directory && metadata.nlink() != 1)
        || metadata.uid() != current_uid()
    {
        return Err(StoreError::Insecure(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StoreError::Insecure(path.to_owned()));
    }
    Ok(())
}

fn validate_ancestor_chain(path: &Utf8Path) -> Result<(), StoreError> {
    for ancestor in path.ancestors().skip(1) {
        let Ok(metadata) = fs::symlink_metadata(ancestor) else {
            continue;
        };
        let mode = metadata.permissions().mode();
        let trusted_owner = metadata.uid() == current_uid() || metadata.uid() == 0;
        let writable_without_sticky = mode & 0o022 != 0 && mode & u32::from(libc::S_ISVTX) == 0;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !trusted_owner
            || writable_without_sticky
        {
            return Err(StoreError::Insecure(ancestor.to_owned()));
        }
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid private-store name")]
    InvalidName,
    #[error("insecure private-store path: {0}")]
    Insecure(Utf8PathBuf),
    #[error("private-store member exceeds read limit: {0}")]
    TooLarge(Utf8PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
