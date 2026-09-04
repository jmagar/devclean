use crate::private_store::{PrivateStore, StoreError};
use devclean_core::InodeSpill;
use std::io;

pub struct FileInodeSpill {
    store: PrivateStore,
    max_partition_bytes: u64,
}

impl FileInodeSpill {
    pub fn new(store: PrivateStore, max_partition_bytes: u64) -> Self {
        Self {
            store,
            max_partition_bytes,
        }
    }

    fn name(partition: u16) -> String {
        format!("inode-{partition:04x}.idx")
    }

    fn map_error(error: StoreError) -> io::Error {
        io::Error::other(error)
    }
}

impl InodeSpill for FileInodeSpill {
    fn contains(&mut self, partition: u16, key: &str) -> io::Result<bool> {
        let Some(bytes) = self
            .store
            .read_if_exists(&Self::name(partition), self.max_partition_bytes)
            .map_err(Self::map_error)?
        else {
            return Ok(false);
        };
        Ok(bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line == key.as_bytes()))
    }

    fn spill(&mut self, partition: u16, entries: &[(String, u64)]) -> io::Result<()> {
        let mut bytes = Vec::new();
        for (key, _) in entries {
            if key.as_bytes().contains(&b'\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "newline in inode key",
                ));
            }
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(b'\n');
        }
        let existing = self
            .store
            .read_if_exists(&Self::name(partition), self.max_partition_bytes)
            .map_err(Self::map_error)?
            .map_or(0, |value| value.len());
        if existing.saturating_add(bytes.len()) as u64 > self.max_partition_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "inode spill partition limit",
            ));
        }
        self.store
            .append(&Self::name(partition), &bytes)
            .map_err(Self::map_error)
    }
}
