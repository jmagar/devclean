use std::fs;
use std::os::unix::fs::MetadataExt;

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathIdentity {
    pub path: Utf8PathBuf,
    pub device: u64,
    pub inode: u64,
    pub is_dir: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedRootIdentity {
    pub path: Utf8PathBuf,
    pub device: u64,
    pub inode: u64,
    pub ancestors: Vec<PathIdentity>,
}

impl ApprovedRootIdentity {
    pub fn inspect(path: &Utf8Path) -> Result<Self, ScopeError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ScopeError::InvalidRoot(path.to_owned()));
        }
        let canonical = fs::canonicalize(path)?;
        let path = Utf8PathBuf::from_path_buf(canonical).map_err(|_| ScopeError::NonUtf8)?;
        let mut ancestors = Vec::new();
        for ancestor in path.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            ancestors.push(PathIdentity {
                path: ancestor.to_owned(),
                device: m.dev(),
                inode: m.ino(),
                is_dir: m.is_dir() && !m.file_type().is_symlink(),
            });
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            ancestors,
        })
    }

    pub fn unchanged(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.dev() == self.device
                && m.ino() == self.inode
        }) && self.ancestors.iter().all(|expected| {
            fs::symlink_metadata(&expected.path).is_ok_and(|m| {
                m.dev() == expected.device
                    && m.ino() == expected.inode
                    && m.is_dir() == expected.is_dir
                    && !m.file_type().is_symlink()
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeDecision {
    Include,
    Exclude,
    Boundary,
}

#[derive(Clone, Debug)]
pub struct ScopePolicy {
    roots: Vec<ApprovedRootIdentity>,
    exclusions: Vec<Utf8PathBuf>,
    cross_mounts: bool,
}

impl ScopePolicy {
    pub fn new(
        mut roots: Vec<ApprovedRootIdentity>,
        exclusions: Vec<Utf8PathBuf>,
        cross_mounts: bool,
    ) -> Self {
        roots.sort_by_key(|r| r.path.as_str().len());
        let mut selected: Vec<ApprovedRootIdentity> = Vec::new();
        for root in roots {
            if !selected
                .iter()
                .any(|parent| root.path.starts_with(&parent.path))
            {
                selected.push(root);
            }
        }
        Self {
            roots: selected,
            exclusions,
            cross_mounts,
        }
    }

    pub fn authorize(&self, path: &Utf8Path, device: u64) -> ScopeDecision {
        if path
            .components()
            .any(|part| matches!(part, Utf8Component::ParentDir | Utf8Component::CurDir))
        {
            return ScopeDecision::Exclude;
        }
        if self
            .exclusions
            .iter()
            .any(|excluded| path.starts_with(excluded))
        {
            return ScopeDecision::Exclude;
        }
        let Some(root) = self.roots.iter().find(|root| path.starts_with(&root.path)) else {
            return ScopeDecision::Exclude;
        };
        if path
            .ancestors()
            .take_while(|ancestor| *ancestor != root.path)
            .any(|ancestor| {
                fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink())
            })
        {
            return ScopeDecision::Boundary;
        }
        if !root.unchanged() || (!self.cross_mounts && device != root.device) {
            ScopeDecision::Boundary
        } else {
            ScopeDecision::Include
        }
    }

    pub fn roots(&self) -> &[ApprovedRootIdentity] {
        &self.roots
    }
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid approved root: {0}")]
    InvalidRoot(Utf8PathBuf),
    #[error("path is not valid UTF-8")]
    NonUtf8,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
