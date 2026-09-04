use crate::command::{CommandError, CommandRunner, CommandSpec, CommandStatus};
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use devclean_core::{
    ActivityIndex, ApprovedRootIdentity, CoverageStatus, PermitKind, ProtectionSignal, WorkPool,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct InventoryLimits {
    pub max_objects: usize,
    pub max_response_bytes: u64,
    pub max_pages: usize,
    pub total_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GitCommonKey {
    pub common_dir: Utf8PathBuf,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitWorktreeState {
    pub id: String,
    pub path: Option<Utf8PathBuf>,
    pub registered: bool,
    pub detached: bool,
    pub dirty: bool,
    pub untracked: bool,
    pub active: bool,
    pub ahead: u64,
    pub reachable_from_retained_ref: bool,
    pub has_remote_evidence: bool,
    pub stale: bool,
    pub accessible: bool,
    pub coverage: CoverageStatus,
    pub snapshot_fingerprint: String,
}

impl GitWorktreeState {
    pub fn protections(&self) -> Vec<ProtectionSignal> {
        let mut values = Vec::new();
        if self.dirty {
            values.push(ProtectionSignal::Dirty);
        }
        if self.untracked {
            values.push(ProtectionSignal::Untracked);
        }
        if self.active {
            values.push(ProtectionSignal::Active);
        }
        if self.ahead > 0 || !self.has_remote_evidence {
            values.push(ProtectionSignal::Unpublished);
        }
        if !self.reachable_from_retained_ref {
            values.push(ProtectionSignal::UnreachableCommit);
        }
        if !self.accessible || self.path.is_none() {
            values.push(ProtectionSignal::Inaccessible);
        }
        if !self.registered {
            values.push(ProtectionSignal::UnknownOwnership);
        }
        values.sort();
        values.dedup();
        values
    }
}

#[derive(Clone, Debug)]
pub struct GitInventory {
    pub coverage: CoverageStatus,
    pub worktrees: Vec<GitWorktreeState>,
    pub graph_walks: u64,
    pub snapshot_fingerprint: Option<String>,
}

pub trait GitBackend {
    fn inventory(&mut self, key: &GitCommonKey, limits: InventoryLimits) -> GitInventory;
}

pub struct GitCommandBackend<'a> {
    pub runner: &'a dyn MachineCommandRunner,
    pub activity: &'a ActivityIndex,
    pub approved_roots: &'a [ApprovedRootIdentity],
    pub cancellation: &'a AtomicBool,
    pub timeout: Duration,
    pub output_limit: usize,
}

impl GitCommandBackend<'_> {
    pub fn read_only_specs(&self, key: &GitCommonKey) -> [CommandSpec; 2] {
        let git_dir = format!("--git-dir={}", key.common_dir);
        [
            CommandSpec {
                executable: "/usr/bin/git".into(),
                args: vec![
                    git_dir.clone(),
                    "worktree".into(),
                    "list".into(),
                    "--porcelain".into(),
                    "-z".into(),
                ],
                cwd: key.common_dir.clone(),
                timeout: self.timeout,
                output_limit: self.output_limit,
            },
            CommandSpec {
                executable: "/usr/bin/git".into(),
                args: vec![git_dir, "rev-list".into(), "--remotes".into()],
                cwd: key.common_dir.clone(),
                timeout: self.timeout,
                output_limit: self.output_limit,
            },
        ]
    }
}

impl GitBackend for GitCommandBackend<'_> {
    fn inventory(&mut self, key: &GitCommonKey, limits: InventoryLimits) -> GitInventory {
        if !approved_path(&key.common_dir, self.approved_roots)
            || !fs::symlink_metadata(&key.common_dir).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.dev() == key.device
                    && metadata.ino() == key.inode
            })
        {
            return GitInventory {
                coverage: CoverageStatus::Partial,
                worktrees: vec![],
                graph_walks: 0,
                snapshot_fingerprint: None,
            };
        }
        let started = Instant::now();
        let [mut worktree_spec, mut graph_spec] = self.read_only_specs(key);
        worktree_spec.timeout = self.timeout.min(limits.total_timeout);
        let worktree_bytes = match run_machine_command(self.runner, &worktree_spec) {
            Ok(bytes) => bytes,
            Err(_) => {
                return GitInventory {
                    coverage: CoverageStatus::Failed,
                    worktrees: vec![],
                    graph_walks: 0,
                    snapshot_fingerprint: None,
                };
            }
        };
        graph_spec.timeout = self
            .timeout
            .min(limits.total_timeout.saturating_sub(started.elapsed()));
        let graph_bytes = match run_machine_command(self.runner, &graph_spec) {
            Ok(bytes) => bytes,
            Err(_) => {
                return GitInventory {
                    coverage: CoverageStatus::Failed,
                    worktrees: vec![],
                    graph_walks: 1,
                    snapshot_fingerprint: None,
                };
            }
        };
        if worktree_bytes.len().saturating_add(graph_bytes.len()) as u64 > limits.max_response_bytes
        {
            return GitInventory {
                coverage: CoverageStatus::Truncated,
                worktrees: vec![],
                graph_walks: 1,
                snapshot_fingerprint: None,
            };
        }
        let reachable: BTreeSet<&str> = std::str::from_utf8(&graph_bytes)
            .unwrap_or("")
            .lines()
            .collect();
        let mut worktrees = parse_worktree_porcelain(&worktree_bytes);
        let mut coverage = CoverageStatus::Complete;
        worktrees.retain(|worktree| {
            let allowed = worktree
                .path
                .as_ref()
                .is_some_and(|path| approved_path(path, self.approved_roots));
            if !allowed {
                coverage.join_assign(&CoverageStatus::Partial);
            }
            allowed
        });
        if worktrees.len() > limits.max_objects {
            worktrees.truncate(limits.max_objects);
            coverage.join_assign(&CoverageStatus::Truncated);
        }
        for worktree in &mut worktrees {
            if self.cancellation.load(Ordering::Relaxed) {
                coverage.join_assign(&CoverageStatus::Partial);
                worktree.coverage.join_assign(&CoverageStatus::Partial);
                break;
            }
            let Some(path) = &worktree.path else {
                coverage.join_assign(&CoverageStatus::Partial);
                continue;
            };
            worktree.accessible = fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
            worktree.active = self.activity.matches_prefix(path);
            if !worktree.accessible {
                continue;
            }
            let remaining = limits.total_timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                coverage.join_assign(&CoverageStatus::TimedOut);
                worktree.coverage.join_assign(&CoverageStatus::TimedOut);
                break;
            }
            let spec = CommandSpec {
                executable: "/usr/bin/git".into(),
                args: vec![
                    "-C".into(),
                    path.to_string(),
                    "status".into(),
                    "--porcelain=v2".into(),
                    "--branch".into(),
                    "-z".into(),
                ],
                cwd: path.clone(),
                timeout: self.timeout.min(remaining),
                output_limit: self.output_limit,
            };
            match run_machine_command(self.runner, &spec) {
                Ok(status) => {
                    apply_status(worktree, &status);
                    if self.cancellation.load(Ordering::Relaxed) {
                        worktree.coverage.join_assign(&CoverageStatus::Partial);
                        coverage.join_assign(&CoverageStatus::Partial);
                        break;
                    }
                    let remaining = limits.total_timeout.saturating_sub(started.elapsed());
                    let mut verify_spec = spec.clone();
                    verify_spec.timeout = self.timeout.min(remaining);
                    match (!remaining.is_zero())
                        .then(|| run_machine_command(self.runner, &verify_spec))
                    {
                        Some(Ok(after)) if after == status => {}
                        _ => {
                            worktree.coverage.join_assign(&CoverageStatus::Partial);
                            coverage.join_assign(&CoverageStatus::Partial);
                        }
                    }
                }
                Err(_) => {
                    worktree.accessible = false;
                    coverage.join_assign(&CoverageStatus::Partial);
                }
            }
            worktree.reachable_from_retained_ref = reachable.contains(worktree.id.as_str());
        }
        worktree_spec.timeout = self
            .timeout
            .min(limits.total_timeout.saturating_sub(started.elapsed()));
        let worktree_after = if worktree_spec.timeout.is_zero() {
            None
        } else {
            run_machine_command(self.runner, &worktree_spec).ok()
        };
        if worktree_after.as_deref() != Some(worktree_bytes.as_slice()) {
            coverage.join_assign(&CoverageStatus::Partial);
        }
        let mut snapshot = worktree_bytes;
        snapshot.extend_from_slice(&graph_bytes);
        let fingerprint = blake3::hash(&snapshot).to_hex().to_string();
        for worktree in &mut worktrees {
            worktree.snapshot_fingerprint.clone_from(&fingerprint);
            if coverage != CoverageStatus::Complete && worktree.coverage == CoverageStatus::Complete
            {
                worktree.coverage.join_assign(&coverage);
            }
        }
        GitInventory {
            coverage,
            worktrees,
            graph_walks: 1,
            snapshot_fingerprint: Some(fingerprint),
        }
    }
}

fn approved_path(path: &Utf8Path, approved_roots: &[ApprovedRootIdentity]) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Utf8Component::ParentDir | Utf8Component::CurDir))
    {
        return false;
    }
    approved_roots.iter().any(|root| {
        let Ok(relative) = path.strip_prefix(&root.path) else {
            return false;
        };
        if !root.unchanged() {
            return false;
        }
        let mut current = root.path.clone();
        for component in relative.components() {
            let Utf8Component::Normal(name) = component else {
                return false;
            };
            current.push(name);
            let Ok(metadata) = fs::symlink_metadata(&current) else {
                return false;
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return false;
            }
        }
        true
    })
}

fn parse_worktree_porcelain(bytes: &[u8]) -> Vec<GitWorktreeState> {
    let mut result = Vec::new();
    let mut current: Option<GitWorktreeState> = None;
    for field in bytes.split(|byte| *byte == 0 || *byte == b'\n') {
        let Ok(field) = std::str::from_utf8(field) else {
            continue;
        };
        if let Some(path) = field.strip_prefix("worktree ") {
            if let Some(value) = current.take() {
                result.push(value);
            }
            current = Some(GitWorktreeState {
                id: String::new(),
                path: Some(path.into()),
                registered: true,
                detached: false,
                dirty: false,
                untracked: false,
                active: false,
                ahead: 0,
                reachable_from_retained_ref: false,
                has_remote_evidence: false,
                stale: false,
                accessible: true,
                coverage: CoverageStatus::Complete,
                snapshot_fingerprint: String::new(),
            });
        } else if let Some(value) = &mut current {
            if let Some(head) = field.strip_prefix("HEAD ") {
                value.id = head.into();
            }
            if field == "detached" {
                value.detached = true;
            }
            if field == "prunable" || field.starts_with("prunable ") {
                value.stale = true;
            }
        }
    }
    if let Some(value) = current {
        result.push(value);
    }
    result
}

fn apply_status(worktree: &mut GitWorktreeState, bytes: &[u8]) {
    for field in bytes.split(|byte| *byte == 0 || *byte == b'\n') {
        if field.starts_with(b"? ") {
            worktree.untracked = true;
        }
        if field
            .first()
            .is_some_and(|kind| matches!(kind, b'1' | b'2' | b'u'))
        {
            worktree.dirty = true;
        }
        if field.starts_with(b"# branch.upstream ") {
            worktree.has_remote_evidence = true;
        }
        if let Some(ab) = field.strip_prefix(b"# branch.ab +") {
            worktree.ahead = std::str::from_utf8(ab)
                .ok()
                .and_then(|value| value.split_ascii_whitespace().next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        }
    }
}

#[derive(Default)]
pub struct GitInventoryCache {
    values: BTreeMap<GitCommonKey, GitInventory>,
}
impl GitInventoryCache {
    pub fn get_or_collect<B: GitBackend>(
        &mut self,
        key: GitCommonKey,
        backend: &mut B,
        limits: InventoryLimits,
        pool: &WorkPool,
        cancellation: &AtomicBool,
    ) -> GitInventory {
        if let Some(value) = self.values.get(&key) {
            return value.clone();
        }
        let Some(_permit) = pool.acquire(PermitKind::Subprocess, || {
            cancellation.load(Ordering::Relaxed)
        }) else {
            return GitInventory {
                coverage: CoverageStatus::Failed,
                worktrees: vec![],
                graph_walks: 0,
                snapshot_fingerprint: None,
            };
        };
        let started = Instant::now();
        let mut value = backend.inventory(&key, limits);
        if started.elapsed() > limits.total_timeout {
            value.coverage = CoverageStatus::TimedOut;
        }
        if value.worktrees.len() > limits.max_objects {
            value.worktrees.truncate(limits.max_objects);
            value.coverage = CoverageStatus::Truncated;
        }
        self.values.insert(key, value.clone());
        value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DockerDaemonKey {
    pub transport: String,
    pub context: String,
    pub engine_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerObjectKind {
    Container,
    Image,
    Layer,
    BuildCache,
    Network,
    Volume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DockerObject {
    pub id: String,
    pub kind: DockerObjectKind,
    pub size: u64,
    pub references: Vec<String>,
    pub compose_project: Option<String>,
    pub running: bool,
    pub dangling: bool,
    pub active_build: bool,
    pub recently_used: bool,
    pub shared_group: Option<String>,
    pub coverage: CoverageStatus,
    pub snapshot_fingerprint: String,
}

impl DockerObject {
    pub fn protections(&self) -> Vec<ProtectionSignal> {
        let mut values = Vec::new();
        if self.kind == DockerObjectKind::Volume {
            values.push(ProtectionSignal::DockerVolume);
        }
        if self.running || self.active_build {
            values.push(ProtectionSignal::Active);
        }
        if !self.references.is_empty() {
            values.push(ProtectionSignal::OpenFile);
        }
        values
    }
    pub fn ownership_proven(&self) -> bool {
        !self.references.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct DockerPage {
    pub objects: Vec<DockerObject>,
    pub next: Option<String>,
    pub response_bytes: u64,
}
pub trait DockerBackend {
    fn identity(&mut self, key: &DockerDaemonKey) -> Result<String, String>;
    fn epoch(&mut self, key: &DockerDaemonKey) -> Result<String, String>;
    fn page(&mut self, key: &DockerDaemonKey, cursor: Option<&str>) -> Result<DockerPage, String>;
}

#[derive(Clone, Debug)]
pub struct DockerInventory {
    pub coverage: CoverageStatus,
    pub objects: Vec<DockerObject>,
    pub epoch: Option<String>,
    pub calls: u64,
}

#[derive(Default)]
pub struct DockerInventoryCache {
    values: BTreeMap<DockerDaemonKey, DockerInventory>,
}
impl DockerInventoryCache {
    pub fn get_or_collect<B: DockerBackend>(
        &mut self,
        key: DockerDaemonKey,
        backend: &mut B,
        approved: &DockerDaemonKey,
        limits: InventoryLimits,
        pool: &WorkPool,
        cancellation: &AtomicBool,
    ) -> DockerInventory {
        if let Some(value) = self.values.get(&key) {
            return value.clone();
        }
        if &key != approved {
            return DockerInventory {
                coverage: CoverageStatus::Failed,
                objects: vec![],
                epoch: None,
                calls: 0,
            };
        }
        let Some(_permit) =
            pool.acquire(PermitKind::Docker, || cancellation.load(Ordering::Relaxed))
        else {
            return DockerInventory {
                coverage: CoverageStatus::Failed,
                objects: vec![],
                epoch: None,
                calls: 0,
            };
        };
        let identity = match backend.identity(&key) {
            Ok(value) if value == approved.engine_id => value,
            _ => {
                return memo_docker(
                    &mut self.values,
                    key,
                    DockerInventory {
                        coverage: CoverageStatus::Failed,
                        objects: vec![],
                        epoch: None,
                        calls: 1,
                    },
                );
            }
        };
        let start = match backend.epoch(&key) {
            Ok(value) => value,
            Err(_) => {
                return memo_docker(
                    &mut self.values,
                    key,
                    DockerInventory {
                        coverage: CoverageStatus::Failed,
                        objects: vec![],
                        epoch: None,
                        calls: 2,
                    },
                );
            }
        };
        let mut calls = 2;
        let mut cursor = None;
        let mut objects = Vec::new();
        let mut bytes = 0u64;
        let mut coverage = CoverageStatus::Complete;
        let started = Instant::now();
        let mut pages = 0usize;
        let mut cursors = BTreeSet::new();
        loop {
            if cancellation.load(Ordering::Relaxed) || started.elapsed() > limits.total_timeout {
                coverage.join_assign(&CoverageStatus::Partial);
                break;
            }
            if pages == limits.max_pages || !cursors.insert(cursor.clone()) {
                coverage.join_assign(&CoverageStatus::Truncated);
                break;
            }
            let page = match backend.page(&key, cursor.as_deref()) {
                Ok(value) => value,
                Err(_) => {
                    coverage.join_assign(&CoverageStatus::Failed);
                    break;
                }
            };
            pages += 1;
            calls += 1;
            bytes = bytes.saturating_add(page.response_bytes);
            if bytes > limits.max_response_bytes
                || objects.len().saturating_add(page.objects.len()) > limits.max_objects
            {
                let remaining = limits.max_objects.saturating_sub(objects.len());
                objects.extend(page.objects.into_iter().take(remaining));
                coverage.join_assign(&CoverageStatus::Truncated);
                break;
            }
            objects.extend(page.objects);
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        let end = backend.epoch(&key).ok();
        calls += 1;
        let snapshot_fingerprint = blake3::hash(
            format!(
                "{}\0{}\0{}\0{}",
                key.transport, key.context, identity, start
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();
        for object in &mut objects {
            object
                .snapshot_fingerprint
                .clone_from(&snapshot_fingerprint);
        }
        if end.as_deref() != Some(start.as_str()) {
            coverage.join_assign(&CoverageStatus::Partial);
        }
        if coverage != CoverageStatus::Complete {
            for object in &mut objects {
                object.coverage.join_assign(&coverage);
            }
        }
        let value = DockerInventory {
            coverage,
            objects,
            epoch: Some(start),
            calls,
        };
        memo_docker(&mut self.values, key, value)
    }
}

fn memo_docker(
    values: &mut BTreeMap<DockerDaemonKey, DockerInventory>,
    key: DockerDaemonKey,
    value: DockerInventory,
) -> DockerInventory {
    values.insert(key, value.clone());
    value
}

pub trait MachineCommandRunner {
    fn run_machine(
        &self,
        spec: &CommandSpec,
    ) -> Result<crate::command::CommandOutcome, CommandError>;
}

impl MachineCommandRunner for CommandRunner {
    fn run_machine(
        &self,
        spec: &CommandSpec,
    ) -> Result<crate::command::CommandOutcome, CommandError> {
        self.run(spec)
    }
}

pub fn run_machine_command(
    runner: &dyn MachineCommandRunner,
    spec: &CommandSpec,
) -> Result<Vec<u8>, CommandError> {
    let result = runner.run_machine(spec)?;
    match result.status {
        CommandStatus::Success => Ok(result.stdout),
        CommandStatus::TimedOut => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "inventory command timed out",
        )
        .into()),
        CommandStatus::OutputTruncated => Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "inventory output truncated",
        )
        .into()),
        CommandStatus::Exit(_) => Err(std::io::Error::other("inventory command failed").into()),
    }
}
