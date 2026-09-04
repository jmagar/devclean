use crate::command::{CommandError, CommandRunner, CommandSpec, CommandStatus};
use camino::Utf8PathBuf;
use devclean_core::{ActivityIndex, PermitKind, WorkPool};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityStatus {
    Complete,
    TimedOut,
    Truncated,
    PermissionDenied,
    Malformed,
}

#[derive(Clone, Debug)]
pub struct ActivitySnapshot {
    pub status: ActivityStatus,
    pub index: ActivityIndex,
    pub records_seen: u64,
}

pub struct ActivityCollector {
    snapshot: Option<ActivitySnapshot>,
    max_records: usize,
    pool: Arc<WorkPool>,
    cancellation: Arc<AtomicBool>,
}

impl ActivityCollector {
    pub fn new(max_records: usize, pool: Arc<WorkPool>, cancellation: Arc<AtomicBool>) -> Self {
        Self {
            snapshot: None,
            max_records,
            pool,
            cancellation,
        }
    }
    pub fn snapshot_once(
        &mut self,
        runner: &CommandRunner,
        spec: &CommandSpec,
        approved_roots: &[Utf8PathBuf],
    ) -> Result<ActivitySnapshot, CommandError> {
        if let Some(snapshot) = &self.snapshot {
            return Ok(snapshot.clone());
        }
        let snapshot = snapshot_lsof_bounded(
            runner,
            spec,
            approved_roots,
            self.max_records,
            &self.pool,
            &self.cancellation,
        )?;
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }
}

impl Default for ActivityCollector {
    fn default() -> Self {
        Self::new(
            100_000,
            Arc::new(WorkPool::new(
                1,
                std::collections::BTreeMap::from([(PermitKind::Subprocess, 1)]),
            )),
            Arc::new(AtomicBool::new(false)),
        )
    }
}

pub fn snapshot_lsof(
    runner: &CommandRunner,
    spec: &CommandSpec,
    approved_roots: &[Utf8PathBuf],
    pool: &WorkPool,
    cancellation: &AtomicBool,
) -> Result<ActivitySnapshot, CommandError> {
    snapshot_lsof_bounded(runner, spec, approved_roots, 100_000, pool, cancellation)
}

pub fn snapshot_lsof_bounded(
    runner: &CommandRunner,
    spec: &CommandSpec,
    approved_roots: &[Utf8PathBuf],
    max_records: usize,
    pool: &WorkPool,
    cancellation: &AtomicBool,
) -> Result<ActivitySnapshot, CommandError> {
    let _permit = pool
        .acquire(PermitKind::Subprocess, || {
            cancellation.load(Ordering::Relaxed)
        })
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "activity cancelled")
        })?;
    let outcome = runner.run(spec)?;
    let status = match outcome.status {
        CommandStatus::TimedOut => ActivityStatus::TimedOut,
        CommandStatus::OutputTruncated => ActivityStatus::Truncated,
        CommandStatus::Exit(1) if outcome.stderr_was_present => ActivityStatus::PermissionDenied,
        CommandStatus::Exit(1) => ActivityStatus::Complete,
        CommandStatus::Exit(_) => ActivityStatus::Malformed,
        CommandStatus::Success => ActivityStatus::Complete,
    };
    let mut index = ActivityIndex::new(max_records);
    let mut records_seen = 0;
    let mut malformed = false;
    for field in outcome.stdout.split(|byte| *byte == 0 || *byte == b'\n') {
        if let Some(raw_path) = field.strip_prefix(b"n") {
            records_seen += 1;
            if let Ok(path) = std::str::from_utf8(raw_path) {
                let path = Utf8PathBuf::from(path);
                if approved_roots.iter().any(|root| path.starts_with(root)) {
                    index.insert(path);
                }
            } else {
                malformed = true;
            }
        }
    }
    let status = if status == ActivityStatus::Complete && index.overflow.is_some() {
        ActivityStatus::Truncated
    } else if status == ActivityStatus::Complete && malformed {
        ActivityStatus::Malformed
    } else {
        status
    };
    Ok(ActivitySnapshot {
        status,
        index,
        records_seen,
    })
}
