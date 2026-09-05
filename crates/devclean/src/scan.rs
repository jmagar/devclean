use crate::detectors::CatalogDetector;
use camino::{Utf8Path, Utf8PathBuf};
use devclean_core::{
    DiagnosticAggregator, DiagnosticKey, InodeSpill, Observation, PermitKind, ResourceFingerprint,
    ResourceIdentity, ScanBudgetTracker, ScanMetrics, ScopeDecision, ScopePolicy,
    StreamingPipeline, WorkPool,
};
use rayon::prelude::*;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

pub type BeforeMetadataHook = Arc<dyn Fn(&Utf8Path) + Send + Sync>;
pub type ProgressHook = Arc<dyn Fn(u64, u64) + Send + Sync>;
pub type RootProgressHook = Arc<dyn Fn(usize, u64, u64) + Send + Sync>;

#[derive(Clone)]
pub struct TraversalOptions {
    pub max_queue: usize,
    pub max_observations: u64,
    /// Optional scan-wide budget shared by concurrent root traversals.
    pub shared_observations_remaining: Option<Arc<AtomicU64>>,
    pub cross_mounts: bool,
    pub exclusions: Vec<Utf8PathBuf>,
    pub scope: Option<ScopePolicy>,
    pub cancellation: Arc<AtomicBool>,
    pub pool: Arc<WorkPool>,
    pub before_metadata: Option<BeforeMetadataHook>,
    pub progress: Option<ProgressHook>,
    pub deadline: Option<Instant>,
    /// Emit an observation for each approved root before walking its children.
    /// This lets explicitly approved cache roots be reported as one useful,
    /// recursively-accounted candidate instead of only reporting recognized
    /// descendants.
    pub emit_roots: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraversalCoverage {
    Complete,
    Partial,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct TraversalOutcome {
    pub coverage: TraversalCoverage,
    pub metrics: ScanMetrics,
}

pub struct RootTraversalOutcome {
    pub index: usize,
    pub traversal: TraversalOutcome,
    pub diagnostics: DiagnosticAggregator,
    pub elapsed: std::time::Duration,
}

enum RootMessage {
    Observations(usize, Vec<Observation>),
    Finished(RootTraversalOutcome),
}

const OBSERVATION_BATCH_SIZE: usize = 512;
const OBSERVATION_BATCH_QUEUE: usize = 128;

pub fn stream_roots_parallel(
    roots: &[Utf8PathBuf],
    options: &TraversalOptions,
    max_workers: usize,
    progress: Option<RootProgressHook>,
    mut emit: impl FnMut(usize, Observation),
) -> Vec<RootTraversalOutcome> {
    if roots.is_empty() {
        return Vec::new();
    }
    let workers = max_workers.clamp(1, roots.len());
    let next = AtomicUsize::new(0);
    // Traversal produces millions of entries on a real developer workstation.
    // Sending every observation separately made channel synchronization a hot
    // path, so workers hand off cache-sized batches instead.
    let (sender, receiver) = mpsc::sync_channel::<RootMessage>(OBSERVATION_BATCH_QUEUE);
    let mut outcomes = Vec::with_capacity(roots.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let next = &next;
            let progress = progress.clone();
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(root) = roots.get(index) else {
                        break;
                    };
                    let started = Instant::now();
                    let mut diagnostics = DiagnosticAggregator::new(1000, 3);
                    let observations = sender.clone();
                    let mut batch = Vec::with_capacity(OBSERVATION_BATCH_SIZE);
                    let mut root_options = options.clone();
                    if let Some(progress) = progress.clone() {
                        root_options.progress = Some(Arc::new(move |entries, queue_high_water| {
                            progress(index, entries, queue_high_water);
                        }));
                    }
                    let traversal = stream_observations(
                        std::slice::from_ref(root),
                        &root_options,
                        &mut diagnostics,
                        |observation| {
                            batch.push(observation);
                            if batch.len() == OBSERVATION_BATCH_SIZE {
                                let full = std::mem::replace(
                                    &mut batch,
                                    Vec::with_capacity(OBSERVATION_BATCH_SIZE),
                                );
                                if observations
                                    .send(RootMessage::Observations(index, full))
                                    .is_err()
                                {
                                    root_options.cancellation.store(true, Ordering::Relaxed);
                                }
                            }
                        },
                    );
                    if !batch.is_empty()
                        && sender
                            .send(RootMessage::Observations(index, batch))
                            .is_err()
                    {
                        break;
                    }
                    if sender
                        .send(RootMessage::Finished(RootTraversalOutcome {
                            index,
                            traversal,
                            diagnostics,
                            elapsed: started.elapsed(),
                        }))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        drop(sender);
        while outcomes.len() < roots.len() {
            match receiver.recv() {
                Ok(RootMessage::Observations(index, observations)) => {
                    for observation in observations {
                        emit(index, observation);
                    }
                }
                Ok(RootMessage::Finished(outcome)) => outcomes.push(outcome),
                Err(_) => panic!("root traversal worker disconnected"),
            }
        }
    });
    outcomes.sort_by_key(|outcome| outcome.index);
    outcomes
}

pub fn stream_observations(
    roots: &[Utf8PathBuf],
    options: &TraversalOptions,
    diagnostics: &mut DiagnosticAggregator,
    mut emit: impl FnMut(Observation),
) -> TraversalOutcome {
    let mut metrics = ScanMetrics::default();
    let mut coverage = TraversalCoverage::Complete;
    let dropped_diagnostics_before = diagnostics.dropped_groups;
    let mut queue = VecDeque::new();
    let mut selected = Vec::<Utf8PathBuf>::new();
    for root in roots {
        if selected.iter().any(|parent| root.starts_with(parent)) {
            continue;
        }
        selected.retain(|child| !child.starts_with(root));
        selected.push(root.clone());
    }
    for root in selected {
        if options
            .exclusions
            .iter()
            .any(|excluded| root.starts_with(excluded))
        {
            continue;
        }
        if options.scope.as_ref().is_some_and(|scope| {
            scope
                .roots()
                .iter()
                .find(|identity| identity.path == root)
                .is_none_or(|identity| !identity.unchanged())
        }) {
            record(diagnostics, &root, &root, "root_identity_changed");
            coverage = TraversalCoverage::Partial;
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&root) else {
            record(diagnostics, &root, &root, "root_unreadable");
            coverage = TraversalCoverage::Partial;
            continue;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if options.emit_roots {
                if !claim_observation(options) {
                    record(diagnostics, &root, &root, "observation_limit");
                    coverage = TraversalCoverage::Partial;
                    continue;
                }
                metrics.entries_seen += 1;
                metrics.metadata_reads += 1;
                emit(filesystem_observation(root.clone(), &metadata));
            }
            queue.push_back((root.clone(), metadata.dev(), root));
        } else {
            record(diagnostics, &root, &root, "root_not_directory");
            coverage = TraversalCoverage::Partial;
        }
    }

    while let Some((directory, root_device, scan_root)) = queue.pop_front() {
        metrics.cancellation_checks += 1;
        if options.cancellation.load(Ordering::Relaxed) {
            coverage = TraversalCoverage::Cancelled;
            break;
        }
        if options
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            record(diagnostics, &scan_root, &directory, "elapsed_limit");
            coverage = TraversalCoverage::Partial;
            break;
        }
        let directory_before = fs::symlink_metadata(&directory).ok();
        if options.scope.as_ref().is_some_and(|scope| {
            !matches!(
                scope.authorize(&directory, root_device),
                ScopeDecision::Include
            )
        }) {
            record(
                diagnostics,
                &scan_root,
                &directory,
                "scope_boundary_changed",
            );
            coverage = TraversalCoverage::Partial;
            continue;
        }
        metrics.queue_high_water = metrics.queue_high_water.max(queue.len() as u64);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                record(diagnostics, &scan_root, &directory, "directory_unreadable");
                coverage = TraversalCoverage::Partial;
                continue;
            }
        };
        let mut entries = entries;
        loop {
            let mut paths = Vec::with_capacity(512);
            for entry in entries.by_ref().take(512) {
                metrics.cancellation_checks += 1;
                if options.cancellation.load(Ordering::Relaxed) {
                    coverage = TraversalCoverage::Cancelled;
                    break;
                }
                if options
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    record(diagnostics, &scan_root, &directory, "elapsed_limit");
                    coverage = TraversalCoverage::Partial;
                    break;
                }
                if metrics.entries_seen >= options.max_observations {
                    record(diagnostics, &scan_root, &directory, "observation_limit");
                    coverage = TraversalCoverage::Partial;
                    break;
                }
                let Ok(entry) = entry else {
                    record(diagnostics, &scan_root, &directory, "entry_disappeared");
                    coverage = TraversalCoverage::Partial;
                    continue;
                };
                let Ok(path) = Utf8PathBuf::from_path_buf(entry.path()) else {
                    record(diagnostics, &scan_root, &directory, "non_utf8_path");
                    coverage = TraversalCoverage::Partial;
                    continue;
                };
                if options
                    .exclusions
                    .iter()
                    .any(|excluded| path.starts_with(excluded))
                {
                    continue;
                }
                if !claim_observation(options) {
                    record(diagnostics, &scan_root, &directory, "observation_limit");
                    coverage = TraversalCoverage::Partial;
                    break;
                }
                metrics.entries_seen += 1;
                metrics.metadata_reads += 1;
                if should_emit_progress(metrics.entries_seen)
                    && let Some(progress) = &options.progress
                {
                    progress(metrics.entries_seen, metrics.queue_high_water);
                }
                paths.push(path);
            }
            if paths.is_empty() {
                break;
            }
            let results = metadata_batch(paths, options);
            for (path, metadata) in results {
                metrics.cancellation_checks += 1;
                if options.cancellation.load(Ordering::Relaxed) {
                    coverage = TraversalCoverage::Cancelled;
                    break;
                }
                let metadata = match metadata {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        record(diagnostics, &scan_root, &path, "metadata_unavailable");
                        coverage = TraversalCoverage::Partial;
                        continue;
                    }
                };
                // Re-authorize every observed entry after metadata collection.
                // Containing-directory identity checks cannot retract an
                // observation if an intermediate component is swapped first.
                if let Some(scope) = &options.scope {
                    match scope.authorize(&path, metadata.dev()) {
                        ScopeDecision::Include => {}
                        ScopeDecision::Exclude => continue,
                        ScopeDecision::Boundary => {
                            record(diagnostics, &scan_root, &path, "scope_boundary_changed");
                            coverage = TraversalCoverage::Partial;
                            continue;
                        }
                    }
                }
                emit(filesystem_observation(path.clone(), &metadata));
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    if crosses_mount(root_device, metadata.dev(), options.cross_mounts) {
                        record(diagnostics, &scan_root, &path, "mount_boundary");
                        coverage = TraversalCoverage::Partial;
                    } else if queue.len() == options.max_queue {
                        record(diagnostics, &scan_root, &path, "queue_limit");
                        coverage = TraversalCoverage::Partial;
                    } else {
                        queue.push_back((path, root_device, scan_root.clone()));
                    }
                }
            }
            if coverage == TraversalCoverage::Cancelled
                || options
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                || metrics.entries_seen >= options.max_observations
                || options
                    .shared_observations_remaining
                    .as_ref()
                    .is_some_and(|remaining| remaining.load(Ordering::Relaxed) == 0)
            {
                break;
            }
        }
        let directory_unchanged = directory_before.as_ref().is_some_and(|before| {
            fs::symlink_metadata(&directory)
                .is_ok_and(|after| before.dev() == after.dev() && before.ino() == after.ino())
        });
        if !directory_unchanged
            || options.scope.as_ref().is_some_and(|scope| {
                !matches!(
                    scope.authorize(&directory, root_device),
                    ScopeDecision::Include
                )
            })
        {
            record(
                diagnostics,
                &scan_root,
                &directory,
                "directory_identity_changed",
            );
            coverage = TraversalCoverage::Partial;
        }
    }
    if diagnostics.dropped_groups > dropped_diagnostics_before
        && coverage == TraversalCoverage::Complete
    {
        coverage = TraversalCoverage::Partial;
    }
    TraversalOutcome { coverage, metrics }
}

fn should_emit_progress(entries_seen: u64) -> bool {
    entries_seen > 0 && entries_seen % 100_000 == 0
}

fn claim_observation(options: &TraversalOptions) -> bool {
    options
        .shared_observations_remaining
        .as_ref()
        .is_none_or(|remaining| {
            remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
        })
}

fn metadata_batch(
    paths: Vec<Utf8PathBuf>,
    options: &TraversalOptions,
) -> Vec<(Utf8PathBuf, std::io::Result<fs::Metadata>)> {
    fn inspect(
        path: Utf8PathBuf,
        options: &TraversalOptions,
    ) -> (Utf8PathBuf, std::io::Result<fs::Metadata>) {
        let Some(_permit) = options.pool.acquire(PermitKind::Filesystem, || {
            options.cancellation.load(Ordering::Relaxed)
        }) else {
            return (
                path,
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "filesystem work cancelled",
                )),
            );
        };
        if let Some(hook) = &options.before_metadata {
            hook(&path);
        }
        let metadata = fs::symlink_metadata(&path);
        (path, metadata)
    }

    if paths.len() < 32 || options.before_metadata.is_some() {
        return paths
            .into_iter()
            .map(|path| inspect(path, options))
            .collect();
    }
    static METADATA_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    let pool = METADATA_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .thread_name(|index| format!("devclean-metadata-{index}"))
            .build()
            .expect("fixed metadata pool configuration")
    });
    pool.install(|| {
        paths
            .into_par_iter()
            .map(|path| inspect(path, options))
            .collect()
    })
}

fn filesystem_observation(path: Utf8PathBuf, metadata: &fs::Metadata) -> Observation {
    let kind = if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "special"
    };
    let candidate = CatalogDetector::is_filesystem_candidate(&path);
    let attributes = if candidate {
        std::collections::BTreeMap::from([
            ("device".into(), metadata.dev().to_string()),
            ("inode".into(), metadata.ino().to_string()),
            ("links".into(), metadata.nlink().to_string()),
            ("probe_filesystem_identity".into(), "complete".into()),
        ])
    } else {
        std::collections::BTreeMap::new()
    };
    Observation {
        identity: ResourceIdentity::Filesystem { path },
        fingerprint: if candidate {
            ResourceFingerprint::filesystem(
                metadata.dev(),
                metadata.ino(),
                kind,
                metadata.len(),
                i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
            )
        } else {
            ResourceFingerprint::filesystem_extent(metadata.dev(), metadata.ino())
        },
        logical_bytes: Some(metadata.len()),
        allocated_bytes: Some(metadata.blocks().saturating_mul(512)),
        attributes,
    }
}

pub fn crosses_mount(root_device: u64, entry_device: u64, cross_mounts: bool) -> bool {
    !cross_mounts && root_device != entry_device
}

pub fn stream_into_pipeline<S: InodeSpill>(
    roots: &[Utf8PathBuf],
    options: &TraversalOptions,
    diagnostics: &mut DiagnosticAggregator,
    pipeline: &mut StreamingPipeline<S>,
    budget: &mut ScanBudgetTracker,
) -> std::io::Result<TraversalOutcome> {
    let mut pipeline_error = None;
    let mut outcome = stream_observations(roots, options, diagnostics, |observation| {
        if pipeline_error.is_none() {
            if let Err(error) = pipeline.observe(observation, budget) {
                pipeline_error = Some(error);
            }
        }
    });
    if pipeline.sink.overflow.is_some()
        || pipeline.activity.overflow.is_some()
        || pipeline.ownership.overflow.is_some()
    {
        outcome.coverage = TraversalCoverage::Partial;
    }
    match pipeline_error {
        Some(error) => Err(error),
        None => Ok(outcome),
    }
}

fn record(diagnostics: &mut DiagnosticAggregator, root: &Utf8Path, path: &Utf8Path, reason: &str) {
    diagnostics.record(
        DiagnosticKey {
            root: root.to_string(),
            detector: "filesystem".into(),
            reason: reason.into(),
        },
        path.to_string(),
    );
}

#[cfg(test)]
mod progress_tests {
    use super::should_emit_progress;

    #[test]
    fn progress_interval_is_bounded_and_predictable() {
        assert!(!should_emit_progress(0));
        assert!(!should_emit_progress(99_999));
        assert!(should_emit_progress(100_000));
        assert!(should_emit_progress(200_000));
    }
}
