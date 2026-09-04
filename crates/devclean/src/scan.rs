use camino::{Utf8Path, Utf8PathBuf};
use devclean_core::{
    DiagnosticAggregator, DiagnosticKey, InodeSpill, Observation, PermitKind, ResourceFingerprint,
    ResourceIdentity, ScanBudgetTracker, ScanMetrics, ScopeDecision, ScopePolicy,
    StreamingPipeline, WorkPool,
};
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub type BeforeMetadataHook = Arc<dyn Fn(&Utf8Path) + Send + Sync>;

#[derive(Clone)]
pub struct TraversalOptions {
    pub max_queue: usize,
    pub max_observations: u64,
    pub cross_mounts: bool,
    pub exclusions: Vec<Utf8PathBuf>,
    pub scope: Option<ScopePolicy>,
    pub cancellation: Arc<AtomicBool>,
    pub pool: Arc<WorkPool>,
    pub before_metadata: Option<BeforeMetadataHook>,
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
        for entry in entries {
            metrics.cancellation_checks += 1;
            if options.cancellation.load(Ordering::Relaxed) {
                coverage = TraversalCoverage::Cancelled;
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
            let Some(_permit) = options.pool.acquire(PermitKind::Filesystem, || {
                options.cancellation.load(Ordering::Relaxed)
            }) else {
                coverage = TraversalCoverage::Cancelled;
                break;
            };
            if let Some(hook) = &options.before_metadata {
                hook(&path);
            }
            metrics.entries_seen += 1;
            metrics.metadata_reads += 1;
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    record(diagnostics, &scan_root, &path, "metadata_unavailable");
                    coverage = TraversalCoverage::Partial;
                    continue;
                }
            };
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
            let kind = if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "special"
            };
            let mut attributes = std::collections::BTreeMap::new();
            attributes.insert("device".into(), metadata.dev().to_string());
            attributes.insert("inode".into(), metadata.ino().to_string());
            attributes.insert("links".into(), metadata.nlink().to_string());
            attributes.insert("probe_filesystem_identity".into(), "complete".into());
            emit(Observation {
                identity: ResourceIdentity::Filesystem { path: path.clone() },
                fingerprint: ResourceFingerprint::filesystem(
                    metadata.dev(),
                    metadata.ino(),
                    kind,
                    metadata.len(),
                    i128::from(metadata.mtime()) * 1_000_000_000
                        + i128::from(metadata.mtime_nsec()),
                ),
                logical_bytes: Some(metadata.len()),
                allocated_bytes: Some(metadata.blocks().saturating_mul(512)),
                attributes,
            });
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
    }
    if diagnostics.dropped_groups > dropped_diagnostics_before
        && coverage == TraversalCoverage::Complete
    {
        coverage = TraversalCoverage::Partial;
    }
    TraversalOutcome { coverage, metrics }
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
