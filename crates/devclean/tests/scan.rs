use devclean::scan::{
    TraversalCoverage, TraversalOptions, crosses_mount, stream_into_pipeline, stream_observations,
    stream_roots_parallel,
};
use devclean_core::{
    ActivityIndex, ApprovedRootIdentity, BudgetKind, CandidateSink, DiagnosticAggregator,
    InodeSpill, ObservationRouter, PermitKind, ProjectOwnershipIndex, ResourceIdentity,
    RouteInterest, ScanBudget, ScanMetrics, ScopePolicy, StreamingPipeline, WorkPool,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn options() -> TraversalOptions {
    TraversalOptions {
        max_queue: 100,
        max_observations: 1000,
        shared_observations_remaining: None,
        cross_mounts: false,
        exclusions: vec![],
        scope: None,
        cancellation: Arc::new(AtomicBool::new(false)),
        pool: Arc::new(WorkPool::new(
            4,
            BTreeMap::from([
                (PermitKind::Filesystem, 2),
                (PermitKind::Detector, 1),
                (PermitKind::Subprocess, 1),
                (PermitKind::Docker, 1),
            ]),
        )),
        before_metadata: None,
        progress: None,
        deadline: None,
        emit_roots: false,
    }
}

fn scoped_options(identity: ApprovedRootIdentity) -> TraversalOptions {
    let mut settings = options();
    settings.scope = Some(ScopePolicy::new(vec![identity], vec![], false));
    settings
}

#[test]
fn performance_contract_single_walk_deduplicates_roots_and_reads_metadata_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    fs::create_dir(root.join("project")).unwrap();
    fs::write(root.join("project/file"), b"data").unwrap();
    std::os::unix::fs::symlink(root, root.join("project/loop")).unwrap();
    let mut seen = vec![];
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(
        &[root.to_owned(), root.join("project")],
        &options(),
        &mut diagnostics,
        |value| seen.push(value),
    );
    assert_eq!(outcome.coverage, TraversalCoverage::Complete);
    assert_eq!(outcome.metrics.entries_seen, 3);
    assert_eq!(outcome.metrics.metadata_reads, outcome.metrics.entries_seen);
    assert_eq!(seen.len(), 3);
}

#[test]
fn traversal_stops_at_scan_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    fs::create_dir(root.join("project")).unwrap();
    fs::write(root.join("project/file"), b"data").unwrap();
    let mut settings = options();
    settings.deadline = Some(std::time::Instant::now());
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &settings, &mut diagnostics, |_| {});
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(
        diagnostics
            .groups()
            .keys()
            .any(|key| key.reason == "elapsed_limit")
    );
}

#[test]
fn performance_contract_parallel_roots_preserve_complete_independent_results() {
    let tmp = tempfile::tempdir().unwrap();
    let base = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let roots = [base.join("one"), base.join("two")];
    for root in &roots {
        fs::create_dir(root).unwrap();
        for index in 0..100 {
            fs::write(root.join(format!("entry-{index}")), b"x").unwrap();
        }
    }
    let mut seen = [0_u64; 2];
    let outcomes = stream_roots_parallel(&roots, &options(), 2, None, |index, _| seen[index] += 1);
    assert_eq!(seen, [100, 100]);
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.traversal.coverage == TraversalCoverage::Complete)
    );
}

#[test]
fn performance_contract_parallel_roots_share_one_observation_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let base = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let roots = [base.join("one"), base.join("two")];
    for root in &roots {
        fs::create_dir(root).unwrap();
        for index in 0..100 {
            fs::write(root.join(format!("entry-{index}")), b"x").unwrap();
        }
    }
    let mut settings = options();
    settings.shared_observations_remaining = Some(Arc::new(std::sync::atomic::AtomicU64::new(150)));
    let outcomes = stream_roots_parallel(&roots, &settings, 2, None, |_, _| {});
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.traversal.metrics.entries_seen)
            .sum::<u64>(),
        150
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| outcome.traversal.coverage == TraversalCoverage::Partial)
    );
}

#[test]
fn traversal_can_emit_an_approved_root_for_recursive_cache_accounting() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    fs::write(root.join("entry"), b"data").unwrap();
    let mut settings = options();
    settings.emit_roots = true;
    let mut seen = Vec::new();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);

    let outcome = stream_observations(
        &[root.to_owned()],
        &settings,
        &mut diagnostics,
        |observation| seen.push(observation.identity),
    );

    assert_eq!(outcome.coverage, TraversalCoverage::Complete);
    assert_eq!(outcome.metrics.entries_seen, 2);
    assert!(matches!(
        &seen[0],
        ResourceIdentity::Filesystem { path } if path == root
    ));
}

#[test]
fn traversal_reports_limits_cancellation_hardlinks_and_sparse_allocation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("original"), b"same").unwrap();
    fs::hard_link(root.join("original"), root.join("linked")).unwrap();
    let sparse = fs::File::create(root.join("sparse")).unwrap();
    sparse.set_len(1_000_000).unwrap();
    let mut observations = vec![];
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let mut limited = options();
    limited.max_queue = 1;
    let outcome = stream_observations(&[root.to_owned()], &limited, &mut diagnostics, |value| {
        observations.push(value)
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(outcome.metrics.queue_high_water <= 1);
    let inode = fs::metadata(root.join("original")).unwrap().ino();
    assert_eq!(
        observations
            .iter()
            .filter(|value| value
                .fingerprint
                .extent_identity()
                .is_some_and(|(_, value)| value == inode))
            .count(),
        2
    );
    let sparse_observation = observations.iter().find(|value| matches!(&value.identity, ResourceIdentity::Filesystem { path } if path.ends_with("sparse"))).unwrap();
    assert!(sparse_observation.allocated_bytes < sparse_observation.logical_bytes);

    let cancelled = options();
    cancelled.cancellation.store(true, Ordering::Relaxed);
    let outcome = stream_observations(&[root.to_owned()], &cancelled, &mut diagnostics, |_| {});
    assert_eq!(outcome.coverage, TraversalCoverage::Cancelled);
    assert!(outcome.metrics.cancellation_checks > 0);
}

#[test]
fn observation_limit_is_visible_partial_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    for n in 0..10 {
        fs::write(root.join(format!("{n}")), b"x").unwrap();
    }
    let mut limited = options();
    limited.max_observations = 3;
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &limited, &mut diagnostics, |_| {});
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert_eq!(outcome.metrics.entries_seen, 3);
}

#[test]
fn excluded_subtree_is_skipped_before_metadata_and_does_not_degrade_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let excluded = root.join("excluded");
    fs::create_dir(&excluded).unwrap();
    fs::write(excluded.join("secret.log"), b"ignored").unwrap();
    fs::write(root.join("included.log"), b"seen").unwrap();
    let metadata_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut settings = options();
    settings.exclusions = vec![excluded.clone()];
    let calls = Arc::clone(&metadata_calls);
    settings.before_metadata = Some(Arc::new(move |_| {
        calls.fetch_add(1, Ordering::Relaxed);
    }));
    let mut seen = Vec::new();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &settings, &mut diagnostics, |value| {
        seen.push(value.identity)
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Complete);
    assert_eq!(metadata_calls.load(Ordering::Relaxed), 1);
    assert_eq!(outcome.metrics.metadata_reads, 1);
    assert!(seen.iter().all(|identity| {
        !matches!(identity, ResourceIdentity::Filesystem { path } if path.starts_with(&excluded))
    }));
}

#[test]
fn root_replacement_during_metadata_hook_becomes_boundary_without_observation() {
    let tmp = tempfile::tempdir().unwrap();
    let base = camino::Utf8PathBuf::from_path_buf(fs::canonicalize(tmp.path()).unwrap()).unwrap();
    let root = base.join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("trigger"), b"old").unwrap();
    let identity = ApprovedRootIdentity::inspect(&root).unwrap();
    let old = base.join("root-old");
    let swapped = Arc::new(AtomicBool::new(false));
    let mut settings = scoped_options(identity);
    let flag = Arc::clone(&swapped);
    let hook_root = root.clone();
    settings.before_metadata = Some(Arc::new(move |_| {
        if !flag.swap(true, Ordering::Relaxed) {
            fs::rename(&hook_root, &old).unwrap();
            fs::create_dir(&hook_root).unwrap();
            fs::write(hook_root.join("trigger"), b"new").unwrap();
        }
    }));
    let mut seen = Vec::new();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root], &settings, &mut diagnostics, |value| {
        seen.push(value)
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(swapped.load(Ordering::Relaxed));
    assert!(seen.is_empty());
}

#[test]
fn approved_ancestor_replacement_during_hook_becomes_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let base = camino::Utf8PathBuf::from_path_buf(fs::canonicalize(tmp.path()).unwrap()).unwrap();
    let ancestor = base.join("ancestor");
    let root = ancestor.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("trigger"), b"old").unwrap();
    let identity = ApprovedRootIdentity::inspect(&root).unwrap();
    let old = base.join("ancestor-old");
    let swapped = Arc::new(AtomicBool::new(false));
    let mut settings = scoped_options(identity);
    let flag = Arc::clone(&swapped);
    let hook_ancestor = ancestor.clone();
    settings.before_metadata = Some(Arc::new(move |_| {
        if !flag.swap(true, Ordering::Relaxed) {
            fs::rename(&hook_ancestor, &old).unwrap();
            fs::create_dir_all(hook_ancestor.join("root")).unwrap();
            fs::write(hook_ancestor.join("root/trigger"), b"new").unwrap();
        }
    }));
    let mut seen = Vec::new();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root], &settings, &mut diagnostics, |value| {
        seen.push(value)
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(swapped.load(Ordering::Relaxed));
    assert!(seen.is_empty());
}

#[test]
fn approved_root_symlink_swap_during_hook_becomes_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let base = camino::Utf8PathBuf::from_path_buf(fs::canonicalize(tmp.path()).unwrap()).unwrap();
    let root = base.join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("trigger"), b"old").unwrap();
    let identity = ApprovedRootIdentity::inspect(&root).unwrap();
    let old = base.join("root-old");
    let swapped = Arc::new(AtomicBool::new(false));
    let mut settings = scoped_options(identity);
    let flag = Arc::clone(&swapped);
    let hook_root = root.clone();
    settings.before_metadata = Some(Arc::new(move |_| {
        if !flag.swap(true, Ordering::Relaxed) {
            fs::rename(&hook_root, &old).unwrap();
            std::os::unix::fs::symlink(&old, &hook_root).unwrap();
        }
    }));
    let mut seen = Vec::new();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root], &settings, &mut diagnostics, |value| {
        seen.push(value)
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(swapped.load(Ordering::Relaxed));
    assert!(seen.is_empty());
}

#[test]
fn missing_root_and_mount_boundary_are_partial() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = camino::Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("gone");
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[missing], &options(), &mut diagnostics, |_| {});
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(crosses_mount(1, 2, false));
    assert!(!crosses_mount(1, 2, true));
}

#[test]
fn cancellation_during_a_large_directory_has_bounded_latency() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    for n in 0..1000 {
        fs::write(root.join(format!("{n}")), b"x").unwrap();
    }
    let settings = options();
    let cancel = settings.cancellation.clone();
    let mut seen = 0;
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &settings, &mut diagnostics, |_| {
        seen += 1;
        if seen == 5 {
            cancel.store(true, Ordering::Relaxed);
        }
    });
    assert_eq!(outcome.coverage, TraversalCoverage::Cancelled);
    assert!(seen <= 6);
}

#[test]
fn unreadable_directory_degrades_coverage_and_preserves_root_grouping() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let denied = root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &options(), &mut diagnostics, |_| {});
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(diagnostics.groups().keys().any(|key| key.root == root));
}

#[test]
fn disappearing_entry_degrades_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let vanishing = root.join("vanish");
    fs::write(&vanishing, b"x").unwrap();
    let mut settings = options();
    settings.before_metadata = Some(Arc::new(|path| {
        if path.file_name() == Some("vanish") {
            let _ = fs::remove_file(path);
        }
    }));
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_observations(&[root.to_owned()], &settings, &mut diagnostics, |_| {});
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(
        diagnostics
            .groups()
            .keys()
            .any(|key| key.reason == "metadata_unavailable")
    );
}

struct NoSpill;

impl InodeSpill for NoSpill {
    fn contains(&mut self, _: u16, _: &str) -> std::io::Result<bool> {
        Ok(false)
    }
    fn spill(&mut self, _: u16, _: &[(String, u64)]) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn integrated_sink_overflow_forces_partial_coverage_without_corpus_retention() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    fs::write(root.join("build.log"), b"x").unwrap();
    let settings = options();
    let mut router = ObservationRouter::default();
    router.register("logs", [RouteInterest::Extension("log".into())]);
    let mut pipeline = StreamingPipeline {
        pool: settings.pool.clone(),
        cancellation: settings.cancellation.clone(),
        router,
        sink: CandidateSink::new(1, NoSpill),
        activity: ActivityIndex::new(1),
        ownership: ProjectOwnershipIndex::new(1),
        metrics: ScanMetrics::default(),
    };
    let mut limits = BTreeMap::new();
    limits.insert(BudgetKind::CandidateCount, 0);
    limits.insert(BudgetKind::CandidateBytes, 0);
    limits.insert(BudgetKind::InodeEntries, 0);
    let mut budget = ScanBudget { limits }.tracker();
    let mut diagnostics = DiagnosticAggregator::new(10, 2);
    let outcome = stream_into_pipeline(
        &[root.to_owned()],
        &settings,
        &mut diagnostics,
        &mut pipeline,
        &mut budget,
    )
    .unwrap();
    assert_eq!(outcome.coverage, TraversalCoverage::Partial);
    assert!(pipeline.sink.overflow.is_some());
}
