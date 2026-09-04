use camino::Utf8PathBuf;
use devclean_core::*;
use std::collections::BTreeMap;
use std::sync::Arc;

fn observation(path: &str, bytes: u64) -> Observation {
    Observation {
        identity: ResourceIdentity::Filesystem { path: path.into() },
        fingerprint: ResourceFingerprint::opaque("test", path),
        logical_bytes: Some(bytes),
        allocated_bytes: Some(bytes),
        attributes: BTreeMap::new(),
    }
}

#[test]
fn router_visits_are_linear_in_observations_plus_matches() {
    let mut router = ObservationRouter::default();
    router.register("node", [RouteInterest::Basename("node_modules".into())]);
    router.register("logs", [RouteInterest::Extension("log".into())]);
    let mut metrics = ScanMetrics::default();
    let mut matches = 0;
    for n in 0..100_000 {
        let name = if n % 10 == 0 {
            "build.log"
        } else {
            "source.rs"
        };
        matches += router
            .route(&observation(&format!("/work/{n}/{name}"), 1), &mut metrics)
            .len();
    }
    assert_eq!(matches, 10_000);
    assert_eq!(metrics.detector_visits, 10_000);
    assert!(metrics.route_lookups <= 300_000);
}

#[derive(Default)]
struct Spill {
    keys: std::collections::BTreeSet<String>,
}
impl InodeSpill for Spill {
    fn contains(&mut self, _: u16, key: &str) -> std::io::Result<bool> {
        Ok(self.keys.contains(key))
    }
    fn spill(&mut self, _: u16, entries: &[(String, u64)]) -> std::io::Result<()> {
        self.keys.extend(entries.iter().map(|(key, _)| key.clone()));
        Ok(())
    }
}

#[test]
fn candidate_sink_deduplicates_hardlink_accounting_and_reports_overflow() {
    let mut limits = BTreeMap::new();
    limits.insert(BudgetKind::CandidateCount, 1);
    limits.insert(BudgetKind::CandidateBytes, 1024);
    limits.insert(BudgetKind::InodeEntries, 10);
    let mut budget = ScanBudget { limits }.tracker();
    let mut sink = CandidateSink::new(1, Spill::default());
    sink.retain(
        "rust",
        &observation("/a", 50),
        Some("1:2".into()),
        &mut budget,
    )
    .unwrap();
    sink.retain(
        "rust",
        &observation("/b", 50),
        Some("1:2".into()),
        &mut budget,
    )
    .unwrap();
    sink.retain("node", &observation("/c", 10), None, &mut budget)
        .unwrap();
    assert_eq!(sink.aggregates()["rust"].allocated_bytes, 50);
    assert_eq!(sink.aggregates()["rust"].observations, 2);
    assert_eq!(
        sink.overflow.as_ref().unwrap().kind,
        BudgetKind::CandidateCount
    );
}

#[test]
fn candidate_and_inode_retention_limits_are_typed() {
    let mut too_small = BTreeMap::new();
    too_small.insert(BudgetKind::CandidateCount, 1);
    too_small.insert(BudgetKind::CandidateBytes, 1);
    too_small.insert(BudgetKind::InodeEntries, 1);
    let mut budget = ScanBudget { limits: too_small }.tracker();
    let mut sink = CandidateSink::new(1, Spill::default());
    sink.retain("rust", &observation("/a", 1), None, &mut budget)
        .unwrap();
    assert_eq!(
        sink.overflow.as_ref().unwrap().kind,
        BudgetKind::CandidateBytes
    );
    assert!(sink.aggregates().is_empty());

    let mut limits = BTreeMap::new();
    limits.insert(BudgetKind::CandidateCount, 1);
    limits.insert(BudgetKind::CandidateBytes, 1024);
    limits.insert(BudgetKind::InodeEntries, 0);
    let mut budget = ScanBudget { limits }.tracker();
    let mut sink = CandidateSink::new(1, Spill::default());
    sink.retain(
        "rust",
        &observation("/a", 1),
        Some("1:2".into()),
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        sink.overflow.as_ref().unwrap().kind,
        BudgetKind::InodeEntries
    );
}

#[test]
#[ignore = "Task 10 diagnostic flood qualification"]
fn activity_prefix_lookup_and_diagnostics_are_bounded() {
    let mut activity = ActivityIndex::default();
    activity.insert(Utf8PathBuf::from("/work/project/target/file"));
    assert!(activity.matches_prefix(camino::Utf8Path::new("/work/project/target")));
    assert!(!activity.matches_prefix(camino::Utf8Path::new("/work/other")));

    let mut diagnostics = DiagnosticAggregator::new(1, 2);
    let key = DiagnosticKey {
        root: "/work".into(),
        detector: "fs".into(),
        reason: "gone".into(),
    };
    for sample in ["a", "b", "c"] {
        diagnostics.record(key.clone(), sample.into());
    }
    diagnostics.record(
        DiagnosticKey {
            root: "/other".into(),
            detector: "fs".into(),
            reason: "denied".into(),
        },
        "x".into(),
    );
    assert_eq!(diagnostics.groups()[&key].count, 3);
    assert_eq!(diagnostics.groups()[&key].samples.len(), 2);
    assert_eq!(diagnostics.dropped_groups, 1);

    let mut ownership = ProjectOwnershipIndex::default();
    ownership.insert("/work/project".into(), "cargo".into());
    assert_eq!(
        ownership.owner_for(camino::Utf8Path::new("/work/project/target/debug")),
        Some("cargo")
    );
    assert_eq!(
        ownership.owner_for(camino::Utf8Path::new("/work/other")),
        None
    );
}

#[test]
fn hundred_thousand_observations_stream_through_integrated_pipeline() {
    let rss_before = max_rss_bytes();
    let mut router = ObservationRouter::default();
    router.register("logs", [RouteInterest::Extension("log".into())]);
    let mut activity = ActivityIndex::new(10);
    activity.insert("/work/active".into());
    let mut ownership = ProjectOwnershipIndex::new(10);
    ownership.insert("/work".into(), "workspace".into());
    let mut pipeline = StreamingPipeline {
        pool: Arc::new(WorkPool::new(
            2,
            BTreeMap::from([(PermitKind::Detector, 1)]),
        )),
        cancellation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        router,
        sink: CandidateSink::new(128, Spill::default()),
        activity,
        ownership,
        metrics: ScanMetrics::default(),
    };
    let mut limits = BTreeMap::new();
    limits.insert(BudgetKind::CandidateCount, 2);
    limits.insert(BudgetKind::CandidateBytes, 2_000_000);
    limits.insert(BudgetKind::InodeEntries, 100_000);
    let mut budget = ScanBudget { limits }.tracker();
    for n in 0..100_000 {
        let mut value = observation(&format!("/work/project/{n}.log"), 1);
        value.attributes.insert("device".into(), "1".into());
        value.attributes.insert("inode".into(), n.to_string());
        pipeline.observe(value, &mut budget).unwrap();
    }
    assert_eq!(pipeline.sink.aggregates()["logs"].observations, 100_000);
    assert_eq!(pipeline.metrics.detector_visits, 100_000);
    let rss_growth = max_rss_bytes().saturating_sub(rss_before);
    assert!(
        rss_growth < 128 * 1024 * 1024,
        "RSS grew by {rss_growth} bytes"
    );
}

#[cfg(target_os = "macos")]
fn max_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0);
    unsafe { usage.assume_init().ru_maxrss as u64 }
}

#[cfg(not(target_os = "macos"))]
fn max_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0);
    unsafe { (usage.assume_init().ru_maxrss as u64).saturating_mul(1024) }
}
