use devclean_core::*;

fn statuses() -> [CoverageStatus; 9] {
    [
        CoverageStatus::Complete,
        CoverageStatus::Skipped,
        CoverageStatus::Unsupported,
        CoverageStatus::Unknown,
        CoverageStatus::Stale,
        CoverageStatus::Partial,
        CoverageStatus::Truncated,
        CoverageStatus::TimedOut,
        CoverageStatus::Failed,
    ]
}

#[test]
fn coverage_join_is_exhaustively_commutative_associative_and_idempotent() {
    for a in statuses() {
        assert_eq!(a.join(&a), a);
        for b in statuses() {
            assert_eq!(a.join(&b), b.join(&a));
            for c in statuses() {
                assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
            }
        }
    }
}

#[test]
fn coverage_join_permutations_preserve_the_worst_status() {
    let permutations = [
        [
            CoverageStatus::Partial,
            CoverageStatus::Failed,
            CoverageStatus::TimedOut,
        ],
        [
            CoverageStatus::TimedOut,
            CoverageStatus::Partial,
            CoverageStatus::Failed,
        ],
        [
            CoverageStatus::Failed,
            CoverageStatus::TimedOut,
            CoverageStatus::Partial,
        ],
    ];
    for values in permutations {
        assert_eq!(
            values
                .iter()
                .fold(CoverageStatus::Complete, |total, value| total.join(value)),
            CoverageStatus::Failed
        );
    }
}

#[test]
fn every_required_probe_is_complete_for_the_same_candidate() {
    let a = LogicalCandidateId::derive("test", "owner", "a");
    let b = LogicalCandidateId::derive("test", "owner", "b");
    let required: RequiredProbeSet = [ProbeKind::Activity, ProbeKind::FilesystemIdentity]
        .into_iter()
        .collect();
    let mut coverage = CoverageMap::default();
    coverage.insert(a.clone(), ProbeKind::Activity, CoverageStatus::Complete);
    coverage.insert(
        a.clone(),
        ProbeKind::FilesystemIdentity,
        CoverageStatus::Complete,
    );
    coverage.insert(b.clone(), ProbeKind::Activity, CoverageStatus::Complete);
    assert!(coverage.satisfies(&a, &required));
    assert!(!coverage.satisfies(&b, &required));
    coverage.insert(a.clone(), ProbeKind::Activity, CoverageStatus::Partial);
    assert!(!coverage.satisfies(&a, &required));
}

#[test]
fn missing_candidate_never_borrows_another_candidates_authority() {
    let a = LogicalCandidateId::derive("test", "owner", "a");
    let b = LogicalCandidateId::derive("test", "owner", "b");
    let required: RequiredProbeSet = [ProbeKind::OpenFiles].into_iter().collect();
    let mut coverage = CoverageMap::default();
    coverage.insert(a, ProbeKind::OpenFiles, CoverageStatus::Complete);
    assert!(!coverage.satisfies(&b, &required));
}
