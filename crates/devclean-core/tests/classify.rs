use devclean_core::*;

fn artifact(required: RequiredProbeSet) -> DetectedArtifact {
    DetectedArtifact {
        id: LogicalCandidateId::derive("test", "owner", "path"),
        identity: ResourceIdentity::Filesystem {
            path: "path".into(),
        },
        fingerprint: ResourceFingerprint::filesystem(1, 2, "dir", 0, 1),
        category: ArtifactCategory::Cache,
        evidence: vec![Evidence {
            code: EvidenceCode::KnownCache,
            source: "fixture".into(),
            confidence: Confidence::High,
        }],
        required_probes: required,
        protection_signals: vec![],
    }
}

fn complete_for(value: &DetectedArtifact) -> CoverageMap {
    let mut coverage = CoverageMap::default();
    for probe in [
        ProbeKind::ApprovedScope,
        ProbeKind::Rebuildability,
        ProbeKind::Activity,
        ProbeKind::OpenFiles,
        ProbeKind::FilesystemIdentity,
    ] {
        coverage.insert(value.id.clone(), probe, CoverageStatus::Complete);
    }
    coverage
}

#[test]
fn degraded_coverage_cannot_escalate_classification() {
    let required: RequiredProbeSet = [ProbeKind::Activity].into_iter().collect();
    let value = artifact(required.clone());
    let complete = complete_for(&value);
    let mut partial = complete.clone();
    partial.insert(
        value.id.clone(),
        ProbeKind::Activity,
        CoverageStatus::Partial,
    );
    assert_eq!(
        classify(value, &complete, &Policy::default()).tier(),
        Tier::Safe
    );
    assert_eq!(
        classify(artifact(required), &partial, &Policy::default()).tier(),
        Tier::Protected
    );
}

#[test]
fn every_hard_protection_blocks_safe_and_every_mandatory_probe_fails_closed() {
    let complete = complete_for(&artifact(RequiredProbeSet::default()));
    for signal in [
        ProtectionSignal::Active,
        ProtectionSignal::OpenFile,
        ProtectionSignal::Mounted,
        ProtectionSignal::Dirty,
        ProtectionSignal::Untracked,
        ProtectionSignal::Unpublished,
        ProtectionSignal::UnreachableCommit,
        ProtectionSignal::DockerVolume,
        ProtectionSignal::Database,
        ProtectionSignal::Archive,
        ProtectionSignal::UniqueState,
        ProtectionSignal::Inaccessible,
        ProtectionSignal::UnknownOwnership,
    ] {
        let mut value = artifact(RequiredProbeSet::default());
        value.protection_signals.push(signal);
        assert_eq!(
            classify(value, &complete, &Policy::default()).tier(),
            Tier::Protected
        );
    }
    for failed in [
        ProbeKind::ApprovedScope,
        ProbeKind::Rebuildability,
        ProbeKind::FilesystemIdentity,
        ProbeKind::Activity,
        ProbeKind::OpenFiles,
    ] {
        let mut coverage = complete.clone();
        coverage.insert(
            artifact(RequiredProbeSet::default()).id,
            failed,
            CoverageStatus::Partial,
        );
        assert_eq!(
            classify(
                artifact(RequiredProbeSet::default()),
                &coverage,
                &Policy::default()
            )
            .tier(),
            Tier::Protected
        );
    }
}

#[test]
fn git_and_docker_mandatory_probes_are_candidate_local_and_fail_closed() {
    let mut git = artifact(RequiredProbeSet::default());
    git.category = ArtifactCategory::Worktree;
    git.identity = ResourceIdentity::GitWorktree {
        common_dir: "/repo/.git".into(),
        worktree_id: "wt".into(),
    };
    let git_probes = [
        ProbeKind::ApprovedScope,
        ProbeKind::FilesystemIdentity,
        ProbeKind::Activity,
        ProbeKind::OpenFiles,
        ProbeKind::GitStatus,
        ProbeKind::GitRegistration,
        ProbeKind::GitReachability,
    ];
    let mut git_coverage = CoverageMap::default();
    for probe in git_probes.clone() {
        git_coverage.insert(git.id.clone(), probe, CoverageStatus::Complete);
    }
    assert_eq!(
        classify(git.clone(), &git_coverage, &Policy::default()).tier(),
        Tier::Review
    );
    for failed in git_probes {
        let mut coverage = git_coverage.clone();
        coverage.insert(git.id.clone(), failed, CoverageStatus::Failed);
        assert_eq!(
            classify(git.clone(), &coverage, &Policy::default()).tier(),
            Tier::Protected
        );
    }

    let mut docker = artifact(RequiredProbeSet::default());
    docker.identity = ResourceIdentity::Docker {
        daemon: "engine".into(),
        object_kind: "cache".into(),
        id: "id".into(),
    };
    let docker_probes = [
        ProbeKind::Rebuildability,
        ProbeKind::DockerSnapshot,
        ProbeKind::DockerReferences,
    ];
    let mut docker_coverage = CoverageMap::default();
    for probe in docker_probes.clone() {
        docker_coverage.insert(docker.id.clone(), probe, CoverageStatus::Complete);
    }
    assert_eq!(
        classify(docker.clone(), &docker_coverage, &Policy::default()).tier(),
        Tier::Safe
    );
    for failed in docker_probes {
        let mut coverage = docker_coverage.clone();
        coverage.insert(docker.id.clone(), failed, CoverageStatus::Truncated);
        assert_eq!(
            classify(docker.clone(), &coverage, &Policy::default()).tier(),
            Tier::Protected
        );
    }
}

#[test]
fn detector_output_reports_overflow() {
    let outcome = DetectorOutcome::bounded(
        [
            artifact(RequiredProbeSet::default()),
            artifact(RequiredProbeSet::default()),
        ],
        1,
    );
    assert_eq!(outcome.artifacts.len(), 1);
    assert_eq!(outcome.overflow.unwrap().kind, BudgetKind::CandidateCount);
}
