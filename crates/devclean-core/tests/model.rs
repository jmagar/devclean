use devclean_core::*;
use std::collections::BTreeMap;

#[test]
fn logical_id_is_stable_while_fingerprint_tracks_replacement() {
    let a = LogicalCandidateId::derive("rust", "repo", "target");
    let b = LogicalCandidateId::derive("rust", "repo", "target");
    assert_eq!(a, b);
    assert_ne!(
        ResourceFingerprint::filesystem(1, 10, "dir", 4, 1),
        ResourceFingerprint::filesystem(1, 11, "dir", 4, 1)
    );
    assert_ne!(
        ResourceFingerprint::filesystem(1, 10, "dir", 4, 1),
        ResourceFingerprint::filesystem(1, 10, "dir", 4, 2)
    );
}

#[test]
fn report_candidate_is_advisory_only() {
    let value = AdvisoryCandidate {
        id: LogicalCandidateId::derive("rust", "repo", "target"),
        identity: ResourceIdentity::Filesystem {
            path: "repo/target".into(),
        },
        fingerprint: ResourceFingerprint::opaque("test", "one"),
        category: ArtifactCategory::Build,
        positive_evidence: vec![],
        tier: Tier::Safe,
        protections: vec![],
        coverage: CoverageStatus::Complete,
        logical_bytes_estimate: None,
        physical_bytes_estimate: None,
        shared_physical_bytes: None,
        size_provenance: SizeProvenance::RecursiveFilesystemExtent,
    };
    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: AdvisoryCandidate = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn observation_serialization_is_deterministic() {
    let observation = Observation {
        identity: ResourceIdentity::Filesystem { path: "x".into() },
        fingerprint: ResourceFingerprint::opaque("t", "x"),
        logical_bytes: Some(1),
        allocated_bytes: Some(4096),
        attributes: BTreeMap::new(),
    };
    assert_eq!(
        serde_json::to_string(&observation).unwrap(),
        serde_json::to_string(&observation).unwrap()
    );
}
