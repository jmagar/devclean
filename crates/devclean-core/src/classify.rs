use crate::{
    ArtifactCategory, ClassifiedCandidate, CoverageMap, DetectedArtifact, EvidenceCode, ProbeKind,
    ProtectionSignal, RequiredProbeSet, ResourceIdentity, Tier,
};

#[derive(Clone, Debug)]
pub struct Policy {
    pub safe_builds: bool,
    pub safe_caches: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            safe_builds: true,
            safe_caches: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyProof {
    pub required: RequiredProbeSet,
    pub missing: RequiredProbeSet,
    pub blockers: Vec<ProtectionSignal>,
    pub positively_identified: bool,
}

impl SafetyProof {
    pub fn evaluate(artifact: &DetectedArtifact, coverage: &CoverageMap) -> Self {
        let mut required = artifact.required_probes.clone();
        match artifact.identity {
            ResourceIdentity::Filesystem { .. } => required.0.extend([
                ProbeKind::ApprovedScope,
                ProbeKind::Rebuildability,
                ProbeKind::FilesystemIdentity,
                ProbeKind::Activity,
                ProbeKind::OpenFiles,
            ]),
            ResourceIdentity::GitWorktree { .. } => required.0.extend([
                ProbeKind::ApprovedScope,
                ProbeKind::FilesystemIdentity,
                ProbeKind::Activity,
                ProbeKind::OpenFiles,
                ProbeKind::GitStatus,
                ProbeKind::GitRegistration,
                ProbeKind::GitReachability,
            ]),
            ResourceIdentity::Docker { .. } => required.0.extend([
                ProbeKind::Rebuildability,
                ProbeKind::DockerSnapshot,
                ProbeKind::DockerReferences,
            ]),
        }
        if artifact
            .evidence
            .iter()
            .any(|e| e.code == EvidenceCode::ManifestPresent)
        {
            required.0.insert(ProbeKind::Metadata);
        }
        let missing = required
            .0
            .iter()
            .filter(|probe| {
                !coverage
                    .status(&artifact.id, probe)
                    .is_some_and(crate::CoverageStatus::grants_authority)
            })
            .cloned()
            .collect();
        let positively_identified = artifact.evidence.iter().any(|e| {
            matches!(
                e.code,
                EvidenceCode::GeneratedLayout
                    | EvidenceCode::ManifestPresent
                    | EvidenceCode::KnownCache
            )
        });
        Self {
            required,
            missing: RequiredProbeSet(missing),
            blockers: artifact.protection_signals.clone(),
            positively_identified,
        }
    }
}

pub fn classify(
    artifact: DetectedArtifact,
    coverage: &CoverageMap,
    policy: &Policy,
) -> ClassifiedCandidate {
    let proof = SafetyProof::evaluate(&artifact, coverage);
    let mut protections: Vec<String> = proof
        .blockers
        .iter()
        .map(|signal| format!("{signal:?}").to_lowercase())
        .collect();
    let tier = if !proof.blockers.is_empty()
        || artifact
            .evidence
            .iter()
            .any(|e| e.code == EvidenceCode::Stateful)
    {
        if artifact
            .evidence
            .iter()
            .any(|e| e.code == EvidenceCode::Stateful)
        {
            protections.push("stateful".into());
        }
        Tier::Protected
    } else if !proof.missing.0.is_empty() {
        protections.push("mandatory_probe_incomplete".into());
        Tier::Protected
    } else if !proof.positively_identified
        || artifact
            .evidence
            .iter()
            .any(|e| e.code == EvidenceCode::Ambiguous)
    {
        Tier::Unknown
    } else {
        match artifact.category {
            ArtifactCategory::Build if policy.safe_builds => Tier::Safe,
            ArtifactCategory::Cache if policy.safe_caches => Tier::Safe,
            _ => Tier::Review,
        }
    };
    ClassifiedCandidate {
        artifact,
        tier,
        protections,
    }
}
