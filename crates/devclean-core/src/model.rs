use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::coverage::CoverageStatus;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct LogicalCandidateId(pub Uuid);

impl LogicalCandidateId {
    pub fn derive(detector: &str, owner: &str, logical_location: &str) -> Self {
        let material = format!("{detector}\0{owner}\0{logical_location}");
        Self(Uuid::new_v5(&Uuid::NAMESPACE_URL, material.as_bytes()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ResourceFingerprint(pub String);

impl ResourceFingerprint {
    pub fn filesystem(device: u64, inode: u64, kind: &str, size: u64, modified_ns: i128) -> Self {
        let material = format!("fs\0{device}\0{inode}\0{kind}\0{size}\0{modified_ns}");
        Self(blake3::hash(material.as_bytes()).to_hex().to_string())
    }

    pub fn opaque(namespace: &str, identity: &str) -> Self {
        let material = format!("{namespace}\0{identity}");
        Self(blake3::hash(material.as_bytes()).to_hex().to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceIdentity {
    Filesystem {
        #[schemars(with = "String")]
        path: Utf8PathBuf,
    },
    Docker {
        daemon: String,
        object_kind: String,
        id: String,
    },
    GitWorktree {
        #[schemars(with = "String")]
        common_dir: Utf8PathBuf,
        worktree_id: String,
    },
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCode {
    GeneratedLayout,
    ManifestPresent,
    KnownCache,
    Inactive,
    Shared,
    Stateful,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub code: EvidenceCode,
    pub source: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    Build,
    Cache,
    Dependency,
    Log,
    Worktree,
    Container,
    Image,
    Volume,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub identity: ResourceIdentity,
    pub fingerprint: ResourceFingerprint,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedArtifact {
    pub id: LogicalCandidateId,
    pub identity: ResourceIdentity,
    pub fingerprint: ResourceFingerprint,
    pub category: ArtifactCategory,
    pub evidence: Vec<Evidence>,
    pub required_probes: crate::RequiredProbeSet,
    pub protection_signals: Vec<ProtectionSignal>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionSignal {
    Active,
    OpenFile,
    Mounted,
    Dirty,
    Untracked,
    Unpublished,
    UnreachableCommit,
    DockerVolume,
    Database,
    Archive,
    UniqueState,
    Inaccessible,
    UnknownOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Safe,
    Review,
    Protected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedCandidate {
    pub(crate) artifact: DetectedArtifact,
    pub(crate) tier: Tier,
    pub(crate) protections: Vec<String>,
}

impl ClassifiedCandidate {
    pub fn id(&self) -> &LogicalCandidateId {
        &self.artifact.id
    }
    pub fn tier(&self) -> Tier {
        self.tier
    }
    pub fn protections(&self) -> &[String] {
        &self.protections
    }
    pub fn into_advisory(self) -> AdvisoryCandidate {
        let size_provenance =
            if matches!(self.artifact.identity, ResourceIdentity::Filesystem { .. }) {
                SizeProvenance::RecursiveFilesystemExtent
            } else {
                SizeProvenance::DirectInventory
            };
        AdvisoryCandidate {
            id: self.artifact.id,
            identity: self.artifact.identity,
            fingerprint: self.artifact.fingerprint,
            category: self.artifact.category,
            positive_evidence: self
                .artifact
                .evidence
                .into_iter()
                .filter(|evidence| {
                    matches!(
                        evidence.code,
                        EvidenceCode::GeneratedLayout
                            | EvidenceCode::ManifestPresent
                            | EvidenceCode::KnownCache
                    )
                })
                .take(16)
                .map(|mut evidence| {
                    evidence.source = bounded_evidence_source(&evidence.source);
                    evidence
                })
                .collect(),
            tier: self.tier,
            protections: self.protections,
            coverage: CoverageStatus::Complete,
            logical_bytes_estimate: None,
            physical_bytes_estimate: None,
            shared_physical_bytes: None,
            size_provenance,
        }
    }
}

/// Classified candidates cannot be constructed outside the central policy.
///
/// ```compile_fail
/// use devclean_core::{ClassifiedCandidate, Tier};
/// let _ = ClassifiedCandidate { artifact: panic!(), tier: Tier::Safe, protections: vec![] };
/// ```
const _CLASSIFIED_CANDIDATE_AUTHORITY_BOUNDARY: () = ();

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdvisoryCandidate {
    pub id: LogicalCandidateId,
    pub identity: ResourceIdentity,
    pub fingerprint: ResourceFingerprint,
    pub category: ArtifactCategory,
    pub positive_evidence: Vec<Evidence>,
    pub tier: Tier,
    pub protections: Vec<String>,
    /// Candidate-local probe authority. This is report evidence only and cannot
    /// be used to construct an authorized cleanup action.
    pub coverage: CoverageStatus,
    /// Recursive logical size observed at or below this candidate. `None`
    /// means the inventory source did not provide a bounded estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_bytes_estimate: Option<u64>,
    /// Inode-deduplicated allocated bytes at or below this candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_bytes_estimate: Option<u64>,
    /// Portion of the physical estimate also attributed to another candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_physical_bytes: Option<u64>,
    pub size_provenance: SizeProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SizeProvenance {
    RecursiveFilesystemExtent,
    DirectInventory,
}

fn bounded_evidence_source(value: &str) -> String {
    value
        .chars()
        .take(128)
        .flat_map(char::escape_default)
        .collect()
}
