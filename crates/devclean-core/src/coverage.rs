use crate::LogicalCandidateId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    FilesystemIdentity,
    Activity,
    OpenFiles,
    GitStatus,
    GitRegistration,
    GitReachability,
    DockerSnapshot,
    DockerReferences,
    Metadata,
    ApprovedScope,
    Rebuildability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Unsupported,
    Skipped,
    Partial,
    Failed,
    TimedOut,
    Truncated,
    Stale,
    Unknown,
}

impl CoverageStatus {
    pub fn grants_authority(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Monotonic aggregation from least to most actionable loss of coverage.
    pub fn join(&self, other: &Self) -> Self {
        if self.precedence() >= other.precedence() {
            self.clone()
        } else {
            other.clone()
        }
    }

    pub fn join_assign(&mut self, other: &Self) {
        *self = self.join(other);
    }

    fn precedence(&self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Skipped => 1,
            Self::Unsupported => 2,
            Self::Unknown => 3,
            Self::Stale => 4,
            Self::Partial => 5,
            Self::Truncated => 6,
            Self::TimedOut => 7,
            Self::Failed => 8,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequiredProbeSet(pub BTreeSet<ProbeKind>);

impl FromIterator<ProbeKind> for RequiredProbeSet {
    fn from_iter<T: IntoIterator<Item = ProbeKind>>(probes: T) -> Self {
        Self(probes.into_iter().collect())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageMap(pub BTreeMap<LogicalCandidateId, BTreeMap<ProbeKind, CoverageStatus>>);

impl CoverageMap {
    pub fn insert(
        &mut self,
        candidate: LogicalCandidateId,
        probe: ProbeKind,
        status: CoverageStatus,
    ) {
        self.0
            .entry(candidate)
            .or_default()
            .entry(probe)
            .and_modify(|current| current.join_assign(&status))
            .or_insert(status);
    }

    pub fn status(
        &self,
        candidate: &LogicalCandidateId,
        probe: &ProbeKind,
    ) -> Option<&CoverageStatus> {
        self.0.get(candidate)?.get(probe)
    }

    pub fn satisfies(&self, candidate: &LogicalCandidateId, required: &RequiredProbeSet) -> bool {
        required.0.iter().all(|probe| {
            self.status(candidate, probe)
                .is_some_and(CoverageStatus::grants_authority)
        })
    }
}
