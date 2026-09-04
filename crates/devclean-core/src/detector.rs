use crate::{BudgetKind, CoverageStatus, DetectedArtifact, Observation, OverflowEvent};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectorDescriptor {
    pub id: &'static str,
    pub version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationInterest {
    Basename(&'static str),
    Extension(&'static str),
    ResourceKind(&'static str),
}

pub struct DetectorContext<'a> {
    pub observations: &'a [Observation],
    pub artifact_limit: usize,
}

pub struct DetectorOutcome {
    pub artifacts: Vec<DetectedArtifact>,
    pub overflow: Option<OverflowEvent>,
    pub coverage: CoverageStatus,
}

impl DetectorOutcome {
    pub fn bounded(artifacts: impl IntoIterator<Item = DetectedArtifact>, limit: usize) -> Self {
        let mut values = Vec::with_capacity(limit.min(1024));
        for artifact in artifacts {
            if values.len() == limit {
                return Self {
                    artifacts: values,
                    overflow: Some(OverflowEvent {
                        kind: BudgetKind::CandidateCount,
                        limit: limit as u64,
                        attempted: limit.saturating_add(1) as u64,
                    }),
                    coverage: CoverageStatus::Truncated,
                };
            }
            values.push(artifact);
        }
        Self {
            artifacts: values,
            overflow: None,
            coverage: CoverageStatus::Complete,
        }
    }

    pub fn failed() -> Self {
        Self {
            artifacts: vec![],
            overflow: None,
            coverage: CoverageStatus::Failed,
        }
    }
}

pub trait Detector: Send + Sync {
    fn descriptor(&self) -> DetectorDescriptor;
    fn interests(&self) -> &'static [ObservationInterest];
    fn detect(&self, context: DetectorContext<'_>) -> DetectorOutcome;
}
