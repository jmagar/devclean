pub mod accounting;
pub mod budget;
pub mod classify;
pub mod coverage;
pub mod detector;
pub mod model;
pub mod pool;
pub mod scope;
pub mod stream;

pub use accounting::{AccountingError, PhysicalAccounting, PhysicalExtent, RelationshipIndex};
pub use budget::{BudgetKind, OverflowEvent, ScanBudget, ScanBudgetTracker};
pub use classify::{Policy, SafetyProof, classify};
pub use coverage::{CoverageMap, CoverageStatus, ProbeKind, RequiredProbeSet};
pub use detector::{
    Detector, DetectorContext, DetectorDescriptor, DetectorOutcome, ObservationInterest,
};
pub use model::{
    AdvisoryCandidate, ArtifactCategory, ClassifiedCandidate, Confidence, DetectedArtifact,
    Evidence, EvidenceCode, LogicalCandidateId, Observation, ProtectionSignal, ResourceFingerprint,
    ResourceIdentity, SizeProvenance, Tier,
};
pub use pool::{PermitKind, WorkPermit, WorkPool};
pub use scope::{ApprovedRootIdentity, ScopeDecision, ScopePolicy};
pub use stream::{
    ActivityIndex, CandidateAggregate, CandidateSink, DiagnosticAggregator, DiagnosticKey,
    DiagnosticSummary, InodeSpill, ObservationRouter, ProjectOwnershipIndex, RouteInterest,
    ScanMetrics, StreamingPipeline,
};
