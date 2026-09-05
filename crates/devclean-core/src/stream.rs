use crate::{
    BudgetKind, Observation, OverflowEvent, PermitKind, ResourceIdentity, ScanBudgetTracker,
    WorkPool,
};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RouteInterest {
    Basename(String),
    Extension(String),
    ApprovedCache(String),
    ProjectOwner(String),
    ResourceKind(String),
}

#[derive(Clone, Debug, Default)]
pub struct ObservationRouter {
    routes: BTreeMap<RouteInterest, BTreeSet<String>>,
}

impl ObservationRouter {
    pub fn register(
        &mut self,
        detector: impl Into<String>,
        interests: impl IntoIterator<Item = RouteInterest>,
    ) {
        let detector = detector.into();
        for interest in interests {
            self.routes
                .entry(interest)
                .or_default()
                .insert(detector.clone());
        }
    }

    pub fn route(&self, observation: &Observation, metrics: &mut ScanMetrics) -> Vec<String> {
        let mut keys = Vec::with_capacity(5);
        match &observation.identity {
            ResourceIdentity::Filesystem { path } => {
                if let Some(name) = path.file_name() {
                    keys.push(RouteInterest::Basename(name.to_owned()));
                }
                if let Some(extension) = path.extension() {
                    keys.push(RouteInterest::Extension(extension.to_owned()));
                }
                keys.push(RouteInterest::ResourceKind("filesystem".into()));
            }
            ResourceIdentity::Docker { object_kind, .. } => {
                keys.push(RouteInterest::ResourceKind(object_kind.clone()));
            }
            ResourceIdentity::GitWorktree { .. } => {
                keys.push(RouteInterest::ResourceKind("git_worktree".into()));
            }
        }
        if let Some(value) = observation.attributes.get("approved_cache") {
            keys.push(RouteInterest::ApprovedCache(value.clone()));
        }
        if let Some(value) = observation.attributes.get("project_owner") {
            keys.push(RouteInterest::ProjectOwner(value.clone()));
        }
        let mut matches = BTreeSet::new();
        for key in keys {
            metrics.route_lookups += 1;
            if let Some(detectors) = self.routes.get(&key) {
                matches.extend(detectors.iter().cloned());
            }
        }
        metrics.detector_visits += matches.len() as u64;
        matches.into_iter().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateAggregate {
    pub observations: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

pub trait InodeSpill {
    fn contains(&mut self, partition: u16, key: &str) -> std::io::Result<bool>;
    fn spill(&mut self, partition: u16, entries: &[(String, u64)]) -> std::io::Result<()>;
}

pub struct CandidateSink<S> {
    aggregates: BTreeMap<String, CandidateAggregate>,
    inode_partitions: BTreeMap<u16, BTreeMap<String, u64>>,
    max_inodes_per_partition: usize,
    spill: S,
    pub overflow: Option<OverflowEvent>,
}

impl<S: InodeSpill> CandidateSink<S> {
    pub fn new(max_inodes_per_partition: usize, spill: S) -> Self {
        Self {
            aggregates: BTreeMap::new(),
            inode_partitions: BTreeMap::new(),
            max_inodes_per_partition,
            spill,
            overflow: None,
        }
    }

    pub fn retain(
        &mut self,
        detector: &str,
        observation: &Observation,
        inode_key: Option<String>,
        budget: &mut ScanBudgetTracker,
    ) -> std::io::Result<()> {
        if !self.aggregates.contains_key(detector) {
            let retained_bytes = detector
                .len()
                .saturating_add(std::mem::size_of::<CandidateAggregate>())
                as u64;
            if let Err(event) = budget.try_reserve_many(&[
                (BudgetKind::CandidateCount, 1),
                (BudgetKind::CandidateBytes, retained_bytes),
            ]) {
                self.overflow = Some(event);
                return Ok(());
            }
        }
        let aggregate = self
            .aggregates
            .entry(detector.to_owned())
            .or_insert(CandidateAggregate {
                observations: 0,
                logical_bytes: 0,
                allocated_bytes: 0,
            });
        aggregate.observations += 1;
        aggregate.logical_bytes = aggregate
            .logical_bytes
            .saturating_add(observation.logical_bytes.unwrap_or(0));
        if let Some(key) = inode_key {
            let digest = blake3::hash(key.as_bytes());
            let partition = u16::from_be_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]);
            let entries = self.inode_partitions.entry(partition).or_default();
            let seen = entries.contains_key(&key) || self.spill.contains(partition, &key)?;
            if !seen {
                if let Err(event) = budget.try_reserve_many(&[
                    (BudgetKind::InodeEntries, 1),
                    (BudgetKind::CandidateBytes, key.len() as u64),
                ]) {
                    self.overflow = Some(event);
                    return Ok(());
                }
                entries.insert(key, observation.allocated_bytes.unwrap_or(0));
                aggregate.allocated_bytes = aggregate
                    .allocated_bytes
                    .saturating_add(observation.allocated_bytes.unwrap_or(0));
            }
            if entries.len() >= self.max_inodes_per_partition {
                let values: Vec<_> = std::mem::take(entries).into_iter().collect();
                self.spill.spill(partition, &values)?;
            }
        } else {
            aggregate.allocated_bytes = aggregate
                .allocated_bytes
                .saturating_add(observation.allocated_bytes.unwrap_or(0));
        }
        Ok(())
    }

    pub fn aggregates(&self) -> &BTreeMap<String, CandidateAggregate> {
        &self.aggregates
    }
}

#[derive(Clone, Debug)]
pub struct ActivityIndex {
    active: BTreeSet<Utf8PathBuf>,
    limit: usize,
    pub overflow: Option<OverflowEvent>,
}

impl ActivityIndex {
    pub fn new(limit: usize) -> Self {
        Self {
            active: BTreeSet::new(),
            limit,
            overflow: None,
        }
    }
    pub fn insert(&mut self, path: Utf8PathBuf) {
        if !self.active.contains(&path) && self.active.len() == self.limit {
            self.overflow = Some(OverflowEvent {
                kind: BudgetKind::ActivityEntries,
                limit: self.limit as u64,
                attempted: self.limit.saturating_add(1) as u64,
            });
            return;
        }
        self.active.insert(path);
    }
    pub fn matches_prefix(&self, path: &Utf8Path) -> bool {
        self.active
            .range(path.to_owned()..)
            .next()
            .is_some_and(|active| active.starts_with(path))
    }
}

impl Default for ActivityIndex {
    fn default() -> Self {
        Self::new(100_000)
    }
}

#[derive(Clone, Debug)]
pub struct ProjectOwnershipIndex {
    owners: BTreeMap<Utf8PathBuf, String>,
    limit: usize,
    pub overflow: Option<OverflowEvent>,
}

impl ProjectOwnershipIndex {
    pub fn new(limit: usize) -> Self {
        Self {
            owners: BTreeMap::new(),
            limit,
            overflow: None,
        }
    }
    pub fn insert(&mut self, root: Utf8PathBuf, owner: String) {
        if !self.owners.contains_key(&root) && self.owners.len() == self.limit {
            self.overflow = Some(OverflowEvent {
                kind: BudgetKind::ProjectOwners,
                limit: self.limit as u64,
                attempted: self.limit.saturating_add(1) as u64,
            });
            return;
        }
        self.owners.insert(root, owner);
    }
    pub fn owner_for(&self, path: &Utf8Path) -> Option<&str> {
        path.ancestors()
            .find_map(|ancestor| self.owners.get(ancestor).map(String::as_str))
    }
}

impl Default for ProjectOwnershipIndex {
    fn default() -> Self {
        Self::new(100_000)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DiagnosticKey {
    pub root: String,
    pub detector: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticSummary {
    pub count: u64,
    pub samples: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DiagnosticAggregator {
    max_groups: usize,
    max_samples: usize,
    groups: BTreeMap<DiagnosticKey, DiagnosticSummary>,
    pub dropped_groups: u64,
}

impl DiagnosticAggregator {
    pub fn new(max_groups: usize, max_samples: usize) -> Self {
        Self {
            max_groups,
            max_samples,
            groups: BTreeMap::new(),
            dropped_groups: 0,
        }
    }
    pub fn record(&mut self, key: DiagnosticKey, sample: String) {
        if !self.groups.contains_key(&key) && self.groups.len() == self.max_groups {
            self.dropped_groups += 1;
            return;
        }
        let summary = self.groups.entry(key).or_insert(DiagnosticSummary {
            count: 0,
            samples: vec![],
        });
        summary.count += 1;
        if summary.samples.len() < self.max_samples {
            summary.samples.push(sample);
        }
    }
    pub fn groups(&self) -> &BTreeMap<DiagnosticKey, DiagnosticSummary> {
        &self.groups
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanMetrics {
    pub entries_seen: u64,
    pub metadata_reads: u64,
    pub route_lookups: u64,
    pub detector_visits: u64,
    pub queue_high_water: u64,
    pub cancellation_checks: u64,
}

pub struct StreamingPipeline<S> {
    pub pool: Arc<WorkPool>,
    pub cancellation: Arc<std::sync::atomic::AtomicBool>,
    pub router: ObservationRouter,
    pub sink: CandidateSink<S>,
    pub activity: ActivityIndex,
    pub ownership: ProjectOwnershipIndex,
    pub metrics: ScanMetrics,
}

impl<S: InodeSpill> StreamingPipeline<S> {
    pub fn observe(
        &mut self,
        mut observation: Observation,
        budget: &mut ScanBudgetTracker,
    ) -> std::io::Result<()> {
        let _permit = self
            .pool
            .acquire(PermitKind::Detector, || {
                self.cancellation.load(std::sync::atomic::Ordering::Relaxed)
            })
            .ok_or_else(|| std::io::Error::other("detector permits disabled"))?;
        if let ResourceIdentity::Filesystem { path } = &observation.identity {
            if let Some(owner) = self.ownership.owner_for(path) {
                observation
                    .attributes
                    .insert("project_owner".into(), owner.into());
            }
            if self.activity.matches_prefix(path) {
                observation
                    .attributes
                    .insert("active".into(), "true".into());
            }
        }
        let inode_key = match (
            observation.attributes.get("device"),
            observation.attributes.get("inode"),
        ) {
            (Some(device), Some(inode)) => Some(format!("{device}:{inode}")),
            _ => None,
        };
        for detector in self.router.route(&observation, &mut self.metrics) {
            self.sink
                .retain(&detector, &observation, inode_key.clone(), budget)?;
        }
        Ok(())
    }
}
