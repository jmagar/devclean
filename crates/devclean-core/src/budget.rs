use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    QueueItems,
    CandidateCount,
    CandidateBytes,
    InodeEntries,
    ActivityEntries,
    ProjectOwners,
    EvidenceBytes,
    Diagnostics,
    CommandBytes,
    DockerObjects,
    DockerBytes,
    ReportBytes,
    TerminalRows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OverflowEvent {
    pub kind: BudgetKind,
    pub limit: u64,
    pub attempted: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ScanBudget {
    pub limits: BTreeMap<BudgetKind, u64>,
}

#[derive(Clone, Debug)]
pub struct ScanBudgetTracker {
    limits: BTreeMap<BudgetKind, u64>,
    used: BTreeMap<BudgetKind, u64>,
}

impl ScanBudget {
    pub fn tracker(&self) -> ScanBudgetTracker {
        ScanBudgetTracker {
            limits: self.limits.clone(),
            used: BTreeMap::new(),
        }
    }
}

impl ScanBudgetTracker {
    pub fn used(&self, kind: BudgetKind) -> u64 {
        self.used.get(&kind).copied().unwrap_or(0)
    }

    pub fn try_reserve_many(
        &mut self,
        reservations: &[(BudgetKind, u64)],
    ) -> Result<(), OverflowEvent> {
        let mut next = self.used.clone();
        for (kind, amount) in reservations {
            let limit = self.limits.get(kind).copied().unwrap_or(0);
            let attempted = next.get(kind).copied().unwrap_or(0).saturating_add(*amount);
            if attempted > limit {
                return Err(OverflowEvent {
                    kind: *kind,
                    limit,
                    attempted,
                });
            }
            next.insert(*kind, attempted);
        }
        self.used = next;
        Ok(())
    }

    pub fn try_reserve(&mut self, kind: BudgetKind, amount: u64) -> Result<(), OverflowEvent> {
        self.try_reserve_many(&[(kind, amount)])
    }
}
