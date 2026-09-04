use crate::{BudgetKind, InodeSpill, LogicalCandidateId, OverflowEvent};
use camino::{Utf8Path, Utf8PathBuf};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PhysicalExtent {
    pub device: u64,
    pub inode: u64,
    pub allocated_bytes: u64,
    pub candidates: Vec<LogicalCandidateId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PhysicalAccounting {
    pub unique_bytes: u64,
    pub additive_bytes: BTreeMap<LogicalCandidateId, u64>,
    pub shared_bytes: BTreeMap<LogicalCandidateId, u64>,
}

#[derive(Debug, Error)]
pub enum AccountingError {
    #[error("physical accounting overflow")]
    Overflow(OverflowEvent),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("accounting cancelled")]
    Cancelled,
}

impl PhysicalAccounting {
    pub fn from_extents<S: InodeSpill>(
        extents: impl IntoIterator<Item = PhysicalExtent>,
        max_candidates: usize,
        spill: &mut S,
    ) -> Result<Self, AccountingError> {
        Self::from_extents_cancellable(extents, max_candidates, spill, &AtomicBool::new(false))
    }

    pub fn from_extents_cancellable<S: InodeSpill>(
        extents: impl IntoIterator<Item = PhysicalExtent>,
        max_candidates: usize,
        spill: &mut S,
        cancellation: &AtomicBool,
    ) -> Result<Self, AccountingError> {
        if cancellation.load(Ordering::Relaxed) {
            return Err(AccountingError::Cancelled);
        }
        let mut result = Self::default();
        let mut candidates = BTreeSet::new();
        for extent in extents {
            if cancellation.load(Ordering::Relaxed) {
                return Err(AccountingError::Cancelled);
            }
            let key = format!("{}:{}", extent.device, extent.inode);
            let digest = blake3::hash(key.as_bytes());
            let partition = u16::from_be_bytes([digest.as_bytes()[0], digest.as_bytes()[1]]);
            if spill.contains(partition, &key)? {
                continue;
            }
            spill.spill(partition, &[(key, extent.allocated_bytes)])?;
            let owners: BTreeSet<_> = extent.candidates.into_iter().collect();
            for owner in &owners {
                if !candidates.contains(owner) && candidates.len() == max_candidates {
                    return Err(AccountingError::Overflow(OverflowEvent {
                        kind: BudgetKind::CandidateCount,
                        limit: max_candidates as u64,
                        attempted: max_candidates.saturating_add(1) as u64,
                    }));
                }
                candidates.insert(owner.clone());
            }
            checked_total(&mut result.unique_bytes, extent.allocated_bytes)?;
            if owners.len() == 1 {
                let total = result
                    .additive_bytes
                    .entry(owners.into_iter().next().expect("one owner"))
                    .or_default();
                checked_total(total, extent.allocated_bytes)?;
            } else {
                for owner in owners {
                    let total = result.shared_bytes.entry(owner).or_default();
                    checked_total(total, extent.allocated_bytes)?;
                }
            }
        }
        Ok(result)
    }
}

fn accounting_overflow() -> AccountingError {
    AccountingError::Overflow(OverflowEvent {
        kind: BudgetKind::InodeEntries,
        limit: u64::MAX,
        attempted: u64::MAX,
    })
}

fn checked_total(total: &mut u64, increment: u64) -> Result<(), AccountingError> {
    *total = total
        .checked_add(increment)
        .ok_or_else(accounting_overflow)?;
    Ok(())
}

#[cfg(test)]
mod overflow_tests {
    use super::*;

    #[test]
    fn unique_total_overflow_is_typed() {
        let mut total = u64::MAX;
        assert!(matches!(
            checked_total(&mut total, 1),
            Err(AccountingError::Overflow(_))
        ));
    }

    #[test]
    fn additive_owner_total_overflow_is_typed() {
        let mut totals = BTreeMap::from([(LogicalCandidateId::derive("t", "o", "a"), u64::MAX)]);
        let total = totals.values_mut().next().unwrap();
        assert!(matches!(
            checked_total(total, 1),
            Err(AccountingError::Overflow(_))
        ));
    }

    #[test]
    fn shared_owner_total_overflow_is_typed() {
        let mut totals =
            BTreeMap::from([(LogicalCandidateId::derive("t", "o", "shared"), u64::MAX)]);
        let total = totals.values_mut().next().unwrap();
        assert!(matches!(
            checked_total(total, 1),
            Err(AccountingError::Overflow(_))
        ));
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelationshipIndex {
    pub parent: BTreeMap<Utf8PathBuf, Utf8PathBuf>,
}

impl RelationshipIndex {
    pub fn build(paths: impl IntoIterator<Item = Utf8PathBuf>) -> Self {
        Self::build_cancellable(paths, &AtomicBool::new(false)).expect("cancellation disabled")
    }

    pub fn build_cancellable(
        paths: impl IntoIterator<Item = Utf8PathBuf>,
        cancellation: &AtomicBool,
    ) -> Option<Self> {
        let mut paths: Vec<_> = paths.into_iter().collect();
        if cancellation.load(Ordering::Relaxed) {
            return None;
        }
        paths.sort();
        paths.dedup();
        let mut stack: Vec<Utf8PathBuf> = Vec::new();
        let mut parent = BTreeMap::new();
        for path in paths {
            if cancellation.load(Ordering::Relaxed) {
                return None;
            }
            while stack
                .last()
                .is_some_and(|ancestor| !is_strict_ancestor(ancestor, &path))
            {
                stack.pop();
            }
            if let Some(ancestor) = stack.last() {
                parent.insert(path.clone(), ancestor.clone());
            }
            stack.push(path);
        }
        Some(Self { parent })
    }
}

fn is_strict_ancestor(parent: &Utf8Path, child: &Utf8Path) -> bool {
    parent != child && child.starts_with(parent)
}
