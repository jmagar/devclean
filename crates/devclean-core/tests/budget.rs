use devclean_core::*;
use std::collections::BTreeMap;

#[test]
fn overflow_is_explicit_and_does_not_mutate_usage() {
    let mut tracker = ScanBudget {
        limits: BTreeMap::from([(BudgetKind::QueueItems, 2)]),
    }
    .tracker();
    tracker.try_reserve(BudgetKind::QueueItems, 2).unwrap();
    assert_eq!(
        tracker.try_reserve(BudgetKind::QueueItems, 1).unwrap_err(),
        OverflowEvent {
            kind: BudgetKind::QueueItems,
            limit: 2,
            attempted: 3
        }
    );
}
