use devclean_core::*;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

#[derive(Default)]
struct Spill(BTreeSet<String>);
impl InodeSpill for Spill {
    fn contains(&mut self, _: u16, key: &str) -> std::io::Result<bool> {
        Ok(self.0.contains(key))
    }
    fn spill(&mut self, _: u16, entries: &[(String, u64)]) -> std::io::Result<()> {
        self.0.extend(entries.iter().map(|(key, _)| key.clone()));
        Ok(())
    }
}

fn id(name: &str) -> LogicalCandidateId {
    LogicalCandidateId::derive("test", "owner", name)
}

#[test]
fn physical_bytes_are_unique_and_cross_candidate_links_are_non_additive() {
    let a = id("a");
    let b = id("b");
    let accounting = PhysicalAccounting::from_extents(
        [
            PhysicalExtent {
                device: 1,
                inode: 1,
                allocated_bytes: 100,
                candidates: vec![a.clone()],
            },
            PhysicalExtent {
                device: 1,
                inode: 1,
                allocated_bytes: 100,
                candidates: vec![a.clone()],
            },
            PhysicalExtent {
                device: 1,
                inode: 2,
                allocated_bytes: 50,
                candidates: vec![a.clone(), b.clone()],
            },
        ],
        10,
        &mut Spill::default(),
    )
    .unwrap();
    assert_eq!(accounting.unique_bytes, 150);
    assert_eq!(accounting.additive_bytes[&a], 100);
    assert_eq!(accounting.shared_bytes[&a], 50);
    assert_eq!(accounting.shared_bytes[&b], 50);
}

#[test]
fn physical_accounting_candidate_retention_is_bounded() {
    let result = PhysicalAccounting::from_extents(
        [PhysicalExtent {
            device: 1,
            inode: 1,
            allocated_bytes: 1,
            candidates: vec![id("a"), id("b")],
        }],
        1,
        &mut Spill::default(),
    );
    assert!(matches!(result, Err(AccountingError::Overflow(_))));
}

#[test]
#[ignore = "Task 10 hundred-thousand relationship qualification"]
fn relationship_index_handles_hundred_thousand_siblings_and_deep_paths() {
    let mut paths = vec![camino::Utf8PathBuf::from("/root")];
    paths.extend((0..100_000).map(|n| format!("/root/sibling-{n:06}").into()));
    let mut deep = camino::Utf8PathBuf::from("/root/deep");
    for n in 0..100 {
        deep.push(n.to_string());
        paths.push(deep.clone());
    }
    let index = RelationshipIndex::build(paths);
    assert_eq!(index.parent.len(), 100_100);
    assert_eq!(
        index.parent[camino::Utf8Path::new("/root/sibling-000042")],
        camino::Utf8PathBuf::from("/root")
    );
}

#[test]
#[ignore = "Task 10 high-cardinality hard-link qualification"]
fn high_cardinality_shared_inode_accounting_remains_non_additive() {
    let owners: Vec<_> = (0..100_000).map(|n| id(&format!("owner-{n}"))).collect();
    let accounting = PhysicalAccounting::from_extents(
        [PhysicalExtent {
            device: 1,
            inode: 42,
            allocated_bytes: 4096,
            candidates: owners,
        }],
        100_000,
        &mut Spill::default(),
    )
    .unwrap();
    assert_eq!(accounting.unique_bytes, 4096);
    assert_eq!(accounting.additive_bytes.len(), 0);
    assert_eq!(accounting.shared_bytes.len(), 100_000);
}

#[test]
fn accounting_and_relationship_builds_honor_cancellation() {
    let cancelled = AtomicBool::new(true);
    let mut spill = Spill::default();
    assert!(matches!(
        PhysicalAccounting::from_extents_cancellable(
            std::iter::empty(),
            10,
            &mut spill,
            &cancelled
        ),
        Err(AccountingError::Cancelled)
    ));
    assert!(
        RelationshipIndex::build_cancellable([camino::Utf8PathBuf::from("/a")], &cancelled)
            .is_none()
    );
}
