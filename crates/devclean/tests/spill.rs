use devclean::private_store::PrivateStore;
use devclean::spill::FileInodeSpill;
use devclean_core::InodeSpill;
use std::os::unix::fs::PermissionsExt;

#[test]
fn file_spill_persists_partition_membership_and_enforces_size_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(tmp.path()).unwrap();
    let root = camino::Utf8Path::from_path(&canonical)
        .unwrap()
        .join("private");
    let store = PrivateStore::create(&root).unwrap();
    let mut spill = FileInodeSpill::new(store.clone(), 32);
    spill
        .spill(7, &[("1:2".into(), 10), ("1:3".into(), 20)])
        .unwrap();
    assert!(spill.contains(7, "1:2").unwrap());
    assert!(!spill.contains(7, "1:4").unwrap());

    let mut reopened = FileInodeSpill::new(store, 32);
    assert!(reopened.contains(7, "1:3").unwrap());
    assert!(reopened.spill(7, &[("x".repeat(40), 1)]).is_err());

    let partition = root.join("inode-0007.idx");
    std::fs::set_permissions(&partition, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(reopened.spill(7, &[("1:4".into(), 1)]).is_err());
    std::fs::set_permissions(&partition, std::fs::Permissions::from_mode(0o600)).unwrap();
}
