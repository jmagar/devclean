use camino::Utf8Path;
use devclean::{config::Config, private_store::PrivateStore};
use devclean_core::{ApprovedRootIdentity, ScopeDecision, ScopePolicy};
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};

#[test]
fn scope_includes_children_rejects_siblings_and_mount_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    let identity = ApprovedRootIdentity::inspect(root).unwrap();
    let policy = ScopePolicy::new(vec![identity.clone()], vec![], false);
    assert_eq!(
        policy.authorize(&identity.path.join("child"), identity.device),
        ScopeDecision::Include
    );
    assert_eq!(
        policy.authorize(&identity.path.join("child/../sibling"), identity.device),
        ScopeDecision::Exclude
    );
    assert_eq!(
        policy.authorize(Utf8Path::new("/tmp/not-approved"), identity.device),
        ScopeDecision::Exclude
    );
    assert_eq!(
        policy.authorize(&identity.path, identity.device + 1),
        ScopeDecision::Boundary
    );
}

#[test]
fn approved_root_may_not_be_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("link");
    symlink(tmp.path(), &link).unwrap();
    assert!(ApprovedRootIdentity::inspect(Utf8Path::from_path(&link).unwrap()).is_err());
}

#[test]
fn overlapping_roots_are_deduplicated_and_descendant_symlinks_are_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fs::create_dir(root.join("real")).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();
    let identity = ApprovedRootIdentity::inspect(root).unwrap();
    let child_identity = ApprovedRootIdentity::inspect(&root.join("real")).unwrap();
    let policy = ScopePolicy::new(vec![child_identity, identity.clone()], vec![], false);
    assert_eq!(policy.roots().len(), 1);
    assert_eq!(
        policy.authorize(&identity.path.join("link/file"), identity.device),
        ScopeDecision::Boundary
    );
}

#[test]
fn changed_root_identity_invalidates_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap().join("root");
    fs::create_dir(&root).unwrap();
    let identity = ApprovedRootIdentity::inspect(&root).unwrap();
    fs::rename(&root, root.with_extension("old")).unwrap();
    fs::create_dir(&root).unwrap();
    let policy = ScopePolicy::new(vec![identity.clone()], vec![], false);
    assert_eq!(
        policy.authorize(&identity.path, identity.device),
        ScopeDecision::Boundary
    );
}

#[test]
fn changed_ancestor_identity_invalidates_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    let mut identity = ApprovedRootIdentity::inspect(root).unwrap();
    identity.ancestors[1].inode = identity.ancestors[1].inode.saturating_add(1);
    let device = identity.device;
    let path = identity.path.clone();
    assert_eq!(
        ScopePolicy::new(vec![identity], vec![], false).authorize(&path, device),
        ScopeDecision::Boundary
    );
}

#[test]
fn config_fingerprints_separate_safety_from_presentation() {
    let a = Config::parse("approved_roots=['/tmp/dev']\n[presentation]\nterminal_rows=10").unwrap();
    let b = Config::parse("approved_roots=['/tmp/dev']\n[presentation]\nterminal_rows=20").unwrap();
    assert_eq!(a.safety_fingerprint(), b.safety_fingerprint());
    assert_ne!(a.presentation_fingerprint(), b.presentation_fingerprint());
    assert!(Config::parse("approved_roots=[]\nunknown=true").is_err());
}

#[test]
fn imported_roots_and_docker_credentials_require_approval() {
    let raw = "approved_roots=['/tmp/dev']\n[docker]\ncontext='x'\nendpoint='unix://user:secret@socket'\nengine_id='e'";
    assert!(Config::import_proposed(raw, false).is_err());
    assert!(
        Config::import_proposed(raw, true)
            .unwrap()
            .approved_docker()
            .is_err()
    );
}

#[test]
fn docker_identity_requires_nonempty_fields_and_accepts_credential_free_endpoint() {
    let good = Config::parse("approved_roots=[]\n[docker]\ncontext='desktop'\nendpoint='unix:///tmp/docker.sock'\nengine_id='engine' ").unwrap();
    assert_eq!(good.approved_docker().unwrap().unwrap().engine_id, "engine");
    let empty = Config::parse("approved_roots=[]\n[docker]\ncontext=''\nendpoint='unix:///tmp/docker.sock'\nengine_id='engine'").unwrap();
    assert!(empty.approved_docker().is_err());
}

#[test]
fn private_store_is_0700_and_files_are_exclusive_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(tmp.path()).unwrap();
    let root = Utf8Path::from_path(&canonical).unwrap().join("store");
    let store = PrivateStore::create(&root).unwrap();
    let file = store.create_new("config.toml", b"safe").unwrap();
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
    assert!(store.create_new("config.toml", b"replace").is_err());
}

#[test]
fn private_store_rejects_intermediate_symlink_and_insecure_parent() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(tmp.path()).unwrap();
    let base = Utf8Path::from_path(&canonical).unwrap();
    fs::create_dir(base.join("real")).unwrap();
    symlink(base.join("real"), base.join("link")).unwrap();
    assert!(PrivateStore::create(&base.join("link/store")).is_err());
    let insecure = base.join("insecure");
    fs::create_dir(&insecure).unwrap();
    let mut permissions = fs::metadata(&insecure).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o777);
    fs::set_permissions(&insecure, permissions).unwrap();
    assert!(PrivateStore::create(&insecure.join("store")).is_err());
}

#[test]
fn private_store_rejects_controls_hardlinks_and_special_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(tmp.path()).unwrap();
    let root = Utf8Path::from_path(&canonical).unwrap().join("store");
    let store = PrivateStore::create(&root).unwrap();
    assert!(store.create_new("bad\nname", b"x").is_err());
    let original = root.join("original");
    fs::write(&original, b"x").unwrap();
    fs::hard_link(&original, root.join("linked")).unwrap();
    assert!(store.create_new("linked", b"x").is_err());
    fs::create_dir(root.join("directory-target")).unwrap();
    assert!(store.create_new("directory-target", b"x").is_err());
}

#[test]
fn duplicate_config_keys_are_rejected() {
    assert!(Config::parse("approved_roots=[]\napproved_roots=[]").is_err());
}

#[test]
fn authorized_traversal_scope_combines_dedupes_and_bounds_exclusions() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(tmp.path()).unwrap();
    let base = camino::Utf8PathBuf::from_path_buf(canonical).unwrap();
    let root = base.join("root");
    let nested_cache = root.join("cache");
    let outside_cache = base.join("outside-cache");
    let excluded = root.join("excluded");
    fs::create_dir_all(&nested_cache).unwrap();
    fs::create_dir_all(&outside_cache).unwrap();
    fs::create_dir_all(excluded.join("nested")).unwrap();
    let config = Config::parse(&format!(
        "approved_roots=['{root}']\napproved_caches=['{nested_cache}','{outside_cache}']\nexclusions=['{excluded}','{}/nested']",
        excluded
    ))
    .unwrap();
    let scope = config.authorized_traversal_scope().unwrap();
    let mut expected_roots = vec![root.clone(), outside_cache.clone()];
    expected_roots.sort();
    assert_eq!(scope.roots, expected_roots);
    assert_eq!(scope.exclusions, vec![excluded.clone()]);
    assert!(scope.caches.contains(&nested_cache));
    assert!(scope.caches.contains(&outside_cache));

    let outside = base.join("not-approved");
    fs::create_dir(&outside).unwrap();
    let invalid = Config::parse(&format!(
        "approved_roots=['{root}']\nexclusions=['{outside}']"
    ))
    .unwrap();
    assert!(invalid.authorized_traversal_scope().is_err());

    let alias = root.join("alias");
    symlink(&excluded, &alias).unwrap();
    let aliased = Config::parse(&format!(
        "approved_roots=['{root}']\nexclusions=['{alias}']"
    ))
    .unwrap();
    assert!(aliased.authorized_traversal_scope().is_err());
}
