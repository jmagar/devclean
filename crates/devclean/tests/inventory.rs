use devclean::docker_api::DockerUnixBackend;
use devclean::inventory::*;
use devclean_core::{ActivityIndex, CoverageStatus, PermitKind, ProtectionSignal, WorkPool};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Mutex, atomic::AtomicBool};
use std::time::Duration;

fn limits(max_objects: usize, max_bytes: u64) -> InventoryLimits {
    InventoryLimits {
        max_objects,
        max_response_bytes: max_bytes,
        max_pages: 10,
        total_timeout: Duration::from_secs(1),
    }
}
fn pool() -> WorkPool {
    WorkPool::new(
        2,
        BTreeMap::from([(PermitKind::Subprocess, 1), (PermitKind::Docker, 1)]),
    )
}
fn git_key() -> GitCommonKey {
    GitCommonKey {
        common_dir: "/repo/.git".into(),
        device: 1,
        inode: 2,
    }
}
fn git_state() -> GitWorktreeState {
    GitWorktreeState {
        id: "wt".into(),
        path: Some("/repo/wt".into()),
        registered: true,
        detached: false,
        dirty: false,
        untracked: false,
        active: false,
        ahead: 0,
        reachable_from_retained_ref: true,
        has_remote_evidence: true,
        stale: false,
        accessible: true,
        coverage: CoverageStatus::Complete,
        snapshot_fingerprint: "snapshot".into(),
    }
}

struct GitFake {
    calls: usize,
    value: GitInventory,
}
impl GitBackend for GitFake {
    fn inventory(&mut self, _: &GitCommonKey, _: InventoryLimits) -> GitInventory {
        self.calls += 1;
        self.value.clone()
    }
}
type GitMutation = fn(&mut GitWorktreeState);

#[test]
fn git_truth_table_is_conservative_and_graph_is_coalesced() {
    let clean = git_state();
    assert!(clean.protections().is_empty());
    let cases: Vec<(GitMutation, ProtectionSignal)> = vec![
        (|v| v.dirty = true, ProtectionSignal::Dirty),
        (|v| v.untracked = true, ProtectionSignal::Untracked),
        (|v| v.active = true, ProtectionSignal::Active),
        (|v| v.ahead = 1, ProtectionSignal::Unpublished),
        (
            |v| v.has_remote_evidence = false,
            ProtectionSignal::Unpublished,
        ),
        (
            |v| v.reachable_from_retained_ref = false,
            ProtectionSignal::UnreachableCommit,
        ),
        (|v| v.path = None, ProtectionSignal::Inaccessible),
        (|v| v.accessible = false, ProtectionSignal::Inaccessible),
        (|v| v.registered = false, ProtectionSignal::UnknownOwnership),
    ];
    for (mutate, expected) in cases {
        let mut value = clean.clone();
        mutate(&mut value);
        assert!(value.protections().contains(&expected));
    }
    let mut backend = GitFake {
        calls: 0,
        value: GitInventory {
            coverage: CoverageStatus::Complete,
            worktrees: vec![clean],
            graph_walks: 1,
            snapshot_fingerprint: Some("snapshot".into()),
        },
    };
    let mut cache = GitInventoryCache::default();
    let cancel = AtomicBool::new(false);
    let pool = pool();
    let a = cache.get_or_collect(git_key(), &mut backend, limits(10, 1000), &pool, &cancel);
    let b = cache.get_or_collect(git_key(), &mut backend, limits(10, 1000), &pool, &cancel);
    assert_eq!(backend.calls, 1);
    assert_eq!(a.graph_walks, 1);
    assert_eq!(b.graph_walks, 1);
}

#[test]
fn production_git_plan_uses_only_bounded_read_only_machine_commands() {
    let backend = GitCommandBackend {
        runner: &devclean::command::CommandRunner,
        activity: &ActivityIndex::default(),
        approved_roots: &[],
        cancellation: &AtomicBool::new(false),
        timeout: Duration::from_secs(2),
        output_limit: 4096,
    };
    let specs = backend.read_only_specs(&git_key());
    assert!(specs.iter().all(|spec| spec.executable == "/usr/bin/git"));
    assert!(
        specs
            .iter()
            .all(|spec| spec.timeout == Duration::from_secs(2))
    );
    assert!(specs.iter().all(|spec| spec.output_limit == 4096));
    let joined: Vec<_> = specs
        .iter()
        .flat_map(|spec| spec.args.iter().map(String::as_str))
        .collect();
    assert!(joined.contains(&"worktree"));
    assert!(joined.contains(&"list"));
    assert!(joined.contains(&"rev-list"));
    assert!(joined.contains(&"--remotes"));
    for forbidden in [
        "remove",
        "prune",
        "delete",
        "reset",
        "clean",
        "gc",
        "update-ref",
    ] {
        assert!(!joined.contains(&forbidden));
    }
}

struct CommandSpy {
    specs: Mutex<Vec<devclean::command::CommandSpec>>,
    worktrees: Vec<u8>,
}

impl MachineCommandRunner for CommandSpy {
    fn run_machine(
        &self,
        spec: &devclean::command::CommandSpec,
    ) -> Result<devclean::command::CommandOutcome, devclean::command::CommandError> {
        self.specs.lock().unwrap().push(spec.clone());
        let stdout = if spec.args.iter().any(|arg| arg == "worktree") {
            self.worktrees.clone()
        } else {
            Vec::new()
        };
        Ok(devclean::command::CommandOutcome {
            status: devclean::command::CommandStatus::Success,
            stdout,
            stderr_was_present: false,
        })
    }
}

#[test]
fn escaped_worktree_is_rejected_before_filesystem_access_or_git_c() {
    let temp = tempfile::tempdir().unwrap();
    let root = camino::Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("approved");
    let common = root.join(".git");
    std::fs::create_dir_all(&common).unwrap();
    let metadata = std::fs::symlink_metadata(&common).unwrap();
    let key = GitCommonKey {
        common_dir: common,
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
    };
    let approved = [devclean_core::ApprovedRootIdentity::inspect(&root).unwrap()];
    let escaped = root.parent().unwrap().join("escaped-worktree");
    let spy = CommandSpy {
        specs: Mutex::new(Vec::new()),
        worktrees: format!("worktree {}\0HEAD abc\0", escaped).into_bytes(),
    };
    let mut backend = GitCommandBackend {
        runner: &spy,
        activity: &ActivityIndex::default(),
        approved_roots: &approved,
        cancellation: &AtomicBool::new(false),
        timeout: Duration::from_secs(1),
        output_limit: 4096,
    };
    let result = backend.inventory(&key, limits(10, 4096));
    assert_eq!(result.coverage, CoverageStatus::Partial);
    assert!(result.worktrees.is_empty());
    let specs = spy.specs.lock().unwrap();
    assert!(
        specs
            .iter()
            .all(|spec| !spec.args.iter().any(|arg| arg == "-C"))
    );
    assert!(specs.iter().all(|spec| spec.cwd != escaped));
}

#[test]
fn symlinked_component_worktree_is_rejected_before_git_c() {
    let temp = tempfile::tempdir().unwrap();
    let base =
        camino::Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
    let root = base.join("approved");
    let common = root.join(".git");
    let outside = base.join("outside");
    std::fs::create_dir_all(&common).unwrap();
    std::fs::create_dir_all(outside.join("worktree")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let metadata = std::fs::symlink_metadata(&common).unwrap();
    let key = GitCommonKey {
        common_dir: common,
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
    };
    let approved = [devclean_core::ApprovedRootIdentity::inspect(&root).unwrap()];
    let returned = root.join("link/worktree");
    let spy = CommandSpy {
        specs: Mutex::new(Vec::new()),
        worktrees: format!("worktree {}\0HEAD abc\0", returned).into_bytes(),
    };
    let mut backend = GitCommandBackend {
        runner: &spy,
        activity: &ActivityIndex::default(),
        approved_roots: &approved,
        cancellation: &AtomicBool::new(false),
        timeout: Duration::from_secs(1),
        output_limit: 4096,
    };
    let result = backend.inventory(&key, limits(10, 4096));
    assert_eq!(result.coverage, CoverageStatus::Partial);
    assert!(result.worktrees.is_empty());
    assert!(
        spy.specs
            .lock()
            .unwrap()
            .iter()
            .all(|spec| !spec.args.iter().any(|arg| arg == "-C"))
    );
}

#[test]
fn replaced_common_directory_runs_no_commands() {
    let temp = tempfile::tempdir().unwrap();
    let root = camino::Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("approved");
    let common = root.join(".git");
    std::fs::create_dir_all(&common).unwrap();
    let approved = [devclean_core::ApprovedRootIdentity::inspect(&root).unwrap()];
    let metadata = std::fs::symlink_metadata(&common).unwrap();
    let key = GitCommonKey {
        common_dir: common.clone(),
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
    };
    std::fs::rename(&common, root.join(".git-old")).unwrap();
    std::fs::create_dir(&common).unwrap();
    let spy = CommandSpy {
        specs: Mutex::new(Vec::new()),
        worktrees: Vec::new(),
    };
    let mut backend = GitCommandBackend {
        runner: &spy,
        activity: &ActivityIndex::default(),
        approved_roots: &approved,
        cancellation: &AtomicBool::new(false),
        timeout: Duration::from_secs(1),
        output_limit: 4096,
    };
    let result = backend.inventory(&key, limits(10, 4096));
    assert_eq!(result.coverage, CoverageStatus::Partial);
    assert!(spy.specs.lock().unwrap().is_empty());
}

#[test]
#[ignore = "Task 10 many-worktree qualification"]
fn many_worktrees_are_bounded_and_pre_cancelled_collection_does_no_work() {
    let many = (0..10_000)
        .map(|index| {
            let mut value = git_state();
            value.id = format!("wt-{index}");
            value
        })
        .collect();
    let mut backend = GitFake {
        calls: 0,
        value: GitInventory {
            coverage: CoverageStatus::Complete,
            worktrees: many,
            graph_walks: 1,
            snapshot_fingerprint: Some("snapshot".into()),
        },
    };
    let pool = pool();
    let cancel = AtomicBool::new(false);
    let bounded = GitInventoryCache::default().get_or_collect(
        git_key(),
        &mut backend,
        limits(128, 1024 * 1024),
        &pool,
        &cancel,
    );
    assert_eq!(bounded.worktrees.len(), 128);
    assert_eq!(bounded.coverage, CoverageStatus::Truncated);

    let mut cancelled_backend = GitFake {
        calls: 0,
        value: bounded,
    };
    let cancelled = AtomicBool::new(true);
    let result = GitInventoryCache::default().get_or_collect(
        git_key(),
        &mut cancelled_backend,
        limits(128, 1024 * 1024),
        &pool,
        &cancelled,
    );
    assert_eq!(cancelled_backend.calls, 0);
    assert_eq!(result.coverage, CoverageStatus::Failed);
}

struct DockerFake {
    actual_identity: Option<String>,
    epochs: Vec<String>,
    epoch_calls: usize,
    page_calls: usize,
    fail: bool,
    repeat_cursor: bool,
}
impl DockerBackend for DockerFake {
    fn identity(&mut self, key: &DockerDaemonKey) -> Result<String, String> {
        Ok(self
            .actual_identity
            .clone()
            .unwrap_or_else(|| key.engine_id.clone()))
    }
    fn epoch(&mut self, _: &DockerDaemonKey) -> Result<String, String> {
        let value = self
            .epochs
            .get(self.epoch_calls)
            .cloned()
            .unwrap_or_else(|| self.epochs.last().unwrap().clone());
        self.epoch_calls += 1;
        Ok(value)
    }
    fn page(&mut self, _: &DockerDaemonKey, cursor: Option<&str>) -> Result<DockerPage, String> {
        self.page_calls += 1;
        if self.fail {
            return Err("denied".into());
        }
        let (kind, next) = if cursor.is_none() {
            (DockerObjectKind::Image, Some("2".into()))
        } else {
            (
                DockerObjectKind::Volume,
                self.repeat_cursor.then(|| "2".into()),
            )
        };
        Ok(DockerPage {
            objects: vec![DockerObject {
                id: format!("id-{}", self.page_calls),
                kind,
                size: 10,
                references: if cursor.is_none() {
                    vec!["container".into()]
                } else {
                    vec![]
                },
                compose_project: Some("label-only".into()),
                running: false,
                dangling: cursor.is_none(),
                active_build: false,
                recently_used: false,
                shared_group: cursor.is_none().then(|| "layer-set".into()),
                coverage: CoverageStatus::Complete,
                snapshot_fingerprint: String::new(),
            }],
            next,
            response_bytes: 20,
        })
    }
}
fn docker_key(engine: &str) -> DockerDaemonKey {
    DockerDaemonKey {
        transport: "unix:///socket".into(),
        context: "desktop".into(),
        engine_id: engine.into(),
    }
}
fn fake(epochs: &[&str]) -> DockerFake {
    DockerFake {
        actual_identity: None,
        epochs: epochs.iter().map(|v| (*v).into()).collect(),
        epoch_calls: 0,
        page_calls: 0,
        fail: false,
        repeat_cursor: false,
    }
}

#[test]
#[ignore = "Task 10 Docker pagination and object-limit qualification"]
fn docker_pagination_identity_mutation_limits_and_volume_protection() {
    let pool = pool();
    let cancel = AtomicBool::new(false);
    let mut cache = DockerInventoryCache::default();
    let key1 = docker_key("engine-1");
    let mut stable = fake(&["epoch-1"]);
    let result = cache.get_or_collect(
        key1.clone(),
        &mut stable,
        &key1,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(result.coverage, CoverageStatus::Complete);
    assert_eq!(result.objects.len(), 2);
    assert_eq!(stable.page_calls, 2);
    assert_eq!(stable.epoch_calls, 2);
    let volume = result
        .objects
        .iter()
        .find(|o| o.kind == DockerObjectKind::Volume)
        .unwrap();
    assert_eq!(volume.protections(), vec![ProtectionSignal::DockerVolume]);
    assert!(!volume.ownership_proven());
    let _ = cache.get_or_collect(
        key1.clone(),
        &mut stable,
        &key1,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(stable.page_calls, 2);
    let key2 = docker_key("engine-2");
    let mut changed = fake(&["before", "after"]);
    let changed = cache.get_or_collect(
        key2.clone(),
        &mut changed,
        &key2,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(changed.coverage, CoverageStatus::Partial);
    assert!(
        changed
            .objects
            .iter()
            .all(|o| o.coverage == CoverageStatus::Partial)
    );
    let key3 = docker_key("engine-3");
    let mut bounded = fake(&["same"]);
    let bounded = DockerInventoryCache::default().get_or_collect(
        key3.clone(),
        &mut bounded,
        &key3,
        limits(1, 20),
        &pool,
        &cancel,
    );
    assert_eq!(bounded.coverage, CoverageStatus::Truncated);
    assert_eq!(bounded.objects.len(), 1);
}

#[test]
fn repeating_pagination_failure_and_unapproved_identity_are_bounded_and_memoized() {
    let pool = pool();
    let cancel = AtomicBool::new(false);
    let key = docker_key("engine");
    let mut repeating = fake(&["same"]);
    repeating.repeat_cursor = true;
    let result = DockerInventoryCache::default().get_or_collect(
        key.clone(),
        &mut repeating,
        &key,
        InventoryLimits {
            max_pages: 3,
            ..limits(100, 1000)
        },
        &pool,
        &cancel,
    );
    assert_eq!(result.coverage, CoverageStatus::Truncated);
    assert!(repeating.page_calls <= 3);
    let mut failed = fake(&["same"]);
    failed.fail = true;
    let mut cache = DockerInventoryCache::default();
    let a = cache.get_or_collect(
        key.clone(),
        &mut failed,
        &key,
        limits(10, 100),
        &pool,
        &cancel,
    );
    let b = cache.get_or_collect(
        key.clone(),
        &mut failed,
        &key,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(a.coverage, CoverageStatus::Failed);
    assert_eq!(b.coverage, CoverageStatus::Failed);
    assert_eq!(failed.page_calls, 1);
    let denied = cache.get_or_collect(
        docker_key("other"),
        &mut failed,
        &key,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(denied.coverage, CoverageStatus::Failed);
    assert_eq!(denied.calls, 0);
    let mut replaced = fake(&["same"]);
    replaced.actual_identity = Some("different-engine".into());
    let rejected = DockerInventoryCache::default().get_or_collect(
        key.clone(),
        &mut replaced,
        &key,
        limits(10, 100),
        &pool,
        &cancel,
    );
    assert_eq!(rejected.coverage, CoverageStatus::Failed);
    assert_eq!(rejected.calls, 1);
    assert_eq!(replaced.page_calls, 0);
}

#[test]
fn production_docker_backend_is_get_only_bounded_and_parses_every_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("docker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let df = br#"{"Containers":[{"Id":"c","Image":"i","State":"running","SizeRw":2,"Labels":{"com.docker.compose.project":"p"}}],"Images":[{"Id":"i","RepoTags":[],"Size":10,"SharedSize":3}],"Volumes":[{"Name":"v","Labels":{"com.docker.compose.project":"p"},"UsageData":{"Size":20,"RefCount":0}}],"BuildCache":[{"ID":"b","Size":4,"InUse":true,"Shared":true,"LastUsedAt":1}]}"#.to_vec();
    let networks =
        br#"[{"Id":"n","Containers":{"c":{}},"Labels":{"com.docker.compose.project":"p"}}]"#
            .to_vec();
    let responses = vec![
        br#"{"ID":"engine"}"#.to_vec(),
        df.clone(),
        df.clone(),
        networks,
        df,
    ];
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).unwrap();
            requests.push(
                String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned(),
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    });
    let key = DockerDaemonKey {
        transport: format!("unix://{}", socket.display()),
        context: "test".into(),
        engine_id: "engine".into(),
    };
    // Keep the fixture bounded without making optimized test runs depend on a
    // one-second scheduler window on loaded CI hosts.
    let mut backend =
        DockerUnixBackend::new(Duration::from_secs(2), Duration::from_secs(5), 64 * 1024);
    let result = DockerInventoryCache::default().get_or_collect(
        key.clone(),
        &mut backend,
        &key,
        limits(20, 64 * 1024),
        &pool(),
        &AtomicBool::new(false),
    );
    assert_eq!(result.coverage, CoverageStatus::Complete);
    for kind in [
        DockerObjectKind::Container,
        DockerObjectKind::Image,
        DockerObjectKind::Layer,
        DockerObjectKind::BuildCache,
        DockerObjectKind::Network,
        DockerObjectKind::Volume,
    ] {
        assert!(result.objects.iter().any(|object| object.kind == kind));
    }
    assert!(
        result
            .objects
            .iter()
            .find(|object| object.kind == DockerObjectKind::Container)
            .unwrap()
            .protections()
            .contains(&ProtectionSignal::Active)
    );
    let image = result
        .objects
        .iter()
        .find(|object| object.kind == DockerObjectKind::Image)
        .unwrap();
    assert_eq!(image.references, vec!["c"]);
    assert!(image.dangling);
    assert_eq!(
        result
            .objects
            .iter()
            .find(|object| object.kind == DockerObjectKind::Container)
            .unwrap()
            .compose_project
            .as_deref(),
        Some("p")
    );
    assert!(
        result
            .objects
            .iter()
            .find(|object| object.kind == DockerObjectKind::BuildCache)
            .unwrap()
            .recently_used
    );
    assert!(
        result
            .objects
            .iter()
            .find(|object| object.kind == DockerObjectKind::BuildCache)
            .unwrap()
            .protections()
            .contains(&ProtectionSignal::Active)
    );
    assert!(
        !result
            .objects
            .iter()
            .find(|object| object.kind == DockerObjectKind::Volume)
            .unwrap()
            .ownership_proven()
    );
    assert!(
        server
            .join()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET "))
    );
}
