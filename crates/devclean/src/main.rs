use camino::Utf8PathBuf;
use devclean::activity::{ActivityCollector, ActivityStatus};
use devclean::command::{CommandRunner, CommandSpec};
use devclean::config::Config;
use devclean::docker_api::DockerUnixBackend;
use devclean::engine::{ExitCode, ScanEngine, StreamingScanRequest};
use devclean::inventory::{
    DockerDaemonKey, DockerInventoryCache, DockerObjectKind, GitCommandBackend, GitCommonKey,
    GitInventory, GitInventoryCache, InventoryLimits,
};
use devclean::metadata::{MetadataFormat, MetadataReader, MetadataRequest, MetadataStatus};
use devclean::private_store::PrivateStore;
use devclean::report::{ReportStore, render_explanation, render_summary, write_redacted};
use devclean::scan::{TraversalCoverage, TraversalOptions, stream_observations};
use devclean_core::{
    ActivityIndex, CoverageStatus, DiagnosticAggregator, Observation, PermitKind,
    ResourceFingerprint, ResourceIdentity, ScopePolicy, WorkPool,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

fn main() {
    std::process::exit(run(std::env::args().skip(1).collect()));
}
fn run(args: Vec<String>) -> i32 {
    match parse_command(&args).and_then(execute) {
        Ok(v) => v as i32,
        Err((v, message)) => {
            eprintln!("{}", devclean::report::safe_terminal(&message));
            v as i32
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    Init {
        store: String,
    },
    Scan {
        config: String,
        store: String,
        scan_id: String,
    },
    Report {
        store: String,
        scan_id: String,
    },
    ExportRedacted {
        store: String,
        scan_id: String,
    },
    Explain {
        store: String,
        scan_id: String,
        candidate: devclean_core::LogicalCandidateId,
    },
}

const USAGE: &str = "usage: devclean init STORE | scan CONFIG STORE SCAN_ID | report STORE SCAN_ID | report export --redacted STORE SCAN_ID | explain STORE SCAN_ID CANDIDATE_ID";

fn parse_command(args: &[String]) -> Result<CliCommand, (ExitCode, String)> {
    let invalid = || (ExitCode::ConfigInvalid, USAGE.into());
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init", store] => Ok(CliCommand::Init {
            store: (*store).into(),
        }),
        ["scan", config, store, scan_id] => Ok(CliCommand::Scan {
            config: (*config).into(),
            store: (*store).into(),
            scan_id: (*scan_id).into(),
        }),
        ["report", store, scan_id] => Ok(CliCommand::Report {
            store: (*store).into(),
            scan_id: (*scan_id).into(),
        }),
        ["report", "export", "--redacted", store, scan_id] => Ok(CliCommand::ExportRedacted {
            store: (*store).into(),
            scan_id: (*scan_id).into(),
        }),
        ["explain", store, scan_id, candidate] => Ok(CliCommand::Explain {
            store: (*store).into(),
            scan_id: (*scan_id).into(),
            candidate: devclean_core::LogicalCandidateId(
                uuid::Uuid::parse_str(candidate)
                    .map_err(|_| (ExitCode::ConfigInvalid, "invalid candidate id".into()))?,
            ),
        }),
        _ => Err(invalid()),
    }
}

fn execute(command: CliCommand) -> Result<ExitCode, (ExitCode, String)> {
    // Standalone reports have no config, so keep their terminal output to a
    // conservative fixed number of candidate rows.
    const REPORT_TERMINAL_ROWS: usize = 20;
    match command {
        CliCommand::Init { store } => handle_init(&store),
        CliCommand::Scan {
            config,
            store,
            scan_id,
        } => scan(&config, &store, &scan_id),
        CliCommand::Report { store, scan_id } => {
            handle_report(&store, &scan_id, REPORT_TERMINAL_ROWS)
        }
        CliCommand::ExportRedacted { store, scan_id } => handle_export(&store, &scan_id),
        CliCommand::Explain {
            store,
            scan_id,
            candidate,
        } => handle_explain(&store, &scan_id, &candidate),
    }
}

fn handle_init(path: &str) -> Result<ExitCode, (ExitCode, String)> {
    let store = PrivateStore::create(camino::Utf8Path::new(path)).map_err(internal)?;
    store
        .create_new(
            "config.toml",
            b"approved_roots=[]\napproved_caches=[]\nexclusions=[]\n",
        )
        .map_err(internal)?;
    Ok(ExitCode::Complete)
}

fn handle_report(store: &str, scan_id: &str, rows: usize) -> Result<ExitCode, (ExitCode, String)> {
    let value = reports(store)?.read(scan_id).map_err(internal)?;
    print!(
        "{}",
        render_summary(&value, rows, std::io::stdout().is_terminal())
    );
    Ok(if value.coverage == CoverageStatus::Complete {
        ExitCode::Complete
    } else {
        ExitCode::Incomplete
    })
}

fn handle_export(store: &str, scan_id: &str) -> Result<ExitCode, (ExitCode, String)> {
    let value = reports(store)?.read(scan_id).map_err(internal)?;
    write_redacted(&value, std::io::stdout()).map_err(internal)?;
    Ok(ExitCode::Complete)
}

fn handle_explain(
    store: &str,
    scan_id: &str,
    candidate: &devclean_core::LogicalCandidateId,
) -> Result<ExitCode, (ExitCode, String)> {
    let value = reports(store)?
        .stream_explain(scan_id, candidate)
        .map_err(internal)?
        .ok_or((ExitCode::ConfigInvalid, "candidate not found".into()))?;
    println!("{}", render_explanation(&value));
    Ok(ExitCode::Complete)
}
fn reports(path: &str) -> Result<ReportStore, (ExitCode, String)> {
    Ok(ReportStore::new(
        PrivateStore::create(&Utf8PathBuf::from(path)).map_err(internal)?,
        256 * 1024 * 1024,
    ))
}
fn scan(
    config_path: &str,
    store_path: &str,
    scan_id: &str,
) -> Result<ExitCode, (ExitCode, String)> {
    let bytes = read_config(config_path)?;
    let config = Config::parse(
        std::str::from_utf8(&bytes)
            .map_err(|_| (ExitCode::ConfigInvalid, "config is not UTF-8".into()))?,
    )
    .map_err(config_error)?;
    // Presentation configuration cannot turn stdout into an unbounded export.
    let terminal_rows = config.presentation.terminal_rows.min(100);
    let approved_docker = config.approved_docker().map_err(config_error)?;
    let authorized_scope = config.authorized_traversal_scope().map_err(config_error)?;
    let roots = authorized_scope.roots;
    let approved_caches = authorized_scope.caches;
    let exclusions = authorized_scope.exclusions;
    let git_approved_roots = authorized_scope.root_identities.clone();
    let cancellation = Arc::new(AtomicBool::new(false));
    let pool = Arc::new(WorkPool::new(
        4,
        BTreeMap::from([
            (PermitKind::Filesystem, 2),
            (PermitKind::Detector, 2),
            (PermitKind::Subprocess, 1),
            (PermitKind::Docker, 1),
        ]),
    ));
    let options = TraversalOptions {
        max_queue: 100_000,
        max_observations: 1_000_000,
        cross_mounts: false,
        exclusions: exclusions.clone(),
        scope: Some(ScopePolicy::new(
            authorized_scope.root_identities,
            exclusions,
            false,
        )),
        cancellation: Arc::clone(&cancellation),
        pool,
        before_metadata: None,
    };
    let metadata_reader = MetadataReader::development_defaults(1024 * 1024);
    let metadata_discovery = discover_project_metadata(&roots, &options, &metadata_reader);
    let mut activity_collector = ActivityCollector::new(
        100_000,
        Arc::clone(&options.pool),
        Arc::clone(&cancellation),
    );
    let lsof_args = vec!["-Fn".into()];
    let activity = activity_collector
        .snapshot_once(
            &CommandRunner,
            &CommandSpec {
                executable: "/usr/sbin/lsof".into(),
                args: lsof_args,
                cwd: roots.first().cloned().unwrap_or_else(|| "/".into()),
                timeout: Duration::from_secs(10),
                output_limit: 32 * 1024 * 1024,
            },
            &roots,
        )
        .ok();
    let probe_status = if activity
        .as_ref()
        .is_some_and(|value| value.status == ActivityStatus::Complete)
    {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Unsupported
    };
    let empty_activity = ActivityIndex::default();
    let activity_index = activity
        .as_ref()
        .map(|snapshot| &snapshot.index)
        .unwrap_or(&empty_activity);
    let limits = InventoryLimits {
        max_objects: 100_000,
        max_response_bytes: 128 * 1024 * 1024,
        max_pages: 32,
        total_timeout: Duration::from_secs(30),
    };
    let mut external = Vec::new();
    let mut external_coverage = CoverageStatus::Complete;
    let mut git_cache = GitInventoryCache::default();
    let mut git_backend = GitCommandBackend {
        runner: &CommandRunner,
        activity: activity_index,
        approved_roots: &git_approved_roots,
        cancellation: &cancellation,
        timeout: Duration::from_secs(10),
        output_limit: 32 * 1024 * 1024,
    };
    let mut emitted_git = BTreeSet::new();
    for root in &roots {
        let key = match git_key(root, &git_approved_roots) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(()) => {
                external_coverage.join_assign(&CoverageStatus::Partial);
                continue;
            }
        };
        if !emitted_git.insert(key.clone()) {
            continue;
        }
        let inventory = git_cache.get_or_collect(
            key.clone(),
            &mut git_backend,
            limits,
            &options.pool,
            &cancellation,
        );
        merge_coverage(&mut external_coverage, &inventory.coverage);
        external.extend(git_observations(&key, inventory, &probe_status, &roots));
    }
    if let Some(approved) = approved_docker {
        let key = DockerDaemonKey {
            transport: approved.endpoint,
            context: approved.context,
            engine_id: approved.engine_id,
        };
        let mut backend = DockerUnixBackend::new(
            Duration::from_secs(2),
            Duration::from_secs(10),
            64 * 1024 * 1024,
        );
        let inventory = DockerInventoryCache::default().get_or_collect(
            key.clone(),
            &mut backend,
            &key,
            limits,
            &options.pool,
            &cancellation,
        );
        let docker_snapshot_coverage = inventory.coverage.clone();
        merge_coverage(&mut external_coverage, &inventory.coverage);
        external.extend(inventory.objects.into_iter().map(|object| {
            let kind = docker_kind(&object.kind);
            let mut attributes = BTreeMap::from([
                (
                    "probe_docker_snapshot".into(),
                    coverage_name(&docker_snapshot_coverage).into(),
                ),
                (
                    "probe_docker_references".into(),
                    coverage_name(&object.coverage).into(),
                ),
                (
                    "probe_rebuildability".into(),
                    if matches!(
                        object.kind,
                        DockerObjectKind::Layer | DockerObjectKind::BuildCache
                    ) {
                        "complete".into()
                    } else {
                        "unknown".into()
                    },
                ),
            ]);
            if object.running || object.active_build {
                attributes.insert("active".into(), "true".into());
            }
            if !object.references.is_empty() {
                attributes.insert("open".into(), "true".into());
            }
            if object.kind == DockerObjectKind::Volume {
                attributes.insert("volume".into(), "true".into());
            }
            if object.shared_group.is_some() {
                attributes.insert("shared".into(), "true".into());
            }
            Observation {
                identity: ResourceIdentity::Docker {
                    daemon: key.engine_id.clone(),
                    object_kind: kind.into(),
                    id: object.id.clone(),
                },
                fingerprint: ResourceFingerprint::opaque(
                    "docker",
                    &format!("{}:{}", object.snapshot_fingerprint, object.id),
                ),
                logical_bytes: Some(object.size),
                allocated_bytes: Some(object.size),
                attributes,
            }
        }));
    }
    let safety = config.safety_fingerprint().0;
    let scope = blake3::hash(
        roots
            .iter()
            .flat_map(|p| p.as_str().as_bytes())
            .copied()
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .to_hex()
    .to_string();
    let reports = reports(store_path)?;
    let exit = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run_streaming(
        StreamingScanRequest {
            scan_id,
            safety_fingerprint: &safety,
            scope_fingerprint: &scope,
            probe_status: probe_status.clone(),
            cancellation: &cancellation,
            memory_items: 4096,
        },
        |emit| {
            for observation in external {
                emit(observation);
            }
            let mut diagnostics = DiagnosticAggregator::new(1000, 3);
            let traversal = stream_observations(&roots, &options, &mut diagnostics, |mut value| {
                if let devclean_core::ResourceIdentity::Filesystem { path } = &value.identity {
                    if path.file_name() == Some(".git") {
                        let discovered =
                            path.parent().map(|root| git_key(root, &git_approved_roots));
                        if matches!(discovered, Some(Err(()))) {
                            external_coverage.join_assign(&CoverageStatus::Partial);
                        }
                        if let Some(Ok(Some(key))) = discovered {
                            if !emitted_git.insert(key.clone()) {
                                emit(value);
                                return;
                            }
                            let inventory = git_cache.get_or_collect(
                                key.clone(),
                                &mut git_backend,
                                limits,
                                &options.pool,
                                &cancellation,
                            );
                            merge_coverage(&mut external_coverage, &inventory.coverage);
                            for observation in
                                git_observations(&key, inventory, &probe_status, &roots)
                            {
                                emit(observation);
                            }
                        }
                    }
                    if roots.iter().any(|root| path.starts_with(root)) {
                        value
                            .attributes
                            .insert("probe_approved_scope".into(), "complete".into());
                        value
                            .attributes
                            .insert("probe_activity".into(), coverage_name(&probe_status).into());
                        value.attributes.insert(
                            "probe_open_files".into(),
                            coverage_name(&probe_status).into(),
                        );
                        if let Some((owner, (markers, coverage))) =
                            path.ancestors().find_map(|owner| {
                                metadata_discovery
                                    .owners
                                    .get(owner)
                                    .map(|metadata| (owner, metadata))
                            })
                        {
                            value
                                .attributes
                                .insert("project_owner".into(), owner.to_string());
                            value.attributes.insert("markers".into(), markers.clone());
                            value
                                .attributes
                                .insert("metadata_coverage".into(), (*coverage).into());
                            value
                                .attributes
                                .insert("probe_metadata".into(), (*coverage).into());
                        }
                        if approved_caches.iter().any(|cache| path.starts_with(cache)) {
                            value.attributes.insert("known_cache".into(), "true".into());
                        }
                        if value.attributes.get("known_cache").map(String::as_str) == Some("true")
                            || (!value.attributes.get("markers").is_none_or(String::is_empty)
                                && value
                                    .attributes
                                    .get("metadata_coverage")
                                    .map(String::as_str)
                                    == Some("complete"))
                        {
                            value
                                .attributes
                                .insert("probe_rebuildability".into(), "complete".into());
                        }
                        if activity
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.index.matches_prefix(path))
                        {
                            value.attributes.insert("active".into(), "true".into());
                            value.attributes.insert("open".into(), "true".into());
                        }
                    }
                }
                emit(value);
            });
            producer_coverage(
                traversal.coverage,
                [
                    probe_status,
                    external_coverage,
                    metadata_discovery.coverage.clone(),
                ],
            )
        },
    )
    .map_err(internal)?;
    let report = reports.read(scan_id).map_err(internal)?;
    print!(
        "{}",
        render_summary(&report, terminal_rows, std::io::stdout().is_terminal())
    );
    Ok(exit)
}

fn producer_coverage(
    traversal: TraversalCoverage,
    sources: impl IntoIterator<Item = CoverageStatus>,
) -> CoverageStatus {
    let traversal = match traversal {
        TraversalCoverage::Complete => CoverageStatus::Complete,
        TraversalCoverage::Partial => CoverageStatus::Partial,
        TraversalCoverage::Cancelled => CoverageStatus::Failed,
    };
    sources.into_iter().fold(traversal, |mut total, status| {
        total.join_assign(&status);
        total
    })
}

fn read_config(path: &str) -> Result<Vec<u8>, (ExitCode, String)> {
    read_config_with_hook(path, || {})
}

fn read_config_with_hook(
    path: &str,
    after_read: impl FnOnce(),
) -> Result<Vec<u8>, (ExitCode, String)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(config_error)?;
    let before = file.metadata().map_err(config_error)?;
    if !before.is_file() {
        return Err((
            ExitCode::ConfigInvalid,
            "config is not a regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(config_error)?;
    if bytes.len() > 1024 * 1024 {
        return Err((ExitCode::ConfigInvalid, "config exceeds limit".into()));
    }
    after_read();
    let held = file.metadata().map_err(config_error)?;
    let current = std::fs::symlink_metadata(path).map_err(config_error)?;
    if !current.is_file()
        || current.file_type().is_symlink()
        || held.dev() != before.dev()
        || held.ino() != before.ino()
        || held.dev() != current.dev()
        || held.ino() != current.ino()
    {
        return Err((
            ExitCode::ConfigInvalid,
            "config identity changed while reading".into(),
        ));
    }
    Ok(bytes)
}

fn git_key(
    root: &camino::Utf8Path,
    approved_roots: &[devclean_core::ApprovedRootIdentity],
) -> Result<Option<GitCommonKey>, ()> {
    let dot_git = root.join(".git");
    let dot_git_metadata = match std::fs::symlink_metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if dot_git_metadata.file_type().is_symlink() {
        return Err(());
    }
    let common_dir = if dot_git_metadata.is_dir() {
        Utf8PathBuf::from_path_buf(std::fs::canonicalize(&dot_git).map_err(|_| ())?)
            .map_err(|_| ())?
    } else if dot_git_metadata.is_file() {
        let bytes = read_git_indirection(&dot_git)?;
        let value = std::str::from_utf8(&bytes).map_err(|_| ())?.trim();
        let git_dir = value.strip_prefix("gitdir: ").ok_or(())?;
        let git_dir = Utf8PathBuf::from(git_dir);
        let resolved = if git_dir.is_absolute() {
            git_dir
        } else {
            root.join(git_dir)
        };
        match resolved.parent().and_then(|parent| parent.parent()) {
            Some(parent) if resolved.parent().ok_or(())?.file_name() == Some("worktrees") => {
                parent.into()
            }
            _ => resolved,
        }
    } else {
        return Err(());
    };
    let common_dir = Utf8PathBuf::from_path_buf(std::fs::canonicalize(common_dir).map_err(|_| ())?)
        .map_err(|_| ())?;
    if !approved_roots
        .iter()
        .any(|approved| common_dir.starts_with(&approved.path) && approved.unchanged())
    {
        return Err(());
    }
    let metadata = std::fs::symlink_metadata(&common_dir).map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(());
    }
    Ok(Some(GitCommonKey {
        common_dir,
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn read_git_indirection(path: &camino::Utf8Path) -> Result<Vec<u8>, ()> {
    read_git_indirection_with_hook(path, || {})
}

fn read_git_indirection_with_hook(
    path: &camino::Utf8Path,
    after_read: impl FnOnce(),
) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let before = file.metadata().map_err(|_| ())?;
    if !before.is_file() {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 4096 {
        return Err(());
    }
    after_read();
    let held = file.metadata().map_err(|_| ())?;
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || held.dev() != before.dev()
        || held.ino() != before.ino()
        || held.dev() != path_metadata.dev()
        || held.ino() != path_metadata.ino()
    {
        return Err(());
    }
    Ok(bytes)
}

fn git_observations(
    key: &GitCommonKey,
    inventory: GitInventory,
    activity_coverage: &CoverageStatus,
    approved_roots: &[Utf8PathBuf],
) -> Vec<Observation> {
    let reachability_coverage = inventory.coverage.clone();
    inventory
        .worktrees
        .into_iter()
        .map(|worktree| {
            let approved_scope = worktree
                .path
                .as_ref()
                .is_some_and(|path| approved_roots.iter().any(|root| path.starts_with(root)));
            let filesystem_identity = worktree
                .path
                .as_ref()
                .is_some_and(|path| std::fs::symlink_metadata(path).is_ok());
            let mut attributes = BTreeMap::from([
                (
                    "probe_approved_scope".into(),
                    if approved_scope {
                        "complete"
                    } else {
                        "unknown"
                    }
                    .into(),
                ),
                (
                    "probe_filesystem_identity".into(),
                    if filesystem_identity {
                        "complete"
                    } else {
                        "unknown"
                    }
                    .into(),
                ),
                (
                    "probe_activity".into(),
                    coverage_name(activity_coverage).into(),
                ),
                (
                    "probe_open_files".into(),
                    coverage_name(activity_coverage).into(),
                ),
                (
                    "probe_git_status".into(),
                    coverage_name(&worktree.coverage).into(),
                ),
                ("probe_git_registration".into(), "complete".into()),
                (
                    "probe_git_reachability".into(),
                    coverage_name(&reachability_coverage).into(),
                ),
            ]);
            for protection in worktree.protections() {
                let attribute = match protection {
                    devclean_core::ProtectionSignal::Dirty => "dirty",
                    devclean_core::ProtectionSignal::Untracked => "untracked",
                    devclean_core::ProtectionSignal::Active => "active",
                    devclean_core::ProtectionSignal::Unpublished => "unpublished",
                    devclean_core::ProtectionSignal::UnreachableCommit => "unreachable",
                    devclean_core::ProtectionSignal::Inaccessible => "inaccessible",
                    _ => "shared",
                };
                attributes.insert(attribute.into(), "true".into());
            }
            Observation {
                identity: ResourceIdentity::GitWorktree {
                    common_dir: key.common_dir.clone(),
                    worktree_id: worktree.id.clone(),
                },
                fingerprint: ResourceFingerprint::opaque(
                    "git-worktree",
                    &worktree.snapshot_fingerprint,
                ),
                logical_bytes: None,
                allocated_bytes: None,
                attributes,
            }
        })
        .collect()
}

struct MetadataDiscovery {
    owners: BTreeMap<Utf8PathBuf, (String, &'static str)>,
    coverage: CoverageStatus,
}

fn discover_project_metadata(
    roots: &[Utf8PathBuf],
    options: &TraversalOptions,
    reader: &MetadataReader,
) -> MetadataDiscovery {
    let declarations = [
        ("Cargo.toml", MetadataFormat::Toml),
        ("pyproject.toml", MetadataFormat::Toml),
        ("package.json", MetadataFormat::Json),
        ("mix.exs", MetadataFormat::Text),
        ("go.mod", MetadataFormat::Text),
        ("build.gradle", MetadataFormat::Text),
        ("Package.swift", MetadataFormat::Text),
    ];
    let formats: BTreeMap<_, _> = declarations.into_iter().collect();
    let mut owners = BTreeMap::<Utf8PathBuf, (Vec<&'static str>, bool)>::new();
    let mut queue: VecDeque<_> = roots.iter().cloned().collect();
    let mut visited = 0_u64;
    let mut complete = true;
    while let Some(directory) = queue.pop_front() {
        if options
            .cancellation
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            complete = false;
            break;
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        for entry in entries {
            if options
                .cancellation
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                complete = false;
                break;
            }
            if visited == options.max_observations {
                complete = false;
                break;
            }
            visited += 1;
            let Ok(entry) = entry else {
                complete = false;
                continue;
            };
            let Ok(path) = Utf8PathBuf::from_path_buf(entry.path()) else {
                complete = false;
                continue;
            };
            if options
                .exclusions
                .iter()
                .any(|excluded| path.starts_with(excluded))
            {
                continue;
            }
            if let Some(hook) = &options.before_metadata {
                hook(&path);
            }
            if options
                .cancellation
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                complete = false;
                break;
            }
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                complete = false;
                continue;
            };
            if options.scope.as_ref().is_some_and(|scope| {
                !matches!(
                    scope.authorize(&path, metadata.dev()),
                    devclean_core::ScopeDecision::Include
                )
            }) {
                complete = false;
                continue;
            }
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if queue.len() == options.max_queue {
                    complete = false;
                } else {
                    queue.push_back(path);
                }
                continue;
            }
            let Some(name) = path.file_name() else {
                continue;
            };
            let Some((&manifest_name, &format)) = formats.get_key_value(name) else {
                continue;
            };
            let owner = path.parent().expect("manifest has parent").to_owned();
            let state = owners.entry(owner).or_insert((Vec::new(), true));
            state.0.push(manifest_name);
            if !matches!(
                reader.read(MetadataRequest::development(path, format, 1024 * 1024)),
                Ok(outcome) if outcome.status == MetadataStatus::Complete
            ) {
                state.1 = false;
            }
        }
    }
    MetadataDiscovery {
        owners: owners
            .into_iter()
            .map(|(owner, (mut markers, owner_complete))| {
                markers.sort_unstable();
                markers.dedup();
                (
                    owner,
                    (
                        markers.join(","),
                        if complete && owner_complete {
                            "complete"
                        } else {
                            "partial"
                        },
                    ),
                )
            })
            .collect(),
        coverage: if complete {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        },
    }
}

fn merge_coverage(overall: &mut CoverageStatus, next: &CoverageStatus) {
    overall.join_assign(next);
}

fn coverage_name(value: &CoverageStatus) -> &'static str {
    match value {
        CoverageStatus::Complete => "complete",
        CoverageStatus::Unsupported => "unsupported",
        CoverageStatus::Skipped => "skipped",
        CoverageStatus::Partial => "partial",
        CoverageStatus::Failed => "failed",
        CoverageStatus::TimedOut => "timed_out",
        CoverageStatus::Truncated => "truncated",
        CoverageStatus::Stale => "stale",
        CoverageStatus::Unknown => "unknown",
    }
}

fn docker_kind(value: &DockerObjectKind) -> &'static str {
    match value {
        DockerObjectKind::Container => "container",
        DockerObjectKind::Image => "image",
        DockerObjectKind::Layer => "layer",
        DockerObjectKind::BuildCache => "build_cache",
        DockerObjectKind::Network => "network",
        DockerObjectKind::Volume => "volume",
    }
}
fn config_error(error: impl std::fmt::Display) -> (ExitCode, String) {
    (ExitCode::ConfigInvalid, error.to_string())
}
fn internal(error: impl std::fmt::Display) -> (ExitCode, String) {
    (ExitCode::Internal, error.to_string())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn large_directory_metadata_discovery_checks_cancellation_per_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        for index in 0..10_000 {
            std::fs::write(root.join(format!("file-{index}")), b"x").unwrap();
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let hook_cancel = Arc::clone(&cancellation);
        let identity = devclean_core::ApprovedRootIdentity::inspect(&root).unwrap();
        let options = TraversalOptions {
            max_queue: 100,
            max_observations: 100_000,
            cross_mounts: false,
            exclusions: vec![],
            scope: Some(ScopePolicy::new(vec![identity], vec![], false)),
            cancellation,
            pool: Arc::new(WorkPool::new(1, BTreeMap::new())),
            before_metadata: Some(Arc::new(move |_| {
                if hook_calls.fetch_add(1, Ordering::Relaxed) == 4 {
                    hook_cancel.store(true, Ordering::Relaxed);
                }
            })),
        };
        let discovery = discover_project_metadata(
            &[root],
            &options,
            &MetadataReader::development_defaults(1024 * 1024),
        );
        assert_eq!(discovery.coverage, CoverageStatus::Partial);
        assert!(calls.load(Ordering::Relaxed) <= 5);
        assert!(discovery.owners.is_empty());
    }

    #[test]
    fn git_indirection_requires_explicit_in_scope_common_directory_association() {
        let temp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        let linked = base.join("linked");
        let primary = base.join("primary");
        let common = primary.join(".git");
        let registration = common.join("worktrees/wt");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::create_dir_all(&registration).unwrap();
        std::fs::write(linked.join(".git"), format!("gitdir: {}\n", registration)).unwrap();
        let approved = [
            devclean_core::ApprovedRootIdentity::inspect(&linked).unwrap(),
            devclean_core::ApprovedRootIdentity::inspect(&primary).unwrap(),
        ];
        assert_eq!(
            git_key(&linked, &approved).unwrap().unwrap().common_dir,
            common
        );

        let escaped = base.join("escaped/.git/worktrees/wt");
        std::fs::create_dir_all(&escaped).unwrap();
        std::fs::write(linked.join(".git"), format!("gitdir: {}\n", escaped)).unwrap();
        assert!(git_key(&linked, &approved).is_err());

        std::fs::write(
            linked.join(".git"),
            "gitdir: ../escaped/.git/worktrees/wt\n",
        )
        .unwrap();
        assert!(git_key(&linked, &approved).is_err());

        std::fs::remove_file(linked.join(".git")).unwrap();
        std::os::unix::fs::symlink(&common, linked.join(".git")).unwrap();
        assert!(git_key(&linked, &approved).is_err());
    }

    #[test]
    fn git_indirection_reader_rejects_malformed_oversized_fifo_and_swap() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let base = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        let dot_git = base.join(".git");

        std::fs::write(&dot_git, b"not a gitdir").unwrap();
        let approved = [devclean_core::ApprovedRootIdentity::inspect(&base).unwrap()];
        assert!(git_key(&base, &approved).is_err());

        std::fs::write(&dot_git, vec![b'x'; 4097]).unwrap();
        assert!(read_git_indirection(&dot_git).is_err());

        std::fs::remove_file(&dot_git).unwrap();
        let fifo = CString::new(dot_git.as_std_path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read_git_indirection(&dot_git).is_err());

        std::fs::remove_file(&dot_git).unwrap();
        std::fs::write(&dot_git, b"gitdir: somewhere").unwrap();
        let replacement = dot_git.clone();
        assert!(
            read_git_indirection_with_hook(&dot_git, || {
                std::fs::rename(&replacement, base.join(".git-old")).unwrap();
                std::fs::write(&replacement, b"gitdir: replacement").unwrap();
            })
            .is_err()
        );
    }

    #[test]
    fn config_reader_rejects_deterministic_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, b"approved_roots=[]").unwrap();
        let replacement = path.clone();
        let result = read_config_with_hook(path.to_str().unwrap(), || {
            std::fs::rename(&replacement, temp.path().join("old.toml")).unwrap();
            std::fs::write(&replacement, b"approved_roots=[]").unwrap();
        });
        assert!(matches!(result, Err((ExitCode::ConfigInvalid, _))));
    }

    #[test]
    fn empty_failed_external_inventory_dominates_partial_traversal_in_any_order() {
        // An empty Git/Docker result still carries its source coverage; it must
        // not depend on candidate emission to reach the report header.
        for (index, sources) in [
            vec![CoverageStatus::Failed, CoverageStatus::Partial],
            vec![CoverageStatus::Partial, CoverageStatus::Failed],
        ]
        .into_iter()
        .enumerate()
        {
            let temp = tempfile::tempdir().unwrap();
            let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
                .unwrap()
                .join("reports");
            let report_store = ReportStore::new(PrivateStore::create(&root).unwrap(), 1024 * 1024);
            let engine = ScanEngine {
                reports: &report_store,
                policy: Default::default(),
            };
            let scan_id = format!("empty-failed-{index}");
            let coverage = producer_coverage(TraversalCoverage::Partial, sources);
            let code = engine
                .run_streaming(
                    StreamingScanRequest {
                        scan_id: &scan_id,
                        safety_fingerprint: "safe",
                        scope_fingerprint: "scope",
                        probe_status: CoverageStatus::Complete,
                        cancellation: &AtomicBool::new(false),
                        memory_items: 1,
                    },
                    |_| coverage,
                )
                .unwrap();
            assert_eq!(code, ExitCode::Incomplete);
            assert_eq!(
                report_store.read(&scan_id).unwrap().coverage,
                CoverageStatus::Failed
            );
        }
    }

    #[test]
    fn command_parser_accepts_only_documented_argument_shapes() {
        fn args(values: &[&str]) -> Vec<String> {
            values.iter().map(|value| (*value).into()).collect()
        }
        let candidate = "00000000-0000-0000-0000-000000000001";
        let valid = [
            args(&["init", "store"]),
            args(&["scan", "config", "store", "scan"]),
            args(&["report", "store", "scan"]),
            args(&["report", "export", "--redacted", "store", "scan"]),
            args(&["explain", "store", "scan", candidate]),
        ];
        for values in valid {
            assert!(parse_command(&values).is_ok(), "{values:?}");
        }

        let invalid = [
            args(&[]),
            args(&["init"]),
            args(&["init", "store", "extra"]),
            args(&["scan", "config", "store"]),
            args(&["scan", "config", "store", "scan", "extra"]),
            args(&["report", "store"]),
            args(&["report", "export", "store", "scan"]),
            args(&["report", "export", "--raw", "store", "scan"]),
            args(&["report", "export", "--redacted", "store"]),
            args(&["export", "store", "scan"]),
            args(&["explain", "store", "scan"]),
            args(&["explain", "store", "scan", "not-a-uuid"]),
            args(&["unknown"]),
        ];
        for values in invalid {
            let error = parse_command(&values).unwrap_err();
            assert_eq!(error.0, ExitCode::ConfigInvalid, "{values:?}");
        }
    }
}
