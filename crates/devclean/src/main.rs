use camino::Utf8PathBuf;
use devclean::activity::{ActivityCollector, ActivityStatus};
use devclean::command::{CommandRunner, CommandSpec};
use devclean::config::{Config, DockerScope};
use devclean::detectors::CatalogDetector;
use devclean::docker_api::DockerUnixBackend;
use devclean::engine::{ExitCode, ProducerOutcome, ScanEngine, StreamingScanRequest};
use devclean::inventory::{
    DockerBackend, DockerDaemonKey, DockerInventoryCache, DockerObjectKind, GitCommandBackend,
    GitCommonKey, GitInventory, GitInventoryCache, InventoryLimits,
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
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

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
        macos: bool,
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

const USAGE: &str = "usage: devclean init STORE | init --macos [STORE] | scan CONFIG STORE SCAN_ID | report STORE SCAN_ID | report export --redacted STORE SCAN_ID | explain STORE SCAN_ID CANDIDATE_ID";

fn parse_command(args: &[String]) -> Result<CliCommand, (ExitCode, String)> {
    let invalid = || (ExitCode::ConfigInvalid, USAGE.into());
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init", "--macos"] => Ok(CliCommand::Init {
            store: default_macos_store().map_err(|message| (ExitCode::ConfigInvalid, message))?,
            macos: true,
        }),
        ["init", "--macos", store] => Ok(CliCommand::Init {
            store: (*store).into(),
            macos: true,
        }),
        ["init", store] => Ok(CliCommand::Init {
            store: (*store).into(),
            macos: false,
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

fn default_macos_store() -> Result<String, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Utf8PathBuf::from_path_buf(home.into())
        .map(|home| home.join(".devclean").to_string())
        .map_err(|_| "HOME must be UTF-8".into())
}

fn execute(command: CliCommand) -> Result<ExitCode, (ExitCode, String)> {
    // Standalone reports have no config, so keep their terminal output to a
    // conservative fixed number of candidate rows.
    const REPORT_TERMINAL_ROWS: usize = 20;
    match command {
        CliCommand::Init { store, macos } => handle_init(&store, macos),
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

fn handle_init(path: &str, macos: bool) -> Result<ExitCode, (ExitCode, String)> {
    let store = PrivateStore::create(camino::Utf8Path::new(path)).map_err(internal)?;
    let config = if macos {
        macos_config().map_err(config_error)?
    } else {
        "approved_roots=[]\napproved_caches=[]\nexclusions=[]\n".into()
    };
    store
        .create_new("config.toml", config.as_bytes())
        .map_err(internal)?;
    Ok(ExitCode::Complete)
}

fn macos_config() -> Result<String, &'static str> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let home = Utf8PathBuf::from_path_buf(home.into()).map_err(|_| "HOME must be UTF-8")?;
    let docker = discover_local_docker(&home);
    Ok(macos_config_for(&home, docker))
}

fn discover_local_docker(home: &camino::Utf8Path) -> Option<DockerScope> {
    let candidates = [
        ("orbstack", home.join(".orbstack/run/docker.sock")),
        ("desktop-linux", home.join(".docker/run/docker.sock")),
        ("default", Utf8PathBuf::from("/var/run/docker.sock")),
    ];
    for (context, socket) in candidates {
        let Ok(socket) = std::fs::canonicalize(socket) else {
            continue;
        };
        let Ok(socket) = Utf8PathBuf::from_path_buf(socket) else {
            continue;
        };
        let endpoint = format!("unix://{socket}");
        let key = DockerDaemonKey {
            transport: endpoint.clone(),
            context: context.into(),
            engine_id: "discovery-only".into(),
        };
        let mut backend =
            DockerUnixBackend::new(Duration::from_secs(1), Duration::from_secs(3), 1024 * 1024);
        if let Ok(engine_id) = backend.identity(&key) {
            return Some(DockerScope {
                context: context.into(),
                endpoint,
                engine_id,
            });
        }
    }
    None
}

fn macos_config_for(home: &camino::Utf8Path, docker: Option<DockerScope>) -> String {
    let discovery = discover_macos_project_roots(home);
    let cache_candidates = [
        home.join("Library/Caches"),
        home.join(".cache"),
        home.join(".npm"),
        home.join(".cargo/registry"),
        home.join(".cargo/git"),
        home.join("Library/Developer/Xcode/DerivedData"),
    ];
    let canonical_existing = |paths: &[Utf8PathBuf]| -> Vec<Utf8PathBuf> {
        paths
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .filter_map(|path| Utf8PathBuf::from_path_buf(path).ok())
            .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()))
            .collect()
    };
    let approved_roots = canonical_existing(&discovery.roots);
    let approved_caches = canonical_existing(&cache_candidates);
    let mut output = String::from(
        "# Generated by `devclean init --macos`. Review these explicit scopes before scanning.\n",
    );
    output.push_str(&format!(
        "# Project discovery: inspected={} included={} skipped={} truncated={}.\n",
        discovery.inspected,
        approved_roots.len(),
        discovery.skipped,
        discovery.truncated
    ));
    output.push_str(
        &toml::to_string(&Config {
            approved_roots: approved_roots.into_iter().collect(),
            approved_caches: approved_caches.into_iter().collect(),
            exclusions: BTreeSet::new(),
            docker,
            presentation: devclean::config::Presentation { terminal_rows: 100 },
            limits: devclean::config::ScanLimits::default(),
        })
        .expect("Config is TOML serializable"),
    );
    output
}

struct ProjectDiscovery {
    roots: Vec<Utf8PathBuf>,
    inspected: usize,
    skipped: usize,
    truncated: bool,
}

fn discover_macos_project_roots(home: &camino::Utf8Path) -> ProjectDiscovery {
    const MARKERS: [&str; 7] = [
        ".git",
        "Cargo.toml",
        "package.json",
        "mix.exs",
        "go.mod",
        "pyproject.toml",
        "Package.swift",
    ];
    let mut found = BTreeSet::new();
    let mut queue = VecDeque::from([
        (home.join("workspace"), 0_u8),
        (home.join("unraid"), 0_u8),
        (home.join("u8"), 2_u8),
    ]);
    let mut inspected = 0_usize;
    let mut skipped = 0_usize;
    let mut truncated = false;
    while let Some((directory, depth)) = queue.pop_front() {
        if inspected == 4096 {
            truncated = true;
            break;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
            skipped += 1;
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            skipped += 1;
            continue;
        }
        inspected += 1;
        if directory
            .file_name()
            .is_some_and(|name| name.contains("runner-farm"))
        {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            skipped += 1;
            continue;
        };
        let mut marker_found = false;
        let mut children = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_str().is_some_and(|name| MARKERS.contains(&name)) {
                marker_found = true;
            }
            if depth < 2
                && entry
                    .file_type()
                    .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
                && let Ok(path) = Utf8PathBuf::from_path_buf(entry.path())
            {
                children.push(path);
            }
        }
        if marker_found {
            if let Ok(canonical) = std::fs::canonicalize(&directory)
                && let Ok(canonical) = Utf8PathBuf::from_path_buf(canonical)
            {
                found.insert(canonical);
            }
            continue;
        }
        if depth >= 2 {
            continue;
        }
        children.sort();
        for path in children {
            queue.push_back((path, depth + 1));
        }
    }
    ProjectDiscovery {
        roots: found.into_iter().collect(),
        inspected,
        skipped,
        truncated,
    }
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
    let mut roots = authorized_scope.roots;
    let approved_caches = authorized_scope.caches;
    prioritize_roots(&mut roots, &approved_caches);
    let exclusions = authorized_scope.exclusions;
    let git_approved_roots = authorized_scope.root_identities.clone();
    let cancellation = Arc::new(AtomicBool::new(false));
    // Empirical APFS benchmarks on the real macOS scope show that wider
    // metadata/root fan-out creates contention rather than throughput.
    let filesystem_workers: usize = 4;
    let root_workers: usize = 2;
    let pool = Arc::new(WorkPool::new(
        filesystem_workers.saturating_add(4),
        BTreeMap::from([
            (PermitKind::Filesystem, filesystem_workers),
            (PermitKind::Detector, 2),
            (PermitKind::Subprocess, 1),
            (PermitKind::Docker, 1),
        ]),
    ));
    let options = TraversalOptions {
        max_queue: 250_000,
        max_observations: config.limits.max_observations.clamp(1, 50_000_000),
        shared_observations_remaining: Some(Arc::new(std::sync::atomic::AtomicU64::new(
            config.limits.max_observations.clamp(1, 50_000_000),
        ))),
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
        progress: None,
        deadline: None,
        emit_roots: true,
    };
    let metadata_reader = MetadataReader::development_defaults(1024 * 1024);
    let mut metadata_cache = BTreeMap::new();
    let overall_started = Instant::now();
    let max_elapsed = Duration::from_secs(config.limits.max_elapsed_seconds.clamp(1, 86_400));
    eprintln!("{{\"event\":\"phase_start\",\"phase\":\"activity\"}}");
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
    eprintln!("{{\"event\":\"phase_finish\",\"phase\":\"activity\"}}");
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
    eprintln!("{{\"event\":\"phase_start\",\"phase\":\"git_inventory\"}}");
    for root in &roots {
        if overall_started.elapsed() >= max_elapsed {
            external_coverage.join_assign(&CoverageStatus::Partial);
            eprintln!(
                "{{\"event\":\"phase_limit\",\"phase\":\"git_inventory\",\"reason\":\"elapsed_budget\"}}"
            );
            break;
        }
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
    eprintln!("{{\"event\":\"phase_finish\",\"phase\":\"git_inventory\"}}");
    eprintln!("{{\"event\":\"phase_start\",\"phase\":\"docker_inventory\"}}");
    if overall_started.elapsed() < max_elapsed
        && let Some(approved) = approved_docker
    {
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
    eprintln!("{{\"event\":\"phase_finish\",\"phase\":\"docker_inventory\"}}");
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
    let available = available_bytes(camino::Utf8Path::new(store_path)).map_err(internal)?;
    let min_free_reserve = config
        .limits
        .min_free_bytes
        .clamp(64 * 1024 * 1024, 16 * 1024 * 1024 * 1024);
    if available < min_free_reserve {
        return Err((
            ExitCode::ConfigInvalid,
            format!(
                "scan requires at least {min_free_reserve} bytes free at the report store; available={available}"
            ),
        ));
    }
    eprintln!(
        "scan budgets: observations={} elapsed={}s root_workers={} filesystem_workers={} observation_spool=2147483648B candidate_spool=268435456B free_reserve={}B",
        options.max_observations,
        config.limits.max_elapsed_seconds.clamp(1, 86_400),
        root_workers,
        filesystem_workers,
        min_free_reserve
    );
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
            filesystem_parent_first: true,
        },
        |emit| {
            for observation in external {
                emit(observation);
            }
            for (index, root) in roots.iter().enumerate() {
                eprintln!(
                    "{{\"event\":\"root_start\",\"index\":{},\"total\":{},\"root\":{}}}",
                    index + 1,
                    roots.len(),
                    serde_json::to_string(root.as_str()).unwrap_or_else(|_| "\"invalid\"".into())
                );
            }
            let mut parallel_options = options.clone();
            parallel_options.deadline = Some(overall_started + max_elapsed);
            let parallel_outcomes = devclean::scan::stream_roots_parallel(
                &roots,
                &parallel_options,
                root_workers,
                Some(Arc::new({
                    let roots = roots.clone();
                    move |index, entries, queue_high_water| {
                        eprintln!(
                            "{{\"event\":\"root_progress\",\"root\":{},\"entries\":{},\"queue_high_water\":{}}}",
                            serde_json::to_string(roots[index].as_str())
                                .unwrap_or_else(|_| "\"invalid\"".into()),
                            entries,
                            queue_high_water
                        );
                    }
                })),
                |index, mut value| {
                    let root = &roots[index];
                    if let devclean_core::ResourceIdentity::Filesystem { path } = &value.identity {
                        if path.file_name() == Some(".git") {
                            let discovered = path
                                .parent()
                                .map(|project| git_key(project, &git_approved_roots));
                            if matches!(discovered, Some(Err(()))) {
                                external_coverage.join_assign(&CoverageStatus::Partial);
                            }
                            if let Some(Ok(Some(key))) = discovered
                                && emitted_git.insert(key.clone())
                            {
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
                        if CatalogDetector::is_filesystem_candidate(path) {
                            value
                                .attributes
                                .insert("probe_approved_scope".into(), "complete".into());
                            value.attributes.insert(
                                "probe_activity".into(),
                                coverage_name(&probe_status).into(),
                            );
                            value.attributes.insert(
                                "probe_open_files".into(),
                                coverage_name(&probe_status).into(),
                            );
                            if let Some((owner, markers, coverage)) = project_metadata_for(
                                path,
                                root,
                                &metadata_reader,
                                &mut metadata_cache,
                            ) {
                                value
                                    .attributes
                                    .insert("project_owner".into(), owner.to_string());
                                value.attributes.insert("markers".into(), markers);
                                value
                                    .attributes
                                    .insert("metadata_coverage".into(), coverage.into());
                                value
                                    .attributes
                                    .insert("probe_metadata".into(), coverage.into());
                            }
                            if path
                                .ancestors()
                                .any(|ancestor| approved_caches.contains(ancestor))
                            {
                                value.attributes.insert("known_cache".into(), "true".into());
                            }
                            if approved_caches.contains(path) {
                                value
                                    .attributes
                                    .insert("approved_cache_root".into(), "true".into());
                            }
                            if value.attributes.get("known_cache").map(String::as_str)
                                == Some("true")
                                || (!value
                                    .attributes
                                    .get("markers")
                                    .is_none_or(String::is_empty)
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
                },
            );
            let mut diagnostics = DiagnosticAggregator::new(1000, 3);
            let mut traversal_coverage = TraversalCoverage::Complete;
            let mut incomplete_roots = BTreeSet::new();
            for outcome in parallel_outcomes {
                let root = &roots[outcome.index];
                let root_diagnostics = outcome
                    .diagnostics
                    .groups()
                    .iter()
                    .filter(|(key, _)| key.root == root.as_str())
                    .map(|(key, summary)| format!("{}={}", key.reason, summary.count))
                    .collect::<Vec<_>>()
                    .join(",");
                let remaining = options
                    .shared_observations_remaining
                    .as_ref()
                    .map_or(0, |value| value.load(std::sync::atomic::Ordering::Relaxed));
                eprintln!(
                    "{{\"event\":\"root_finish\",\"index\":{},\"total\":{},\"root\":{},\"entries\":{},\"metadata_reads\":{},\"queue_high_water\":{},\"elapsed_seconds\":{:.3},\"coverage\":{},\"remaining_observations\":{},\"diagnostics\":{}}}",
                    outcome.index + 1,
                    roots.len(),
                    serde_json::to_string(root.as_str()).unwrap_or_else(|_| "\"invalid\"".into()),
                    outcome.traversal.metrics.entries_seen,
                    outcome.traversal.metrics.metadata_reads,
                    outcome.traversal.metrics.queue_high_water,
                    outcome.elapsed.as_secs_f64(),
                    serde_json::to_string(traversal_coverage_name(outcome.traversal.coverage))
                        .unwrap(),
                    remaining,
                    serde_json::to_string(&root_diagnostics).unwrap()
                );
                if outcome.traversal.coverage != TraversalCoverage::Complete {
                    incomplete_roots.insert(root.clone());
                    traversal_coverage = match outcome.traversal.coverage {
                        TraversalCoverage::Cancelled => TraversalCoverage::Cancelled,
                        TraversalCoverage::Partial
                            if traversal_coverage != TraversalCoverage::Cancelled =>
                        {
                            TraversalCoverage::Partial
                        }
                        _ => traversal_coverage,
                    };
                }
            }
            if options
                .shared_observations_remaining
                .as_ref()
                .is_some_and(|value| value.load(std::sync::atomic::Ordering::Relaxed) == 0)
            {
                eprintln!(
                    "{{\"event\":\"scan_limit\",\"remaining_roots\":0,\"reason\":\"observation_budget\"}}"
                );
            }
            if options.before_metadata.is_some() {
            let mut work_budget = ScanWorkBudget::from_started(
                options.max_observations,
                overall_started,
                max_elapsed,
            );
            for (index, root) in roots.iter().enumerate() {
                if let Some(reason) = work_budget.exhausted_reason() {
                    incomplete_roots.extend(roots[index..].iter().cloned());
                    traversal_coverage = TraversalCoverage::Partial;
                    eprintln!(
                        "{{\"event\":\"scan_limit\",\"remaining_roots\":{},\"reason\":\"{}\"}}",
                        roots.len() - index,
                        reason
                    );
                    break;
                }
                eprintln!(
                    "{{\"event\":\"root_start\",\"index\":{},\"total\":{},\"root\":{}}}",
                    index + 1,
                    roots.len(),
                    serde_json::to_string(root.as_str()).unwrap_or_else(|_| "\"invalid\"".into())
                );
                let started = Instant::now();
                let mut root_options = options.clone();
                root_options.max_observations = work_budget.remaining_observations;
                root_options.deadline = Some(work_budget.deadline());
                let progress_root = root.clone();
                root_options.progress = Some(Arc::new(move |entries, queue_high_water| {
                    eprintln!(
                        "{{\"event\":\"root_progress\",\"root\":{},\"entries\":{},\"queue_high_water\":{}}}",
                        serde_json::to_string(progress_root.as_str())
                            .unwrap_or_else(|_| "\"invalid\"".into()),
                        entries,
                        queue_high_water
                    );
                }));
                let traversal = stream_observations(
                    std::slice::from_ref(root),
                    &root_options,
                    &mut diagnostics,
                    |mut value| {
                        if let devclean_core::ResourceIdentity::Filesystem { path } =
                            &value.identity
                        {
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
                            if path.starts_with(root)
                                && CatalogDetector::is_filesystem_candidate(path)
                            {
                                value
                                    .attributes
                                    .insert("probe_approved_scope".into(), "complete".into());
                                value.attributes.insert(
                                    "probe_activity".into(),
                                    coverage_name(&probe_status).into(),
                                );
                                value.attributes.insert(
                                    "probe_open_files".into(),
                                    coverage_name(&probe_status).into(),
                                );
                                if let Some((owner, markers, coverage)) = project_metadata_for(
                                    path,
                                    root,
                                    &metadata_reader,
                                    &mut metadata_cache,
                                )
                                {
                                    value
                                        .attributes
                                        .insert("project_owner".into(), owner.to_string());
                                    value.attributes.insert("markers".into(), markers);
                                    value
                                        .attributes
                                        .insert("metadata_coverage".into(), coverage.into());
                                    value
                                        .attributes
                                        .insert("probe_metadata".into(), coverage.into());
                                }
                                if path
                                    .ancestors()
                                    .any(|ancestor| approved_caches.contains(ancestor))
                                {
                                    value.attributes.insert("known_cache".into(), "true".into());
                                }
                                if approved_caches.contains(path) {
                                    value
                                        .attributes
                                        .insert("approved_cache_root".into(), "true".into());
                                }
                                if value.attributes.get("known_cache").map(String::as_str)
                                    == Some("true")
                                    || (!value
                                        .attributes
                                        .get("markers")
                                        .is_none_or(String::is_empty)
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
                    },
                );
                work_budget.consume(traversal.metrics.entries_seen);
                let root_diagnostics = diagnostics
                    .groups()
                    .iter()
                    .filter(|(key, _)| key.root == root.as_str())
                    .map(|(key, summary)| format!("{}={}", key.reason, summary.count))
                    .collect::<Vec<_>>()
                    .join(",");
                eprintln!(
                    "{{\"event\":\"root_finish\",\"index\":{},\"total\":{},\"root\":{},\"entries\":{},\"metadata_reads\":{},\"queue_high_water\":{},\"elapsed_seconds\":{:.3},\"coverage\":{},\"remaining_observations\":{},\"diagnostics\":{}}}",
                    index + 1,
                    roots.len(),
                    serde_json::to_string(root.as_str()).unwrap_or_else(|_| "\"invalid\"".into()),
                    traversal.metrics.entries_seen,
                    traversal.metrics.metadata_reads,
                    traversal.metrics.queue_high_water,
                    started.elapsed().as_secs_f64(),
                    serde_json::to_string(traversal_coverage_name(traversal.coverage)).unwrap(),
                    work_budget.remaining_observations,
                    serde_json::to_string(&root_diagnostics).unwrap()
                );
                if traversal.coverage != TraversalCoverage::Complete {
                    incomplete_roots.insert(root.clone());
                    traversal_coverage = match traversal.coverage {
                        TraversalCoverage::Cancelled => TraversalCoverage::Cancelled,
                        TraversalCoverage::Partial
                            if traversal_coverage != TraversalCoverage::Cancelled =>
                        {
                            TraversalCoverage::Partial
                        }
                        _ => traversal_coverage,
                    };
                }
            }
            }
            ProducerOutcome {
                coverage: producer_coverage(
                    traversal_coverage,
                    [
                        probe_status,
                        external_coverage,
                    ],
                ),
                incomplete_roots,
                global_estimates_incomplete: false,
            }
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

fn available_bytes(path: &camino::Utf8Path) -> std::io::Result<u64> {
    let encoded = CString::new(path.as_std_path().as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::statvfs(encoded.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    Ok(u64::from(stats.f_bavail).saturating_mul(stats.f_frsize))
}

fn prioritize_roots(roots: &mut [Utf8PathBuf], caches: &BTreeSet<Utf8PathBuf>) {
    roots.sort_by(|left, right| {
        let left_priority = !caches.contains(left);
        let right_priority = !caches.contains(right);
        left_priority
            .cmp(&right_priority)
            .then_with(|| left.cmp(right))
    });
}

fn traversal_coverage_name(value: TraversalCoverage) -> &'static str {
    match value {
        TraversalCoverage::Complete => "complete",
        TraversalCoverage::Partial => "partial",
        TraversalCoverage::Cancelled => "cancelled",
    }
}

struct ScanWorkBudget {
    remaining_observations: u64,
    started: Instant,
    max_elapsed: Duration,
}

impl ScanWorkBudget {
    #[cfg(test)]
    fn new(max_observations: u64, max_elapsed: Duration) -> Self {
        Self::from_started(max_observations, Instant::now(), max_elapsed)
    }

    fn from_started(max_observations: u64, started: Instant, max_elapsed: Duration) -> Self {
        Self {
            remaining_observations: max_observations,
            started,
            max_elapsed,
        }
    }

    fn consume(&mut self, observations: u64) {
        self.remaining_observations = self.remaining_observations.saturating_sub(observations);
    }

    fn deadline(&self) -> Instant {
        self.started + self.max_elapsed
    }

    fn exhausted_reason(&self) -> Option<&'static str> {
        if self.remaining_observations == 0 {
            Some("observation_budget")
        } else if self.started.elapsed() >= self.max_elapsed {
            Some("elapsed_budget")
        } else {
            None
        }
    }
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

fn project_metadata_for(
    candidate: &camino::Utf8Path,
    root: &camino::Utf8Path,
    reader: &MetadataReader,
    cache: &mut BTreeMap<Utf8PathBuf, Option<(Utf8PathBuf, String, &'static str)>>,
) -> Option<(Utf8PathBuf, String, &'static str)> {
    let parent = candidate.parent()?.to_owned();
    if let Some(cached) = cache.get(&parent) {
        return cached.clone();
    }
    let declarations = [
        ("Cargo.toml", MetadataFormat::Toml),
        ("pyproject.toml", MetadataFormat::Toml),
        ("package.json", MetadataFormat::Json),
        ("mix.exs", MetadataFormat::Text),
        ("go.mod", MetadataFormat::Text),
        ("build.gradle", MetadataFormat::Text),
        ("Package.swift", MetadataFormat::Text),
    ];
    let mut result = None;
    for owner in parent
        .ancestors()
        .take_while(|owner| owner.starts_with(root))
    {
        let mut markers = Vec::new();
        let mut complete = true;
        for &(name, format) in &declarations {
            let manifest = owner.join(name);
            if !std::fs::symlink_metadata(&manifest).is_ok_and(|metadata| metadata.is_file()) {
                continue;
            }
            markers.push(name);
            if !matches!(
                reader.read(MetadataRequest::development(manifest, format, 1024 * 1024)),
                Ok(outcome) if outcome.status == MetadataStatus::Complete
            ) {
                complete = false;
            }
        }
        if !markers.is_empty() {
            markers.sort_unstable();
            result = Some((
                owner.to_owned(),
                markers.join(","),
                if complete { "complete" } else { "partial" },
            ));
            break;
        }
    }
    cache.insert(parent, result.clone());
    result
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
                        filesystem_parent_first: false,
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
            args(&["init", "--macos"]),
            args(&["init", "--macos", "store"]),
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

    #[test]
    fn macos_preset_includes_only_existing_targeted_roots() {
        let temp = tempfile::tempdir().unwrap();
        let home = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        std::fs::create_dir_all(home.join("Library/Caches")).unwrap();
        std::fs::create_dir(home.join(".cache")).unwrap();
        std::fs::create_dir_all(home.join("workspace/app")).unwrap();
        std::fs::write(home.join("workspace/app/Cargo.toml"), "[package]").unwrap();
        std::fs::create_dir_all(home.join("workspace/not-a-project")).unwrap();
        std::fs::create_dir_all(home.join("workspace/ci-runner-farm-old")).unwrap();
        std::fs::write(
            home.join("workspace/ci-runner-farm-old/Cargo.toml"),
            "[package]",
        )
        .unwrap();
        std::fs::create_dir_all(home.join("workspace/runner-farm-path-b")).unwrap();
        std::fs::write(
            home.join("workspace/runner-farm-path-b/Cargo.toml"),
            "[package]",
        )
        .unwrap();

        let config = Config::parse(&macos_config_for(&home, None)).unwrap();
        assert_eq!(
            config.approved_roots,
            BTreeSet::from([home.join("workspace/app")])
        );
        assert_eq!(
            config.approved_caches,
            BTreeSet::from([home.join(".cache"), home.join("Library/Caches")])
        );
        assert!(!config.approved_caches.contains(&home.join(".rustup")));
        assert!(!config.approved_caches.contains(&home.join(".local/share")));

        let docker = DockerScope {
            context: "fixture".into(),
            endpoint: "unix:///fixture/docker.sock".into(),
            engine_id: "engine-1".into(),
        };
        let config = Config::parse(&macos_config_for(&home, Some(docker))).unwrap();
        assert_eq!(config.docker.unwrap().engine_id, "engine-1");
    }

    #[test]
    fn project_discovery_ignores_files_and_is_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let home = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        std::fs::create_dir(home.join("workspace")).unwrap();
        for index in 0..5000 {
            std::fs::write(home.join(format!("workspace/file-{index}")), b"x").unwrap();
        }
        std::fs::create_dir(home.join("workspace/project")).unwrap();
        std::fs::write(home.join("workspace/project/Cargo.toml"), "[package]").unwrap();

        let first = discover_macos_project_roots(&home);
        let second = discover_macos_project_roots(&home);
        assert_eq!(first.roots, vec![home.join("workspace/project")]);
        assert_eq!(first.roots, second.roots);
        assert!(!first.truncated);
        assert!(first.inspected <= 2);
    }

    #[test]
    fn performance_contract_candidate_metadata_is_resolved_lazily_and_cached() {
        let temp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap()).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        let mut cache = BTreeMap::new();
        let metadata = project_metadata_for(
            &root.join("target"),
            &root,
            &MetadataReader::development_defaults(1024 * 1024),
            &mut cache,
        )
        .unwrap();
        assert_eq!(metadata.0, root);
        assert_eq!(metadata.1, "Cargo.toml");
        assert_eq!(metadata.2, "complete");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn scan_work_budget_is_global_across_roots_and_time_bounded() {
        let mut budget = ScanWorkBudget::new(5, Duration::from_secs(60));
        budget.consume(2);
        budget.consume(3);
        assert_eq!(budget.exhausted_reason(), Some("observation_budget"));

        let elapsed = ScanWorkBudget::new(5, Duration::ZERO);
        assert_eq!(elapsed.exhausted_reason(), Some("elapsed_budget"));
    }

    #[test]
    fn filesystem_capacity_probe_reports_available_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        assert!(available_bytes(&path).unwrap() > 0);
    }

    #[test]
    fn performance_contract_cache_roots_are_scheduled_first() {
        let cache: Utf8PathBuf = "/tmp/z-cache".into();
        let mut roots = vec![
            "/tmp/a-project".into(),
            cache.clone(),
            "/tmp/b-project".into(),
        ];
        prioritize_roots(&mut roots, &BTreeSet::from([cache.clone()]));
        assert_eq!(roots[0], cache);
        assert_eq!(roots[1].as_str(), "/tmp/a-project");
    }
}
