use camino::Utf8PathBuf;
use devclean::engine::*;
use devclean::private_store::PrivateStore;
use devclean::report::{ReportError, ReportStore};
use devclean_core::{CoverageStatus, Observation, ResourceFingerprint, ResourceIdentity, Tier};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn observation(path: &str, markers: &str) -> Observation {
    let digest = blake3::hash(path.as_bytes());
    let inode = u64::from_be_bytes(digest.as_bytes()[..8].try_into().unwrap());
    Observation {
        identity: ResourceIdentity::Filesystem { path: path.into() },
        fingerprint: ResourceFingerprint::opaque("e2e", path),
        logical_bytes: Some(1),
        allocated_bytes: Some(1),
        attributes: BTreeMap::from([
            ("device".into(), "1".into()),
            ("inode".into(), inode.to_string()),
            ("project_owner".into(), "/p".into()),
            ("markers".into(), markers.into()),
            ("metadata_coverage".into(), "complete".into()),
            ("known_cache".into(), "true".into()),
            ("known_log".into(), "true".into()),
            ("probe_approved_scope".into(), "complete".into()),
            ("probe_rebuildability".into(), "complete".into()),
            ("probe_filesystem_identity".into(), "complete".into()),
            ("probe_activity".into(), "complete".into()),
            ("probe_open_files".into(), "complete".into()),
            ("probe_metadata".into(), "complete".into()),
        ]),
    }
}
fn store() -> (tempfile::TempDir, ReportStore) {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 8 * 1024 * 1024);
    (temp, store)
}

fn filesystem_observation(path: &camino::Utf8Path, markers: &str) -> Observation {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    Observation {
        identity: ResourceIdentity::Filesystem { path: path.into() },
        fingerprint: ResourceFingerprint::filesystem(
            metadata.dev(),
            metadata.ino(),
            if metadata.is_dir() {
                "directory"
            } else {
                "file"
            },
            metadata.len(),
            i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        ),
        logical_bytes: Some(metadata.len()),
        allocated_bytes: Some(metadata.blocks() * 512),
        attributes: BTreeMap::from([
            ("device".into(), metadata.dev().to_string()),
            ("inode".into(), metadata.ino().to_string()),
            ("project_owner".into(), "/fixture".into()),
            ("markers".into(), markers.into()),
            ("metadata_coverage".into(), "complete".into()),
            ("known_cache".into(), "true".into()),
            ("probe_approved_scope".into(), "complete".into()),
            ("probe_rebuildability".into(), "complete".into()),
            ("probe_filesystem_identity".into(), "complete".into()),
            ("probe_activity".into(), "complete".into()),
            ("probe_open_files".into(), "complete".into()),
            ("probe_metadata".into(), "complete".into()),
        ]),
    }
}

#[test]
fn compact_all_family_corpus_persists_exact_classification() {
    let (_temp, reports) = store();
    let mut active_rust = observation("/p/target", "Cargo.toml");
    active_rust
        .attributes
        .insert("active".into(), "true".into());
    let mut nested = observation("/p/node_modules", "package.json");
    nested.attributes.insert("device".into(), "1".into());
    nested.attributes.insert("inode".into(), "77".into());
    let mut shared = observation("/p/node_modules/.cache", "package.json");
    shared.attributes.insert("device".into(), "1".into());
    shared.attributes.insert("inode".into(), "77".into());
    let observations = vec![
        active_rust,
        observation("/p/__pycache__", ""),
        nested,
        observation("/p/_build", "mix.exs"),
        observation("/p/go-build", "go.mod"),
        observation("/p/.gradle", "build.gradle"),
        observation("/p/DerivedData", ""),
        observation("/p/playwright-report", "package.json"),
        observation("/p/.codex", ""),
        observation("/p/run.log", ""),
        observation("/p/archive.zip", ""),
        observation("/p/ordinary", ""),
        shared,
        external_git(true, "complete"),
        external_docker("volume", true, "complete"),
        external_docker("image", false, "complete"),
        external_docker("mystery", false, "complete"),
    ];
    let code = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run(ScanRequest {
        scan_id: "scan",
        safety_fingerprint: "safe",
        scope_fingerprint: "scope",
        observations: &observations,
        probe_status: CoverageStatus::Complete,
        cancellation: &AtomicBool::new(false),
        memory_items: 3,
    })
    .unwrap();
    assert_eq!(code, ExitCode::Complete);
    let report = reports.read("scan").unwrap();
    assert_eq!(report.candidates.len(), 16);
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|v| v.tier == Tier::Safe)
            .count(),
        6
    );
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|v| v.tier == Tier::Protected)
            .count(),
        5
    );
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|v| v.tier == Tier::Review)
            .count(),
        4
    );
    assert!(report.warnings.iter().any(|value| {
        value.contains("shared_candidates=2") && value.contains("relationships=1")
    }));
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|value| value.tier == Tier::Unknown)
            .count(),
        1
    );
}

fn external_git(dirty: bool, coverage: &str) -> Observation {
    Observation {
        identity: ResourceIdentity::GitWorktree {
            common_dir: "/p/.git".into(),
            worktree_id: "abc".into(),
        },
        fingerprint: ResourceFingerprint::opaque("git", "abc"),
        logical_bytes: None,
        allocated_bytes: None,
        attributes: BTreeMap::from([
            ("dirty".into(), dirty.to_string()),
            ("probe_approved_scope".into(), "complete".into()),
            ("probe_filesystem_identity".into(), "complete".into()),
            ("probe_activity".into(), "complete".into()),
            ("probe_open_files".into(), "complete".into()),
            ("probe_git_status".into(), coverage.into()),
            ("probe_git_registration".into(), "complete".into()),
            ("probe_git_reachability".into(), "complete".into()),
        ]),
    }
}

fn external_docker(kind: &str, protected: bool, coverage: &str) -> Observation {
    Observation {
        identity: ResourceIdentity::Docker {
            daemon: "engine".into(),
            object_kind: kind.into(),
            id: format!("{kind}-id"),
        },
        fingerprint: ResourceFingerprint::opaque("docker", kind),
        logical_bytes: Some(10),
        allocated_bytes: Some(10),
        attributes: BTreeMap::from([
            ("volume".into(), protected.to_string()),
            ("probe_rebuildability".into(), "complete".into()),
            ("probe_docker_snapshot".into(), coverage.into()),
            ("probe_docker_references".into(), "complete".into()),
        ]),
    }
}

#[test]
fn incomplete_or_cancelled_scan_never_grants_safe_and_preserves_prior_report() {
    let (_temp, reports) = store();
    let mut value = observation("/p/target", "Cargo.toml");
    value
        .attributes
        .insert("probe_activity".into(), "partial".into());
    let values = vec![value];
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let code = engine
        .run(ScanRequest {
            scan_id: "partial",
            safety_fingerprint: "safe",
            scope_fingerprint: "scope",
            observations: &values,
            probe_status: CoverageStatus::Partial,
            cancellation: &AtomicBool::new(false),
            memory_items: 2,
        })
        .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    assert!(
        reports
            .read("partial")
            .unwrap()
            .candidates
            .iter()
            .all(|v| v.tier != Tier::Safe)
    );
    let held = reports.try_lock().unwrap();
    assert!(matches!(
        engine.run(ScanRequest {
            scan_id: "locked",
            safety_fingerprint: "safe",
            scope_fingerprint: "scope",
            observations: &values,
            probe_status: CoverageStatus::Complete,
            cancellation: &AtomicBool::new(false),
            memory_items: 2
        }),
        Err(ReportError::Locked)
    ));
    drop(held);
    assert!(reports.read("partial").is_ok());
}

#[test]
fn candidate_local_coverage_downgrades_only_safe_authority_and_marks_report_incomplete() {
    let (_temp, reports) = store();
    let complete = observation("/p/target", "Cargo.toml");
    let mut partial = observation("/p/node_modules", "package.json");
    partial
        .attributes
        .insert("probe_activity".into(), "partial".into());
    let code = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run(ScanRequest {
        scan_id: "candidate-local",
        safety_fingerprint: "safe",
        scope_fingerprint: "scope",
        observations: &[complete, partial],
        probe_status: CoverageStatus::Complete,
        cancellation: &AtomicBool::new(false),
        memory_items: 2,
    })
    .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let report = reports.read("candidate-local").unwrap();
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|value| value.tier == Tier::Safe)
            .count(),
        1
    );
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|value| value.tier == Tier::Protected)
            .count(),
        1
    );
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|value| value.coverage == CoverageStatus::Complete)
            .count(),
        1
    );
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|value| value.coverage == CoverageStatus::Partial)
            .count(),
        1
    );
}

#[test]
fn complete_activity_cannot_synthesize_unrelated_mandatory_proofs() {
    for missing_probe in [
        "probe_metadata",
        "probe_approved_scope",
        "probe_rebuildability",
    ] {
        let (_temp, reports) = store();
        let mut value = observation("/p/target", "Cargo.toml");
        value.attributes.remove(missing_probe);
        assert_eq!(
            value.attributes.get("probe_activity").map(String::as_str),
            Some("complete")
        );

        let scan_id = format!("missing-{missing_probe}");
        let code = ScanEngine {
            reports: &reports,
            policy: Default::default(),
        }
        .run(ScanRequest {
            scan_id: &scan_id,
            safety_fingerprint: "safe",
            scope_fingerprint: "scope",
            observations: &[value],
            probe_status: CoverageStatus::Complete,
            cancellation: &AtomicBool::new(false),
            memory_items: 2,
        })
        .unwrap();

        assert_eq!(code, ExitCode::Incomplete, "{missing_probe}");
        let report = reports.read(&scan_id).unwrap();
        assert_eq!(report.candidates.len(), 1);
        assert_ne!(report.candidates[0].tier, Tier::Safe, "{missing_probe}");
        assert!(
            report.candidates[0]
                .protections
                .iter()
                .any(|value| value == "mandatory_probe_incomplete"),
            "{missing_probe}"
        );
    }
}

#[test]
fn mixed_order_recursive_estimates_match_du_blocks_dedupe_hardlinks_and_expose_overlap() {
    let fixture = tempfile::tempdir().unwrap();
    let fixture =
        Utf8PathBuf::from_path_buf(std::fs::canonicalize(fixture.path()).unwrap()).unwrap();
    let target = fixture.join("target");
    let nested = target.join("node_modules");
    std::fs::create_dir_all(&nested).unwrap();
    let blob = nested.join("blob.bin");
    std::fs::write(&blob, vec![7_u8; 8192]).unwrap();
    let hardlink = target.join("blob-hardlink.bin");
    std::fs::hard_link(&blob, &hardlink).unwrap();

    let paths = [&blob, &target, &hardlink, &nested];
    let observations: Vec<_> = paths
        .iter()
        .map(|path| filesystem_observation(path, "Cargo.toml,package.json"))
        .collect();
    let expected_target_logical: u64 = [&target, &nested, &blob, &hardlink]
        .iter()
        .map(|path| std::fs::symlink_metadata(path).unwrap().len())
        .sum();
    let expected_nested_logical = std::fs::symlink_metadata(&nested).unwrap().len()
        + std::fs::symlink_metadata(&blob).unwrap().len();
    let expected_target_physical: u64 = [&target, &nested, &blob]
        .iter()
        .map(|path| std::fs::symlink_metadata(path).unwrap().blocks() * 512)
        .sum();
    let expected_nested_physical = [&nested, &blob]
        .iter()
        .map(|path| std::fs::symlink_metadata(path).unwrap().blocks() * 512)
        .sum::<u64>();
    let du = Command::new("/usr/bin/du")
        .args(["-sk", target.as_str()])
        .output()
        .unwrap();
    assert!(du.status.success());
    let du_kib: u64 = String::from_utf8(du.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(expected_target_physical, du_kib * 1024);

    let (_temp, reports) = store();
    let code = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run(ScanRequest {
        scan_id: "recursive-accounting",
        safety_fingerprint: "safe",
        scope_fingerprint: "scope",
        observations: &observations,
        probe_status: CoverageStatus::Complete,
        cancellation: &AtomicBool::new(false),
        memory_items: 2,
    })
    .unwrap();
    assert_eq!(code, ExitCode::Complete);
    let report = reports.read("recursive-accounting").unwrap();
    let target_candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.identity
                == ResourceIdentity::Filesystem {
                    path: target.clone(),
                }
        })
        .unwrap();
    let nested_candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.identity
                == ResourceIdentity::Filesystem {
                    path: nested.clone(),
                }
        })
        .unwrap();
    assert_eq!(
        target_candidate.logical_bytes_estimate,
        Some(expected_target_logical)
    );
    assert_eq!(
        target_candidate.physical_bytes_estimate,
        Some(expected_target_physical)
    );
    assert_eq!(
        nested_candidate.logical_bytes_estimate,
        Some(expected_nested_logical)
    );
    assert_eq!(
        nested_candidate.physical_bytes_estimate,
        Some(expected_nested_physical)
    );
    assert_eq!(
        nested_candidate.shared_physical_bytes,
        Some(expected_nested_physical)
    );
    assert_eq!(
        target_candidate.shared_physical_bytes,
        Some(expected_nested_physical)
    );
}

#[test]
fn descendant_first_observation_is_replayed_after_candidate_discovery() {
    let (_temp, reports) = store();
    let child = observation("/p/target/deep/ordinary.bin", "");
    let root = observation("/p/target", "Cargo.toml");
    ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run(ScanRequest {
        scan_id: "descendant-first",
        safety_fingerprint: "safe",
        scope_fingerprint: "scope",
        observations: &[child, root],
        probe_status: CoverageStatus::Complete,
        cancellation: &AtomicBool::new(false),
        memory_items: 2,
    })
    .unwrap();
    let report = reports.read("descendant-first").unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].logical_bytes_estimate, Some(2));
    assert_eq!(report.candidates[0].physical_bytes_estimate, Some(2));
}

#[test]
fn incomplete_recursive_accounting_withholds_physical_estimates() {
    for (case, mutate) in [
        ("missing-device", "missing-device"),
        ("bad-inode", "bad-inode"),
        ("missing-allocation", "missing-allocation"),
    ] {
        let (_temp, reports) = store();
        let root = observation("/p/target", "Cargo.toml");
        let mut child = observation("/p/target/ordinary.bin", "");
        match mutate {
            "missing-device" => {
                child.attributes.remove("device");
            }
            "bad-inode" => {
                child
                    .attributes
                    .insert("inode".into(), "not-an-inode".into());
            }
            "missing-allocation" => child.allocated_bytes = None,
            _ => unreachable!(),
        }
        let scan_id = format!("accounting-{case}");
        let code = ScanEngine {
            reports: &reports,
            policy: Default::default(),
        }
        .run(ScanRequest {
            scan_id: &scan_id,
            safety_fingerprint: "safe",
            scope_fingerprint: "scope",
            observations: &[root, child],
            probe_status: CoverageStatus::Complete,
            cancellation: &AtomicBool::new(false),
            memory_items: 2,
        })
        .unwrap();
        assert_eq!(code, ExitCode::Incomplete, "{case}");
        let candidate = &reports.read(&scan_id).unwrap().candidates[0];
        assert_eq!(candidate.physical_bytes_estimate, None, "{case}");
        assert_eq!(candidate.shared_physical_bytes, None, "{case}");
    }
}

#[test]
fn partial_producer_withholds_physical_estimates_instead_of_reporting_zero() {
    let (_temp, reports) = store();
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let code = engine
        .run_streaming(
            StreamingScanRequest {
                scan_id: "partial-accounting",
                safety_fingerprint: "safe",
                scope_fingerprint: "scope",
                probe_status: CoverageStatus::Complete,
                cancellation: &AtomicBool::new(false),
                memory_items: 2,
                filesystem_parent_first: false,
            },
            |emit| {
                emit(observation("/p/target", "Cargo.toml"));
                CoverageStatus::Partial
            },
        )
        .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let candidate = &reports.read("partial-accounting").unwrap().candidates[0];
    assert_eq!(candidate.logical_bytes_estimate, None);
    assert_eq!(candidate.physical_bytes_estimate, None);
    assert_eq!(candidate.shared_physical_bytes, None);
}

#[test]
fn partial_root_does_not_withhold_complete_sibling_estimates() {
    let (_temp, reports) = store();
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let code = engine
        .run_streaming(
            StreamingScanRequest {
                scan_id: "root-local-accounting",
                safety_fingerprint: "safe",
                scope_fingerprint: "scope",
                probe_status: CoverageStatus::Complete,
                cancellation: &AtomicBool::new(false),
                memory_items: 4,
                filesystem_parent_first: false,
            },
            |emit| {
                emit(observation("/good/target", "Cargo.toml"));
                emit(observation("/bad/target", "Cargo.toml"));
                ProducerOutcome {
                    coverage: CoverageStatus::Partial,
                    incomplete_roots: BTreeSet::from([Utf8PathBuf::from("/bad")]),
                    global_estimates_incomplete: false,
                }
            },
        )
        .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let report = reports.read("root-local-accounting").unwrap();
    let good = report
        .candidates
        .iter()
        .find(|candidate| matches!(&candidate.identity, ResourceIdentity::Filesystem { path } if path == "/good/target"))
        .unwrap();
    let bad = report
        .candidates
        .iter()
        .find(|candidate| matches!(&candidate.identity, ResourceIdentity::Filesystem { path } if path == "/bad/target"))
        .unwrap();
    assert_eq!(good.logical_bytes_estimate, Some(1));
    assert_eq!(good.physical_bytes_estimate, Some(1));
    assert_eq!(bad.logical_bytes_estimate, None);
    assert_eq!(bad.physical_bytes_estimate, None);
}

#[test]
fn failed_and_partial_detector_coverage_is_order_independent() {
    for (scan_id, statuses) in [
        ("failed-partial", ["failed", "partial"]),
        ("partial-failed", ["partial", "failed"]),
    ] {
        let (_temp, reports) = store();
        let engine = ScanEngine {
            reports: &reports,
            policy: Default::default(),
        };
        let values = statuses.map(|status| {
            let mut value = observation(&format!("/p/{status}/target"), "Cargo.toml");
            value
                .attributes
                .insert("metadata_coverage".into(), status.into());
            value
                .attributes
                .insert("probe_metadata".into(), status.into());
            value
        });
        assert_eq!(
            engine
                .run(ScanRequest {
                    scan_id,
                    safety_fingerprint: "safe",
                    scope_fingerprint: "scope",
                    observations: &values,
                    probe_status: CoverageStatus::Complete,
                    cancellation: &AtomicBool::new(false),
                    memory_items: 4,
                })
                .unwrap(),
            ExitCode::Incomplete
        );
        assert_eq!(
            reports.read(scan_id).unwrap().coverage,
            CoverageStatus::Failed
        );
    }
}

#[test]
fn extent_partition_overflow_fails_closed_without_partial_estimates() {
    let (_temp, reports) = store();
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let code = engine
        .run_streaming(
            StreamingScanRequest {
                scan_id: "extent-spill-overflow",
                safety_fingerprint: "safe",
                scope_fingerprint: "scope",
                probe_status: CoverageStatus::Complete,
                cancellation: &AtomicBool::new(false),
                memory_items: 2,
                filesystem_parent_first: false,
            },
            |emit| {
                emit(observation("/p/target", "Cargo.toml"));
                for index in 0..250_000 {
                    let mut child = observation(&format!("/p/target/file-{index}"), "");
                    child.attributes.insert("device".into(), "7".into());
                    child.attributes.insert("inode".into(), "9".into());
                    emit(child);
                }
                CoverageStatus::Complete
            },
        )
        .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let report = reports.read("extent-spill-overflow").unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("physical extent accounting incomplete"))
    );
    let candidate = &report.candidates[0];
    assert_eq!(candidate.physical_bytes_estimate, None);
    assert_eq!(candidate.shared_physical_bytes, None);
}

#[test]
#[ignore = "million-observation spill/RSS qualification"]
fn million_unique_observations_remain_spill_bounded() {
    let started = Instant::now();
    let (_temp, reports) = store();
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let code = engine
        .run_streaming(
            StreamingScanRequest {
                scan_id: "million-spill",
                safety_fingerprint: "safe",
                scope_fingerprint: "scope",
                probe_status: CoverageStatus::Complete,
                cancellation: &AtomicBool::new(false),
                memory_items: 2,
                filesystem_parent_first: false,
            },
            |emit| {
                emit(observation("/p/target", "Cargo.toml"));
                for index in 0..1_000_000_u64 {
                    emit(observation(&format!("/p/target/file-{index}"), ""));
                }
                CoverageStatus::Complete
            },
        )
        .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let report = reports.read("million-spill").unwrap();
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| candidate.physical_bytes_estimate.is_none())
    );
    let elapsed = started.elapsed();
    let peak = peak_rss_bytes();
    let rss_bound = (physical_memory_bytes() / 4).max(512 * 1024 * 1024);
    eprintln!("million-observation elapsed={elapsed:?} peak_rss={peak} rss_bound={rss_bound}");
    assert!(elapsed < Duration::from_secs(180));
    assert!(peak < rss_bound);
}

fn peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        peak
    } else {
        peak.saturating_mul(1024)
    }
}

fn physical_memory_bytes() -> u64 {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(pages > 0 && page_size > 0);
    (pages as u64).saturating_mul(page_size as u64)
}

#[test]
fn cancellation_interrupts_recursive_descendant_attribution_without_a_report() {
    let (_temp, reports) = store();
    let cancellation = AtomicBool::new(false);
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let result = engine.run_streaming(
        StreamingScanRequest {
            scan_id: "cancel-descendants",
            safety_fingerprint: "safe",
            scope_fingerprint: "scope",
            probe_status: CoverageStatus::Complete,
            cancellation: &cancellation,
            memory_items: 2,
            filesystem_parent_first: false,
        },
        |emit| {
            emit(observation("/p/target", "Cargo.toml"));
            cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
            emit(observation("/p/target/nested.bin", ""));
            CoverageStatus::Partial
        },
    );
    assert!(matches!(result, Err(ReportError::Cancelled)));
    assert!(reports.read("cancel-descendants").is_err());
}

#[test]
fn producer_panic_preserves_previous_report_at_same_scan_id() {
    let (_temp, reports) = store();
    let engine = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    };
    let values = [observation("/p/target", "Cargo.toml")];
    engine
        .run(ScanRequest {
            scan_id: "stable",
            safety_fingerprint: "before",
            scope_fingerprint: "scope",
            observations: &values,
            probe_status: CoverageStatus::Complete,
            cancellation: &AtomicBool::new(false),
            memory_items: 2,
        })
        .unwrap();
    let before = reports.read("stable").unwrap();
    let result = engine.run_streaming(
        StreamingScanRequest {
            scan_id: "stable",
            safety_fingerprint: "after",
            scope_fingerprint: "scope",
            probe_status: CoverageStatus::Complete,
            cancellation: &AtomicBool::new(false),
            memory_items: 2,
            filesystem_parent_first: false,
        },
        |_emit| -> CoverageStatus { panic!("injected producer panic") },
    );
    assert!(matches!(result, Err(ReportError::Internal)));
    let after = reports.read("stable").unwrap();
    assert_eq!(after.scan_id, before.scan_id);
    assert_eq!(after.safety_fingerprint, before.safety_fingerprint);
    assert_eq!(after.scope_fingerprint, before.scope_fingerprint);
    assert_eq!(after.candidates, before.candidates);
}

#[test]
fn oversized_incomplete_report_falls_back_to_bounded_marker() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("small-reports");
    let reports = ReportStore::new(PrivateStore::create(&root).unwrap(), 1024);
    let huge_path = format!("/p/{}/target", "x".repeat(5000));
    let values = [observation(&huge_path, "Cargo.toml")];
    let code = ScanEngine {
        reports: &reports,
        policy: Default::default(),
    }
    .run(ScanRequest {
        scan_id: "bounded-marker",
        safety_fingerprint: "safe",
        scope_fingerprint: "scope",
        observations: &values,
        probe_status: CoverageStatus::Partial,
        cancellation: &AtomicBool::new(false),
        memory_items: 1,
    })
    .unwrap();
    assert_eq!(code, ExitCode::Incomplete);
    let report = reports.read("bounded-marker").unwrap();
    assert!(report.candidates.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|value| value.contains("omitted"))
    );
}
