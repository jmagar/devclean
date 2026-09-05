use camino::Utf8PathBuf;
use devclean::detectors::{CatalogDetector, MetadataProbeCache};
use devclean_core::{
    CoverageStatus, Detector, DetectorContext, ProtectionSignal, ResourceFingerprint,
    ResourceIdentity,
};
use std::collections::BTreeMap;

fn observation(path: &str, markers: &str) -> devclean_core::Observation {
    devclean_core::Observation {
        identity: ResourceIdentity::Filesystem {
            path: Utf8PathBuf::from(path),
        },
        fingerprint: ResourceFingerprint::opaque("test", path),
        logical_bytes: Some(1),
        allocated_bytes: Some(1),
        attributes: BTreeMap::from([
            ("project_owner".into(), "/work/project".into()),
            ("markers".into(), markers.into()),
            ("metadata_coverage".into(), "complete".into()),
            ("known_cache".into(), "true".into()),
            ("known_log".into(), "true".into()),
        ]),
    }
}

#[test]
fn every_detector_family_has_a_positive_fixture() {
    let fixtures = [
        ("/p/target", "Cargo.toml", "Rust"),
        ("/p/__pycache__", "", "Python"),
        ("/p/node_modules", "package.json", "Node"),
        ("/p/_build", "mix.exs", "ElixirErlang"),
        ("/p/go-build", "go.mod", "Go"),
        ("/p/.gradle", "build.gradle", "JvmAndroid"),
        ("/p/DerivedData", "", "Apple"),
        ("/p/playwright-report", "package.json", "BrowserTest"),
        ("/p/.codex", "", "EditorAgent"),
        ("/p/run.log", "", "LogsDiagnostics"),
        ("/p/cache.zip", "", "General"),
    ];
    let detector = CatalogDetector::default();
    for (path, markers, family) in fixtures {
        let observations = [observation(path, markers)];
        let outcome = detector.detect(DetectorContext {
            observations: &observations,
            artifact_limit: 10,
        });
        assert_eq!(outcome.coverage, CoverageStatus::Complete, "{path}");
        assert_eq!(outcome.artifacts.len(), 1, "{path}");
        assert_eq!(outcome.artifacts[0].evidence[0].source, family);
    }
}

#[test]
fn ambiguous_names_require_the_correct_owner_marker() {
    let detector = CatalogDetector::default();
    for name in ["target", "build", "dist", "deps", "venv", "tmp", "logs"] {
        let observations = [observation(&format!("/ordinary/{name}"), "wrong.marker")];
        let outcome = detector.detect(DetectorContext {
            observations: &observations,
            artifact_limit: 10,
        });
        assert!(outcome.artifacts.is_empty(), "false positive for {name}");
    }
    for path in [
        "/p/cargo-target",
        "/p/pycache",
        "/p/node-modules",
        "/p/elixir-build",
        "/p/golang-cache",
        "/p/gradle-cache",
        "/p/XcodeData",
        "/p/browser-results",
        "/p/agent-state",
        "/p/logbook",
        "/p/archive.txt",
    ] {
        let observations = [observation(
            path,
            "Cargo.toml,pyproject.toml,package.json,mix.exs,go.mod,build.gradle",
        )];
        assert!(
            detector
                .detect(DetectorContext {
                    observations: &observations,
                    artifact_limit: 10
                })
                .artifacts
                .is_empty(),
            "false positive for {path}"
        );
    }
}

#[test]
fn markerless_cache_and_log_names_require_known_ownership() {
    let detector = CatalogDetector::default();
    for path in [
        "/ordinary/__pycache__",
        "/ordinary/DerivedData",
        "/ordinary/ms-playwright",
        "/ordinary/file.log",
    ] {
        let mut value = observation(path, "");
        value.attributes.remove("known_cache");
        value.attributes.remove("known_log");
        let outcome = detector.detect(DetectorContext {
            observations: &[value],
            artifact_limit: 10,
        });
        assert!(outcome.artifacts.is_empty(), "false positive for {path}");
    }
}

#[test]
fn nested_node_modules_contents_are_not_independent_cleanup_candidates() {
    let detector = CatalogDetector::default();
    for path in [
        "/work/project/node_modules/pkg/dist",
        "/work/project/node_modules/.pnpm/pkg/node_modules",
        "/work/project/node_modules/pkg/cache.log",
    ] {
        let value = observation(path, "package.json");
        assert!(!CatalogDetector::is_filesystem_candidate(
            camino::Utf8Path::new(path)
        ));
        assert!(
            detector
                .detect(DetectorContext {
                    observations: &[value],
                    artifact_limit: 10,
                })
                .artifacts
                .is_empty(),
            "nested dependency artifact escaped: {path}"
        );
    }
}

#[test]
fn explicitly_approved_cache_roots_do_not_keep_unknown_ownership_protection() {
    let detector = CatalogDetector::default();
    for path in [
        "/home/user/.npm",
        "/home/user/.cargo/registry",
        "/home/user/Library/Caches",
    ] {
        let mut value = observation(path, "");
        value
            .attributes
            .insert("approved_cache_root".into(), "true".into());
        let outcome = detector.detect(DetectorContext {
            observations: &[value],
            artifact_limit: 10,
        });
        assert_eq!(outcome.artifacts.len(), 1, "{path}");
        assert!(
            !outcome.artifacts[0]
                .protection_signals
                .contains(&ProtectionSignal::UnknownOwnership),
            "{path}"
        );
    }
}

#[test]
fn rebuildable_project_caches_do_not_keep_unknown_ownership_protection() {
    let detector = CatalogDetector::default();
    let mut value = observation("/work/project/.cache", "Cargo.toml");
    value
        .attributes
        .insert("probe_rebuildability".into(), "complete".into());
    let outcome = detector.detect(DetectorContext {
        observations: &[value],
        artifact_limit: 10,
    });

    assert_eq!(outcome.artifacts.len(), 1);
    assert!(
        !outcome.artifacts[0]
            .protection_signals
            .contains(&ProtectionSignal::UnknownOwnership)
    );
}

#[test]
fn unproven_project_caches_remain_unknown_ownership() {
    let detector = CatalogDetector::default();
    let value = observation("/work/project/.cache", "Cargo.toml");
    let outcome = detector.detect(DetectorContext {
        observations: &[value],
        artifact_limit: 10,
    });

    assert_eq!(outcome.artifacts.len(), 1);
    assert!(
        outcome.artifacts[0]
            .protection_signals
            .contains(&ProtectionSignal::UnknownOwnership)
    );
}

#[test]
fn unreferenced_docker_images_require_reference_evidence_but_not_rebuildability() {
    let detector = CatalogDetector::default();
    let value = devclean_core::Observation {
        identity: ResourceIdentity::Docker {
            daemon: "engine".into(),
            object_kind: "image".into(),
            id: "sha256:fixture".into(),
        },
        fingerprint: ResourceFingerprint::opaque("docker", "fixture"),
        logical_bytes: Some(1024),
        allocated_bytes: Some(1024),
        attributes: BTreeMap::from([
            ("probe_docker_snapshot".into(), "complete".into()),
            ("probe_docker_references".into(), "complete".into()),
            ("probe_rebuildability".into(), "unknown".into()),
        ]),
    };
    let outcome = detector.detect(DetectorContext {
        observations: &[value],
        artifact_limit: 10,
    });
    assert_eq!(outcome.artifacts.len(), 1);
    assert!(
        !outcome.artifacts[0]
            .required_probes
            .0
            .contains(&devclean_core::ProbeKind::Rebuildability)
    );
}

#[test]
fn metadata_failure_is_visible_and_requires_metadata_probe() {
    let detector = CatalogDetector::default();
    let mut value = observation("/p/target", "Cargo.toml");
    value
        .attributes
        .insert("metadata_coverage".into(), "failed".into());
    let outcome = detector.detect(DetectorContext {
        observations: &[value],
        artifact_limit: 10,
    });
    assert_eq!(outcome.coverage, CoverageStatus::Failed);
    assert_eq!(outcome.artifacts.len(), 1);
    let detector = CatalogDetector::default();
    let value = observation("/p/target", "Cargo.toml");
    let outcome = detector.detect(DetectorContext {
        observations: &[value],
        artifact_limit: 10,
    });
    assert!(
        outcome.artifacts[0]
            .required_probes
            .0
            .contains(&devclean_core::ProbeKind::Metadata)
    );
}

#[test]
fn every_non_complete_metadata_state_is_visible() {
    for (raw, expected) in [
        ("unsupported", CoverageStatus::Unsupported),
        ("skipped", CoverageStatus::Skipped),
        ("partial", CoverageStatus::Partial),
        ("failed", CoverageStatus::Failed),
        ("timed_out", CoverageStatus::TimedOut),
        ("truncated", CoverageStatus::Truncated),
        ("stale", CoverageStatus::Stale),
        ("unknown", CoverageStatus::Unknown),
        ("malformed", CoverageStatus::Unknown),
    ] {
        let mut value = observation("/p/target", "Cargo.toml");
        value
            .attributes
            .insert("metadata_coverage".into(), raw.into());
        let outcome = CatalogDetector::default().detect(DetectorContext {
            observations: &[value],
            artifact_limit: 10,
        });
        assert_eq!(outcome.coverage, expected, "{raw}");
        assert_eq!(outcome.artifacts.len(), 1, "{raw}");
    }
    let mut missing = observation("/p/target", "Cargo.toml");
    missing.attributes.remove("metadata_coverage");
    assert_eq!(
        CatalogDetector::default()
            .detect(DetectorContext {
                observations: &[missing],
                artifact_limit: 10
            })
            .coverage,
        CoverageStatus::Unknown
    );
}

#[test]
fn expanded_tool_cache_catalog_has_positive_coverage() {
    for (path, markers) in [
        ("/p/registry", ""),
        ("/p/toolchains", ""),
        ("/p/incremental", "Cargo.toml"),
        ("/p/pip", ""),
        ("/p/uv", ""),
        ("/p/.eggs", "pyproject.toml"),
        ("/p/.npm", ""),
        ("/p/mod", ""),
        ("/p/testcache", "go.mod"),
        ("/p/sdk", ""),
        ("/p/avd", ""),
        ("/p/iOS DeviceSupport", ""),
        ("/p/lsp", ""),
        ("/p/CrashReporter", ""),
        ("/p/profiles", "generated"),
        ("/p/benchmarks", "generated"),
        ("/p/doc", "generated"),
    ] {
        let value = observation(path, markers);
        let outcome = CatalogDetector::default().detect(DetectorContext {
            observations: &[value],
            artifact_limit: 10,
        });
        assert_eq!(outcome.artifacts.len(), 1, "missing {path}");
    }
}

#[test]
fn build_shards_are_independent_candidates_with_activity_fences() {
    let detector = CatalogDetector::default();
    let mut active = observation(
        "/work/project/target/debug/incremental/live-crate",
        "Cargo.toml",
    );
    active.attributes.insert("active".into(), "true".into());
    active.attributes.insert("open".into(), "true".into());
    let idle = observation(
        "/work/project/target/debug/incremental/idle-crate",
        "Cargo.toml",
    );
    let mix = observation("/work/project/_build/test", "mix.exs");
    let values = [active, idle, mix];
    let outcome = detector.detect(DetectorContext {
        observations: &values,
        artifact_limit: 10,
    });

    assert_eq!(outcome.artifacts.len(), 3);
    assert!(
        outcome.artifacts[0]
            .protection_signals
            .contains(&ProtectionSignal::Active)
    );
    assert!(
        outcome.artifacts[0]
            .protection_signals
            .contains(&ProtectionSignal::OpenFile)
    );
    assert!(outcome.artifacts[1].protection_signals.is_empty());
    assert!(outcome.artifacts[2].protection_signals.is_empty());
}

#[test]
fn active_recent_failed_stateful_and_irreplaceable_artifacts_are_protected() {
    let detector = CatalogDetector::default();
    let mut values = vec![
        observation("/p/run.log", ""),
        observation("/p/results.dump", ""),
        observation("/p/data.sqlite", ""),
        observation("/p/archive.tar", ""),
        observation("/p/CoreSimulator", ""),
    ];
    values[0].attributes.insert("open".into(), "true".into());
    values[0].attributes.insert("recent".into(), "true".into());
    for attribute in [
        "active",
        "failed_test",
        "retained",
        "required_sdk",
        "dirty",
        "untracked",
        "shared",
    ] {
        values[0].attributes.insert(attribute.into(), "true".into());
    }
    let outcome = detector.detect(DetectorContext {
        observations: &values,
        artifact_limit: 20,
    });
    let signals: Vec<_> = outcome
        .artifacts
        .iter()
        .flat_map(|a| a.protection_signals.iter())
        .collect();
    for expected in [
        ProtectionSignal::OpenFile,
        ProtectionSignal::UniqueState,
        ProtectionSignal::Database,
        ProtectionSignal::Archive,
        ProtectionSignal::Active,
        ProtectionSignal::Dirty,
        ProtectionSignal::Untracked,
        ProtectionSignal::UnknownOwnership,
    ] {
        assert!(signals.contains(&&expected), "missing {expected:?}");
    }
}

#[test]
fn metadata_probes_are_coalesced_and_failures_are_memoized() {
    let cache = MetadataProbeCache::default();
    let mut calls = 0;
    for _ in 0..100 {
        let value = cache
            .get_or_probe("owner", "node", || {
                calls += 1;
                Ok::<_, String>(42)
            })
            .unwrap();
        assert_eq!(value, 42);
    }
    assert_eq!(calls, 1);
    let failures: MetadataProbeCache<()> = MetadataProbeCache::default();
    let mut failure_calls = 0;
    for _ in 0..100 {
        assert!(
            failures
                .get_or_probe("owner", "broken", || {
                    failure_calls += 1;
                    Err("layout drift".into())
                })
                .is_err()
        );
    }
    assert_eq!(failure_calls, 1);
}

#[test]
fn metadata_probe_in_flight_calls_are_coalesced() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let cache = Arc::new(MetadataProbeCache::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let calls = Arc::clone(&calls);
            std::thread::spawn(move || {
                cache
                    .get_or_probe("owner", "rust", || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::thread::yield_now();
                        Ok::<_, String>(7)
                    })
                    .unwrap()
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), 7);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn artifact_limit_is_visible_as_truncated_coverage() {
    let values = [observation("/p/a.log", ""), observation("/p/b.log", "")];
    let outcome = CatalogDetector::default().detect(DetectorContext {
        observations: &values,
        artifact_limit: 1,
    });
    assert_eq!(outcome.coverage, CoverageStatus::Truncated);
    assert!(outcome.overflow.is_some());
}
