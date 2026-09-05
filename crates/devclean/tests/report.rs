use camino::Utf8PathBuf;
use devclean::private_store::PrivateStore;
use devclean::report::*;
use devclean_core::{
    AdvisoryCandidate, ArtifactCategory, Confidence, CoverageStatus, Evidence, EvidenceCode,
    LogicalCandidateId, ResourceFingerprint, ResourceIdentity, SizeProvenance, Tier,
};

fn report(id: &str) -> ScanReportV1 {
    ScanReportV1 {
        schema_version: 1,
        scan_id: id.into(),
        safety_fingerprint: "safe".into(),
        scope_fingerprint: "scope".into(),
        coverage: CoverageStatus::Complete,
        candidates: vec![AdvisoryCandidate {
            id: LogicalCandidateId::derive("test", "owner", "path"),
            identity: ResourceIdentity::Filesystem {
                path: Utf8PathBuf::from("/tmp/\u{1b}]8;;bad\u{7}name\u{202e}.log"),
            },
            fingerprint: ResourceFingerprint::opaque("test", "value"),
            category: ArtifactCategory::Log,
            positive_evidence: vec![Evidence {
                code: EvidenceCode::KnownCache,
                source: "catalog".into(),
                confidence: Confidence::High,
            }],
            tier: Tier::Review,
            protections: vec!["open".into()],
            coverage: CoverageStatus::Complete,
            logical_bytes_estimate: None,
            physical_bytes_estimate: None,
            shared_physical_bytes: None,
            size_provenance: SizeProvenance::RecursiveFilesystemExtent,
        }],
        warnings: vec!["grouped warning".into()],
    }
}

#[test]
fn report_round_trip_is_atomic_private_and_strict() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 64 * 1024);
    let path = store.write(&report("scan-1")).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(store.read("scan-1").unwrap(), report("scan-1"));
    let canonical = std::fs::read_to_string(&path).unwrap();
    assert!(canonical.contains("\"category\":\"log\""));
    assert!(canonical.contains("\"positive_evidence\""));
    assert!(canonical.contains("\"size_provenance\":\"recursive_filesystem_extent\""));
    assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}

#[test]
fn summary_reports_non_overlapping_safe_physical_estimate() {
    let mut value = report("safe-summary");
    let prototype = &value.candidates[0];
    let mut parent = prototype.clone();
    parent.id = LogicalCandidateId::derive("test", "owner", "parent");
    parent.identity = ResourceIdentity::Filesystem {
        path: "/tmp/project/target".into(),
    };
    parent.tier = Tier::Safe;
    parent.physical_bytes_estimate = Some(100);
    let mut child = parent.clone();
    child.id = LogicalCandidateId::derive("test", "owner", "child");
    child.identity = ResourceIdentity::Filesystem {
        path: "/tmp/project/target/debug".into(),
    };
    child.physical_bytes_estimate = Some(75);
    let mut sibling = parent.clone();
    sibling.id = LogicalCandidateId::derive("test", "owner", "sibling");
    sibling.identity = ResourceIdentity::Filesystem {
        path: "/tmp/project/.cache".into(),
    };
    sibling.physical_bytes_estimate = Some(25);
    value.candidates = vec![child, sibling, parent];

    let rendered = render_summary(&value, 0, false);
    assert!(rendered.contains("safe reclaimable estimate\tphysical=125\tcandidates=2\tunknown=0"));
}

#[test]
fn fallible_spool_errors_are_typed_and_preserve_prior_report() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 64 * 1024);
    let prior = report("stable");
    store.write(&prior).unwrap();
    let header = ScanReportHeader {
        scan_id: "stable".into(),
        safety_fingerprint: "safe".into(),
        scope_fingerprint: "scope".into(),
        coverage: CoverageStatus::Complete,
        warnings: vec![],
    };
    let malformed = store.write_streaming_fallible_cancellable(
        &header,
        [Err(ReportError::Malformed)],
        1,
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(matches!(malformed, Err(ReportError::Malformed)));
    assert_eq!(store.read("stable").unwrap(), prior);

    let injected_io = store.write_streaming_fallible_cancellable(
        &header,
        [Err(ReportError::Store(
            devclean::private_store::StoreError::Io(std::io::Error::other("injected spool read")),
        ))],
        1,
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(matches!(injected_io, Err(ReportError::Store(_))));
    assert_eq!(store.read("stable").unwrap(), prior);
}

#[test]
fn huge_memory_items_still_flushes_at_internal_chunk_cap_and_writes_all_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 16 * 1024 * 1024);
    let prototype = report("prototype").candidates.remove(0);
    let candidates = (0..5000)
        .rev()
        .map(|index| {
            let mut candidate = prototype.clone();
            candidate.id = LogicalCandidateId::derive("bounded", "owner", &index.to_string());
            candidate
        })
        .collect::<Vec<_>>();
    let header = ScanReportHeader {
        scan_id: "huge-memory-items".into(),
        safety_fingerprint: "safe".into(),
        scope_fingerprint: "scope".into(),
        coverage: CoverageStatus::Complete,
        warnings: vec![],
    };
    store
        .write_streaming(&header, candidates, usize::MAX)
        .unwrap();
    let stored = store.read("huge-memory-items").unwrap();
    assert_eq!(stored.candidates.len(), 5000);
    assert!(
        stored
            .candidates
            .windows(2)
            .all(|pair| pair[0].id <= pair[1].id)
    );
}

#[test]
fn strict_parser_rejects_duplicates_trailing_versions_and_truncation() {
    let valid = serde_json::to_vec(&report("scan-1")).unwrap();
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b" {}");
    assert!(matches!(
        parse_strict(&trailing),
        Err(ReportError::TrailingData)
    ));
    let duplicate = br#"{"schema_version":1,"schema_version":1,"scan_id":"x","safety_fingerprint":"s","scope_fingerprint":"p","coverage":"complete","candidates":[],"warnings":[]}"#;
    assert!(matches!(
        parse_strict(duplicate),
        Err(ReportError::Malformed)
    ));
    let unsupported = String::from_utf8(valid).unwrap().replacen(
        "\"schema_version\":1",
        "\"schema_version\":2",
        1,
    );
    assert!(matches!(
        parse_strict(unsupported.as_bytes()),
        Err(ReportError::UnsupportedVersion(2))
    ));
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 8);
    assert!(store.write(&report("scan-1")).is_err());
    assert!(!root.join("scan-1.json").exists());
}

#[test]
fn latest_requires_one_compatible_report() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 64 * 1024);
    store.write(&report("a")).unwrap();
    store.write(&report("b")).unwrap();
    assert!(matches!(
        store.latest_compatible(["a", "b"], "safe", "scope"),
        Err(ReportError::AmbiguousLatest)
    ));
    assert_eq!(
        store
            .latest_compatible(["a"], "safe", "scope")
            .unwrap()
            .scan_id,
        "a"
    );
    assert!(matches!(
        store.latest_compatible(["a"], "other", "scope"),
        Err(ReportError::NotFound)
    ));
}

#[test]
fn terminal_output_is_bounded_and_control_safe() {
    let mut source = report("scan-1");
    source.warnings = vec!["warning\u{1b}]8;;bad\u{7}".into()];
    let output = render_summary(&source, 1, false);
    assert!(!output.contains('\u{1b}'));
    assert!(!output.contains('\u{7}'));
    assert!(!output.contains('\u{202e}'));
    assert!(output.contains("\\u{1b}"));
    assert!(!output.contains("interactive:"));
    assert!(output.contains("warning: warning\\u{1b}"));
    assert!(!output.contains('\u{1b}'));
    assert!(render_summary(&source, 0, false).contains("1 more candidates"));
    assert!(!render_summary(&source, 2, false).contains("more candidates"));
    let mut many = report("many");
    many.candidates.extend(many.candidates.clone());
    assert!(render_summary(&many, 1, true).contains("1 more candidates"));
}

#[test]
fn redacted_export_omits_paths_and_is_unusable_for_cleanup() {
    let source = report("secret-scan");
    let mut bytes = Vec::new();
    write_redacted(&source, &mut bytes).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"usable_for_cleanup\":false"));
    assert!(text.contains("candidate-"));
    assert!(!text.contains("secret-scan"));
    assert!(!text.contains("/tmp/"));
    assert!(!text.contains("positive_evidence"));
    assert!(!text.contains("size_provenance"));
}

#[test]
fn redaction_and_terminal_output_sanitize_untrusted_protections_stably() {
    let mut first = report("one");
    first.candidates[0].protections = vec!["active".into(), "secret\u{1b}]8;;endpoint\u{7}".into()];
    let mut second = first.clone();
    second.scan_id = "two".into();
    let mut a = Vec::new();
    let mut b = Vec::new();
    write_redacted(&first, &mut a).unwrap();
    write_redacted(&second, &mut b).unwrap();
    assert_eq!(a, b);
    let export = String::from_utf8(a).unwrap();
    assert!(export.contains("active"));
    assert!(!export.contains("secret"));
    assert!(!export.contains("endpoint"));
    let terminal = render_summary(&first, 1, false);
    assert!(!terminal.contains('\u{1b}'));
    assert!(!terminal.contains('\u{7}'));
    assert!(
        explain_candidate(&first, &first.candidates[0].id)
            .unwrap()
            .contains("\\u{1b}")
    );
}

#[test]
fn safe_candidate_explanation_includes_bounded_positive_evidence_and_size_provenance() {
    let mut source = report("explain");
    source.candidates[0].tier = Tier::Safe;
    source.candidates[0].logical_bytes_estimate = Some(100);
    source.candidates[0].physical_bytes_estimate = Some(80);
    source.candidates[0].shared_physical_bytes = Some(20);
    source.candidates[0].positive_evidence[0].source = "catalog\u{1b}]8;;bad\u{7}".into();
    let id = source.candidates[0].id.clone();
    let output = explain_candidate(&source, &id).unwrap();
    assert!(output.contains("tier=Safe category=Log"));
    assert!(output.contains("KnownCache:catalog"));
    assert!(output.contains("logical=100 physical=80 shared=20"));
    assert!(output.contains("size_provenance=RecursiveFilesystemExtent"));
    assert!(!output.contains('\u{1b}'));
    assert!(!output.contains('\u{7}'));
}

#[test]
fn checked_schema_matches_v1_contract() {
    let schema = scan_report_v1_schema();
    assert_eq!(schema["properties"]["schema_version"]["minimum"], 1);
    assert_eq!(schema["properties"]["schema_version"]["maximum"], 1);
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema.to_string().contains("filesystem"));
    assert!(schema.to_string().contains("protections"));
    assert!(schema.to_string().contains("fingerprint"));
    assert!(schema.to_string().contains("tier"));
    assert!(schema.to_string().contains("logical_bytes_estimate"));
    assert!(schema.to_string().contains("physical_bytes_estimate"));
    assert!(schema.to_string().contains("shared_physical_bytes"));
    assert!(schema.to_string().contains("positive_evidence"));
    assert!(schema.to_string().contains("size_provenance"));
    assert!(schema.to_string().contains("category"));
    for field in [
        "schema_version",
        "scan_id",
        "safety_fingerprint",
        "scope_fingerprint",
        "coverage",
        "candidates",
        "warnings",
    ] {
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == field)
        );
    }
}

#[test]
#[ignore = "Task 10 large external JSON qualification"]
fn external_sort_and_streaming_selectors_handle_reports_over_memory_threshold() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let store = ReportStore::new(PrivateStore::create(&root).unwrap(), 32 * 1024 * 1024);
    let candidates: Vec<_> = (0..10_000)
        .rev()
        .map(|index| AdvisoryCandidate {
            id: LogicalCandidateId::derive("bulk", "owner", &index.to_string()),
            identity: ResourceIdentity::Filesystem {
                path: format!("/bulk/{index}").into(),
            },
            fingerprint: ResourceFingerprint::opaque("bulk", &index.to_string()),
            category: ArtifactCategory::Cache,
            positive_evidence: vec![],
            tier: Tier::Review,
            protections: vec![],
            coverage: CoverageStatus::Complete,
            logical_bytes_estimate: None,
            physical_bytes_estimate: None,
            shared_physical_bytes: None,
            size_provenance: SizeProvenance::RecursiveFilesystemExtent,
        })
        .collect();
    let wanted = candidates[4321].id.clone();
    let header = ScanReportHeader {
        scan_id: "bulk".into(),
        safety_fingerprint: "safe".into(),
        scope_fingerprint: "scope".into(),
        coverage: CoverageStatus::Complete,
        warnings: vec![],
    };
    store.write_streaming(&header, candidates, 128).unwrap();
    let summary = store.stream_summary("bulk").unwrap();
    assert_eq!(summary.candidate_count, 10_000);
    assert_eq!(
        store.stream_explain("bulk", &wanted).unwrap().unwrap().id,
        wanted
    );
    assert_eq!(
        store
            .select_summary(ReportSelector::Latest {
                ids: vec!["bulk"],
                safety: "safe",
                scope: "scope"
            })
            .unwrap(),
        summary
    );
    let loaded = store.read("bulk").unwrap();
    assert!(
        loaded
            .candidates
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    );
}

#[test]
fn report_reads_reject_truncated_symlink_hardlink_and_loose_mode_files() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let private = PrivateStore::create(&root).unwrap();
    private.create_new("truncated.json", b"{").unwrap();
    let store = ReportStore::new(private.clone(), 64 * 1024);
    assert!(store.read("truncated").is_err());
    std::fs::write(root.join("target"), b"{}").unwrap();
    symlink(root.join("target"), root.join("link.json")).unwrap();
    assert!(store.read("link").is_err());
    std::fs::hard_link(root.join("target"), root.join("hard.json")).unwrap();
    assert!(store.read("hard").is_err());
    std::fs::write(root.join("loose.json"), b"{}").unwrap();
    std::fs::set_permissions(
        root.join("loose.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(store.read("loose").is_err());
}

#[test]
fn streaming_paths_enforce_full_header_invariants() {
    let temp = tempfile::tempdir().unwrap();
    let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .join("reports");
    let private = PrivateStore::create(&root).unwrap();
    private.create_new("bad.json", br#"{"schema_version":1,"scan_id":"","safety_fingerprint":"","scope_fingerprint":"","coverage":"complete","candidates":[],"warnings":[]}"#).unwrap();
    let store = ReportStore::new(private, 64 * 1024);
    assert!(store.stream_summary("bad").is_err());
    let bad = ScanReportHeader {
        scan_id: "new".into(),
        safety_fingerprint: "".into(),
        scope_fingerprint: "scope".into(),
        coverage: CoverageStatus::Complete,
        warnings: vec![],
    };
    assert!(store.write_streaming(&bad, Vec::new(), 1).is_err());
}

use std::os::unix::fs::PermissionsExt;
