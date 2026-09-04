use std::process::Command;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_devclean"))
}

#[test]
fn cli_rejects_unsafe_config_files_without_blocking() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let reports = temp.path().join("reports");

    let huge = temp.path().join("huge.toml");
    let file = std::fs::File::create(&huge).unwrap();
    file.set_len(1024 * 1024 + 1).unwrap();
    assert_eq!(
        command()
            .args([
                "scan",
                huge.to_str().unwrap(),
                reports.to_str().unwrap(),
                "huge"
            ])
            .status()
            .unwrap()
            .code(),
        Some(3)
    );

    let symlink = temp.path().join("link.toml");
    std::os::unix::fs::symlink(&huge, &symlink).unwrap();
    assert_eq!(
        command()
            .args([
                "scan",
                symlink.to_str().unwrap(),
                reports.to_str().unwrap(),
                "link"
            ])
            .status()
            .unwrap()
            .code(),
        Some(3)
    );

    let fifo = temp.path().join("fifo.toml");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert_eq!(
        command()
            .args([
                "scan",
                fifo.to_str().unwrap(),
                reports.to_str().unwrap(),
                "fifo"
            ])
            .status()
            .unwrap()
            .code(),
        Some(3)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn cli_exit_codes_and_read_only_scan_contract() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    let project = canonical.join("project");
    let reports = canonical.join("reports");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(project.join("target")).unwrap();
    std::fs::write(project.join("target/object"), b"bytes").unwrap();
    let before = snapshot(&project);
    let config = canonical.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "approved_roots=['{}']\napproved_caches=[]\nexclusions=[]\n[presentation]\nterminal_rows=1\n",
            project.display()
        ),
    )
    .unwrap();
    let scan = command()
        .args([
            "scan",
            config.to_str().unwrap(),
            reports.to_str().unwrap(),
            "scan-1",
        ])
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(0));
    assert_eq!(
        snapshot(&project),
        before,
        "scan mutated detected resources"
    );
    assert!(reports.join("scan-1.json").is_file());
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(reports.join("scan-1.json")).unwrap()).unwrap();
    let candidate = &stored["candidates"][0];
    let explain = command()
        .args([
            "explain",
            reports.to_str().unwrap(),
            "scan-1",
            candidate["id"].as_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(explain.status.code(), Some(0));
    let explanation = String::from_utf8(explain.stdout).unwrap();
    assert!(explanation.contains("category=Build"));
    assert!(explanation.contains("GeneratedLayout"));
    assert!(explanation.contains("size_provenance=RecursiveFilesystemExtent"));
    assert!(explanation.contains("logical="));
    assert!(explanation.contains("physical="));
    assert!(explanation.contains("shared="));
    let report = command()
        .args(["report", reports.to_str().unwrap(), "scan-1"])
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(0));
    assert!(String::from_utf8(report.stdout).unwrap().contains("target"));
    let export = command()
        .args([
            "report",
            "export",
            "--redacted",
            reports.to_str().unwrap(),
            "scan-1",
        ])
        .output()
        .unwrap();
    assert_eq!(export.status.code(), Some(0));
    assert!(
        String::from_utf8(export.stdout)
            .unwrap()
            .contains("\"usable_for_cleanup\":false")
    );
    assert_eq!(command().arg("bad").status().unwrap().code(), Some(3));
    assert_eq!(
        command()
            .args(["report", reports.to_str().unwrap(), "missing"])
            .status()
            .unwrap()
            .code(),
        Some(4)
    );
    let invalid = canonical.join("invalid.toml");
    std::fs::write(&invalid, "not = [valid").unwrap();
    assert_eq!(
        command()
            .args([
                "scan",
                invalid.to_str().unwrap(),
                reports.to_str().unwrap(),
                "bad"
            ])
            .status()
            .unwrap()
            .code(),
        Some(3)
    );
}

#[test]
fn cli_scan_honors_zero_one_and_many_terminal_rows() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    let project = canonical.join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir(project.join("target")).unwrap();
    for rows in [0, 1, 8] {
        let config = canonical.join(format!("rows-{rows}.toml"));
        let reports = canonical.join(format!("reports-{rows}"));
        std::fs::write(
            &config,
            format!(
                "approved_roots=['{}']\n[presentation]\nterminal_rows={rows}\n",
                project.display()
            ),
        )
        .unwrap();
        let output = command()
            .args([
                "scan",
                config.to_str().unwrap(),
                reports.to_str().unwrap(),
                "scan",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.len() < 4096);
        assert_eq!(
            stdout.contains(project.join("target").to_str().unwrap()),
            rows > 0,
            "rows={rows}: {stdout}"
        );
        assert_eq!(stdout.contains("more candidates"), rows == 0);
    }
}

#[test]
fn cli_scans_cache_only_roots_and_omits_excluded_subtrees() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    let project = canonical.join("project");
    let excluded_target = project.join("target");
    let cache_root = canonical.join("cache-only");
    let cache_candidate = cache_root.join("__pycache__");
    let reports = canonical.join("reports");
    std::fs::create_dir_all(&excluded_target).unwrap();
    std::fs::create_dir_all(&cache_candidate).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='scope-fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::write(excluded_target.join("object.o"), b"excluded").unwrap();
    std::fs::write(cache_candidate.join("module.pyc"), b"cache").unwrap();
    let config = canonical.join("scope.toml");
    std::fs::write(
        &config,
        format!(
            "approved_roots=['{}']\napproved_caches=['{}']\nexclusions=['{}']\n",
            project.display(),
            cache_root.display(),
            excluded_target.display()
        ),
    )
    .unwrap();

    let scan = command()
        .args([
            "scan",
            config.to_str().unwrap(),
            reports.to_str().unwrap(),
            "scope-scan",
        ])
        .output()
        .unwrap();
    assert_eq!(
        scan.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(reports.join("scope-scan.json")).unwrap()).unwrap();
    let paths: Vec<_> = report["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|candidate| candidate["identity"]["path"].as_str())
        .collect();
    assert!(paths.contains(&cache_candidate.to_str().unwrap()));
    assert!(
        !paths
            .iter()
            .any(|path| path.starts_with(excluded_target.to_str().unwrap()))
    );
    assert_eq!(report["coverage"], "complete");
}

#[test]
fn cli_uses_nearest_nested_project_owner_without_marker_leakage() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    let workspace = canonical.join("workspace");
    let nested_rust = workspace.join("rust-app");
    let rust_target = nested_rust.join("target");
    let unrelated_target = workspace.join("unrelated/target");
    let outer = workspace.join("outer");
    let outer_target = outer.join("target");
    let nested_node = outer.join("web");
    let node_modules = nested_node.join("node_modules");
    let nested_wrong_target = nested_node.join("target");
    for directory in [
        &rust_target,
        &unrelated_target,
        &outer_target,
        &node_modules,
        &nested_wrong_target,
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    for project in [&nested_rust, &outer] {
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='nested'\nversion='0.1.0'\n",
        )
        .unwrap();
    }
    std::fs::write(
        nested_node.join("package.json"),
        r#"{"name":"web","version":"1.0.0"}"#,
    )
    .unwrap();
    let config = canonical.join("nested.toml");
    let reports = canonical.join("nested-reports");
    std::fs::write(
        &config,
        format!(
            "approved_roots=['{}']\napproved_caches=[]\nexclusions=[]\n",
            workspace.display()
        ),
    )
    .unwrap();
    let scan = command()
        .args([
            "scan",
            config.to_str().unwrap(),
            reports.to_str().unwrap(),
            "nested-scan",
        ])
        .output()
        .unwrap();
    assert!(
        matches!(scan.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(reports.join("nested-scan.json")).unwrap()).unwrap();
    let paths: Vec<_> = report["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|candidate| candidate["identity"]["path"].as_str())
        .collect();
    assert_eq!(
        scan.status.code() == Some(0),
        report["coverage"] == "complete",
        "exit status must expose incomplete auxiliary coverage"
    );
    assert!(paths.contains(&rust_target.to_str().unwrap()));
    assert!(paths.contains(&outer_target.to_str().unwrap()));
    assert!(paths.contains(&node_modules.to_str().unwrap()));
    assert!(!paths.contains(&unrelated_target.to_str().unwrap()));
    assert!(!paths.contains(&nested_wrong_target.to_str().unwrap()));
}

#[test]
fn cli_preserves_marker_owned_candidate_when_manifest_is_truncated() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(temp.path()).unwrap();
    let project = canonical.join("malformed-project");
    let target = project.join("target");
    let reports = canonical.join("malformed-reports");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(project.join("Cargo.toml"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let config = canonical.join("malformed.toml");
    std::fs::write(
        &config,
        format!("approved_roots=['{}']\n", project.display()),
    )
    .unwrap();
    let scan = command()
        .args([
            "scan",
            config.to_str().unwrap(),
            reports.to_str().unwrap(),
            "malformed-scan",
        ])
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(reports.join("malformed-scan.json")).unwrap())
            .unwrap();
    let candidate = report["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["identity"]["path"] == target.to_str().unwrap())
        .expect("marker-owned target must remain visible");
    assert_eq!(candidate["tier"], "protected");
    assert_ne!(candidate["coverage"], "complete");
}

fn snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    fn visit(path: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        entries.sort_by_key(|v| v.path());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                out.push((path.clone(), vec![]));
                visit(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, &mut out);
    out
}
