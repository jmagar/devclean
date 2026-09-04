use camino::{Utf8Path, Utf8PathBuf};
use devclean::metadata::{MetadataFormat, MetadataReader, MetadataRequest, MetadataStatus};
use std::fs;

#[test]
fn valid_cargo_manifest_is_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let path = camino::Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("Cargo.toml");
    fs::write(&path, "[package]\nname=\"x\"\nversion=\"0.1.0\"\n").unwrap();
    let outcome = MetadataReader::development_defaults(1024 * 1024)
        .read(request(&path, 1024 * 1024))
        .unwrap();
    assert_eq!(outcome.status, MetadataStatus::Complete);
}

fn request(path: &Utf8Path, max_bytes: u64) -> MetadataRequest {
    let format = match path.extension() {
        Some("json") => MetadataFormat::Json,
        Some("toml") => MetadataFormat::Toml,
        Some("lock") if path.file_name() == Some("Cargo.lock") => MetadataFormat::Toml,
        _ => MetadataFormat::Text,
    };
    MetadataRequest::development(Utf8PathBuf::from(path), format, max_bytes)
}

#[test]
fn only_allowlisted_metadata_is_read_and_bytes_are_bounded() {
    let tmp = tempfile::tempdir().unwrap();
    let allowed = camino::Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("Cargo.toml");
    let secret = camino::Utf8Path::from_path(tmp.path())
        .unwrap()
        .join(".env");
    fs::write(&allowed, b"123456").unwrap();
    fs::write(&secret, b"SECRET").unwrap();
    let reader = MetadataReader::development_defaults(4);
    let result = reader.read(request(&allowed, 4)).unwrap();
    assert_eq!(result.status, MetadataStatus::Truncated);
    assert_eq!(result.bytes, b"1234");
    assert_eq!(
        reader.read(request(&secret, 4)).unwrap().status,
        MetadataStatus::Unsupported
    );
    assert!(reader.read(request(&secret, 4)).unwrap().bytes.is_empty());
}

#[test]
fn malformed_and_symlink_metadata_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let malformed = root.join("Cargo.toml");
    fs::write(&malformed, b"[[[[[[").unwrap();
    assert_eq!(
        MetadataReader::development_defaults(1024)
            .read(request(&malformed, 1024))
            .unwrap()
            .status,
        MetadataStatus::Malformed
    );
    let real = root.join("real");
    fs::write(&real, b"x=1").unwrap();
    std::os::unix::fs::symlink(&real, root.join("pyproject.toml")).unwrap();
    assert!(
        MetadataReader::development_defaults(1024)
            .read(request(&root.join("pyproject.toml"), 1024))
            .is_err()
    );
}

#[test]
fn deeply_nested_metadata_is_malformed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = camino::Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("package.json");
    fs::write(&path, format!("{}{}", "[".repeat(70), "]".repeat(70))).unwrap();
    assert_eq!(
        MetadataReader::development_defaults(4096)
            .read(request(&path, 4096))
            .unwrap()
            .status,
        MetadataStatus::Malformed
    );
}

#[test]
fn one_line_entry_flood_and_fifo_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let path = root.join("package.json");
    fs::write(
        &path,
        format!(
            "{{{}}}",
            (0..10_100)
                .map(|n| format!("\"k{n}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
    .unwrap();
    assert_eq!(
        MetadataReader::development_defaults(1_000_000)
            .read(request(&path, 1_000_000))
            .unwrap()
            .status,
        MetadataStatus::Malformed
    );
    let fifo = root.join("Cargo.lock");
    let c = std::ffi::CString::new(fifo.as_str()).unwrap();
    unsafe {
        libc::mkfifo(c.as_ptr(), 0o600);
    }
    assert!(
        MetadataReader::development_defaults(1024)
            .read(request(&fifo, 1024))
            .is_err()
    );
}

#[test]
fn declared_format_must_match_name_and_parse_successfully() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    let json = root.join("package.json");
    fs::write(&json, br#"{"key":}"#).unwrap();
    let reader = MetadataReader::development_defaults(1024);
    assert_eq!(
        reader.read(request(&json, 1024)).unwrap().status,
        MetadataStatus::Malformed
    );

    let toml = root.join("Cargo.toml");
    fs::write(&toml, b"not valid ???").unwrap();
    assert_eq!(
        reader.read(request(&toml, 1024)).unwrap().status,
        MetadataStatus::Malformed
    );

    let wrong_format = MetadataRequest::development(json, MetadataFormat::Toml, 1024);
    assert_eq!(
        reader.read(wrong_format).unwrap().status,
        MetadataStatus::Unsupported
    );
}

#[test]
fn request_limits_may_not_exceed_reader_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("package.json");
    fs::write(&path, b"{}").unwrap();
    let mut oversized = request(&path, 5);
    oversized.max_entries = 10_001;
    assert!(
        MetadataReader::development_defaults(4)
            .read(oversized)
            .is_err()
    );
}

#[test]
fn parse_deadline_expiry_is_explicit_and_never_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let path = Utf8Path::from_path(tmp.path())
        .unwrap()
        .join("package.json");
    fs::write(&path, b"{}").unwrap();
    let mut expired = request(&path, 1024);
    expired.max_parse_time = std::time::Duration::ZERO;
    assert_eq!(
        MetadataReader::development_defaults(1024)
            .read(expired)
            .unwrap()
            .status,
        MetadataStatus::ParseTimedOut
    );
}
