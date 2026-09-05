use devclean::activity::{ActivityCollector, ActivityStatus, snapshot_lsof, snapshot_lsof_bounded};
use devclean::command::{CommandRunner, CommandSpec};
use devclean_core::{PermitKind, WorkPool};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn pool() -> WorkPool {
    WorkPool::new(1, BTreeMap::from([(PermitKind::Subprocess, 1)]))
}

fn shell(script: &str, limit: usize) -> CommandSpec {
    CommandSpec {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: "/tmp".into(),
        timeout: Duration::from_millis(500),
        output_limit: limit,
    }
}

#[test]
fn activity_snapshot_filters_to_scope_and_matches_prefixes() {
    let pool = pool();
    let cancellation = AtomicBool::new(false);
    let snapshot = snapshot_lsof(
        &CommandRunner,
        &shell(
            "printf 'p1\\0n/tmp/project/target/file\\0n/private/secret\\0'",
            1024,
        ),
        &["/tmp/project".into()],
        &pool,
        &cancellation,
    )
    .unwrap();
    assert_eq!(snapshot.status, ActivityStatus::Complete);
    assert_eq!(snapshot.records_seen, 2);
    assert!(
        snapshot
            .index
            .matches_prefix(camino::Utf8Path::new("/tmp/project/target"))
    );
    assert!(
        !snapshot
            .index
            .matches_prefix(camino::Utf8Path::new("/private"))
    );
}

#[test]
fn active_ancestor_does_not_protect_an_unopened_descendant() {
    let pool = pool();
    let cancellation = AtomicBool::new(false);
    let snapshot = snapshot_lsof(
        &CommandRunner,
        &shell("printf 'p1\\0n/tmp/project\\0'", 1024),
        &["/tmp/project".into()],
        &pool,
        &cancellation,
    )
    .unwrap();

    assert!(
        snapshot
            .index
            .matches_prefix(camino::Utf8Path::new("/tmp/project"))
    );
    assert!(
        !snapshot
            .index
            .matches_prefix(camino::Utf8Path::new("/tmp/project/target"))
    );
}

#[test]
fn activity_failures_are_typed() {
    let pool = pool();
    let cancellation = AtomicBool::new(false);
    let timed = snapshot_lsof(
        &CommandRunner,
        &shell("sleep 2", 1024),
        &["/tmp".into()],
        &pool,
        &cancellation,
    )
    .unwrap();
    assert_eq!(timed.status, ActivityStatus::TimedOut);
    let truncated = snapshot_lsof(
        &CommandRunner,
        &shell("printf 'n/tmp/very-long-path'", 4),
        &["/tmp".into()],
        &pool,
        &cancellation,
    )
    .unwrap();
    assert_eq!(truncated.status, ActivityStatus::Truncated);
}

#[test]
fn activity_is_snapshotted_only_once_per_collector() {
    let mut collector = ActivityCollector::default();
    let first = collector
        .snapshot_once(
            &CommandRunner,
            &shell("printf 'n/tmp/project/file\\0'", 1024),
            &["/tmp".into()],
        )
        .unwrap();
    let second = collector
        .snapshot_once(&CommandRunner, &shell("sleep 2", 1024), &["/tmp".into()])
        .unwrap();
    assert_eq!(first.status, ActivityStatus::Complete);
    assert_eq!(second.status, ActivityStatus::Complete);
    assert_eq!(second.records_seen, 1);
}

#[test]
fn activity_index_overflow_is_visible_as_truncation() {
    let pool = pool();
    let cancellation = AtomicBool::new(false);
    let snapshot = snapshot_lsof_bounded(
        &CommandRunner,
        &shell("printf 'n/tmp/a\\0n/tmp/b\\0'", 1024),
        &["/tmp".into()],
        1,
        &pool,
        &cancellation,
    )
    .unwrap();
    assert_eq!(snapshot.status, ActivityStatus::Truncated);
    assert!(snapshot.index.overflow.is_some());
}
