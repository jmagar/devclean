use devclean_core::{PermitKind, WorkPool};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[test]
fn one_pool_enforces_total_and_subsystem_limits() {
    let pool = Arc::new(WorkPool::new(
        2,
        BTreeMap::from([
            (PermitKind::Filesystem, 1),
            (PermitKind::Detector, 1),
            (PermitKind::Subprocess, 1),
            (PermitKind::Docker, 1),
        ]),
    ));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut threads = vec![];
    for kind in [
        PermitKind::Filesystem,
        PermitKind::Filesystem,
        PermitKind::Detector,
        PermitKind::Subprocess,
    ] {
        let pool = pool.clone();
        let active = active.clone();
        let peak = peak.clone();
        threads.push(std::thread::spawn(move || {
            let _permit = pool.acquire(kind, || false).unwrap();
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(10));
            active.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(peak.load(Ordering::SeqCst) <= 2);

    let cancelled = AtomicBool::new(true);
    assert!(
        pool.acquire(PermitKind::Docker, || cancelled.load(Ordering::Relaxed))
            .is_none()
    );
}
