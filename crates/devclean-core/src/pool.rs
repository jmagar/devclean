use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PermitKind {
    Filesystem,
    Detector,
    Subprocess,
    Docker,
}

#[derive(Debug)]
struct State {
    total: usize,
    by_kind: BTreeMap<PermitKind, usize>,
}

#[derive(Debug)]
pub struct WorkPool {
    total_limit: usize,
    limits: BTreeMap<PermitKind, usize>,
    state: Mutex<State>,
    ready: Condvar,
}

impl WorkPool {
    pub fn new(total_limit: usize, limits: BTreeMap<PermitKind, usize>) -> Self {
        assert!(total_limit > 0);
        Self {
            total_limit,
            limits,
            state: Mutex::new(State {
                total: 0,
                by_kind: BTreeMap::new(),
            }),
            ready: Condvar::new(),
        }
    }

    pub fn acquire(
        &self,
        kind: PermitKind,
        cancelled: impl Fn() -> bool,
    ) -> Option<WorkPermit<'_>> {
        let limit = self.limits.get(&kind).copied().unwrap_or(0);
        if limit == 0 {
            return None;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if cancelled() {
                return None;
            }
            if state.total < self.total_limit
                && state.by_kind.get(&kind).copied().unwrap_or(0) < limit
            {
                state.total += 1;
                *state.by_kind.entry(kind).or_default() += 1;
                return Some(WorkPermit { pool: self, kind });
            }
            state = self
                .ready
                .wait_timeout(state, Duration::from_millis(5))
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }

    fn release(&self, kind: PermitKind) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.total -= 1;
        *state.by_kind.get_mut(&kind).expect("held permit kind") -= 1;
        self.ready.notify_one();
    }
}

pub struct WorkPermit<'a> {
    pool: &'a WorkPool,
    kind: PermitKind,
}

impl Drop for WorkPermit<'_> {
    fn drop(&mut self) {
        self.pool.release(self.kind);
    }
}
