use devclean_core::{
    Observation, ObservationRouter, ResourceFingerprint, ResourceIdentity, RouteInterest,
    ScanMetrics,
};
use std::collections::BTreeMap;

fn observation(path: String) -> Observation {
    Observation {
        identity: ResourceIdentity::Filesystem { path: path.into() },
        fingerprint: ResourceFingerprint::opaque("stress", "constant"),
        logical_bytes: Some(1),
        allocated_bytes: Some(1),
        attributes: BTreeMap::new(),
    }
}

#[test]
#[ignore = "Task 10 million-observation qualification"]
fn million_ordinary_and_candidate_like_observations_remain_streamed() {
    let mut router = ObservationRouter::default();
    router.register("rust", [RouteInterest::Basename("target".into())]);
    let mut metrics = ScanMetrics::default();
    let mut matches = 0u64;
    for index in 0..1_000_000 {
        matches += router
            .route(
                &observation(format!("/scope/ordinary-{index}")),
                &mut metrics,
            )
            .len() as u64;
    }
    assert_eq!(matches, 0);
    for index in 0..1_000_000 {
        matches += router
            .route(
                &observation(format!("/scope/project-{index}/target")),
                &mut metrics,
            )
            .len() as u64;
    }
    assert_eq!(matches, 1_000_000);
    assert_eq!(metrics.detector_visits, 1_000_000);
    assert_eq!(metrics.route_lookups, 4_000_000);
}
