use crate::detectors::CatalogDetector;
use crate::report::{ReportError, ReportStore, ScanReportHeader};
use crate::spill::FileInodeSpill;
use devclean_core::{
    BudgetKind, CandidateSink, CoverageMap, CoverageStatus, Detector, DetectorContext,
    LogicalCandidateId, Observation, PhysicalAccounting, PhysicalExtent, Policy, ResourceIdentity,
    ScanBudget, ScanMetrics, classify,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ExitCode {
    Complete = 0,
    Incomplete = 2,
    ConfigInvalid = 3,
    Internal = 4,
}

pub struct ScanRequest<'a> {
    pub scan_id: &'a str,
    pub safety_fingerprint: &'a str,
    pub scope_fingerprint: &'a str,
    pub observations: &'a [Observation],
    pub probe_status: CoverageStatus,
    pub cancellation: &'a AtomicBool,
    pub memory_items: usize,
}

pub struct ScanEngine<'a> {
    pub reports: &'a ReportStore,
    pub policy: Policy,
}
pub struct StreamingScanRequest<'a> {
    pub scan_id: &'a str,
    pub safety_fingerprint: &'a str,
    pub scope_fingerprint: &'a str,
    pub probe_status: CoverageStatus,
    pub cancellation: &'a AtomicBool,
    pub memory_items: usize,
    /// Filesystem directories are emitted before their descendants, allowing
    /// recursive accounting to be fused into traversal without replay.
    pub filesystem_parent_first: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerOutcome {
    pub coverage: CoverageStatus,
    pub global_estimates_incomplete: bool,
    /// Filesystem roots whose traversal did not complete. Size estimates for
    /// candidates below these roots are withheld without penalizing complete
    /// sibling roots.
    pub incomplete_roots: BTreeSet<camino::Utf8PathBuf>,
}

impl From<CoverageStatus> for ProducerOutcome {
    fn from(coverage: CoverageStatus) -> Self {
        Self {
            global_estimates_incomplete: coverage != CoverageStatus::Complete,
            coverage,
            incomplete_roots: BTreeSet::new(),
        }
    }
}
impl ScanEngine<'_> {
    pub fn run(&self, request: ScanRequest<'_>) -> Result<ExitCode, ReportError> {
        self.run_streaming(
            StreamingScanRequest {
                scan_id: request.scan_id,
                safety_fingerprint: request.safety_fingerprint,
                scope_fingerprint: request.scope_fingerprint,
                probe_status: request.probe_status,
                cancellation: request.cancellation,
                memory_items: request.memory_items,
                filesystem_parent_first: false,
            },
            |emit| {
                for value in request.observations {
                    emit(value.clone());
                }
                ProducerOutcome::from(CoverageStatus::Complete)
            },
        )
    }
    pub fn run_streaming<R>(
        &self,
        request: StreamingScanRequest<'_>,
        producer: impl FnOnce(&mut dyn FnMut(Observation)) -> R,
    ) -> Result<ExitCode, ReportError>
    where
        R: Into<ProducerOutcome>,
    {
        let _lock = self.reports.try_lock()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_streaming_inner(request, producer)
        }));
        match result {
            Ok(value) => value,
            Err(_) => Err(ReportError::Internal),
        }
    }
    fn run_streaming_inner<R>(
        &self,
        request: StreamingScanRequest<'_>,
        producer: impl FnOnce(&mut dyn FnMut(Observation)) -> R,
    ) -> Result<ExitCode, ReportError>
    where
        R: Into<ProducerOutcome>,
    {
        let detector = CatalogDetector::default();
        let mut metrics = ScanMetrics::default();
        let mut budget = ScanBudget {
            limits: BTreeMap::from([
                (BudgetKind::CandidateCount, 1_000_000),
                (BudgetKind::CandidateBytes, 256 * 1024 * 1024),
                (BudgetKind::InodeEntries, 1_000_000),
            ]),
        }
        .tracker();
        let (_spill_temp, spill_store) = self.reports.temporary_store()?;
        let (_sink_temp, sink_store) = spill_store.temporary_child()?;
        let mut sink = CandidateSink::new(4096, FileInodeSpill::new(sink_store, 16 * 1024 * 1024));
        let mut extent_spool = ExtentSpool::new().map_err(|_| ReportError::Internal)?;
        let mut candidate_roots: BTreeMap<camino::Utf8PathBuf, Vec<LogicalCandidateId>> =
            BTreeMap::new();
        let mut logical_bytes: BTreeMap<LogicalCandidateId, u64> = BTreeMap::new();
        let mut logical_estimates_complete = true;
        let mut physical_estimates_complete = true;
        let mut observation_spool_complete = true;
        let mut observation_spool_bytes = 0_u64;
        let mut candidate_spool_complete = true;
        let mut candidate_spool_bytes = 0_u64;
        let mut observation_spool = BufWriter::with_capacity(
            1024 * 1024,
            tempfile::tempfile().map_err(|_| ReportError::Internal)?,
        );
        let mut spool = BufWriter::with_capacity(
            256 * 1024,
            tempfile::tempfile().map_err(|_| ReportError::Internal)?,
        );
        let mut overall = request.probe_status.clone();
        let mut failed = false;
        let producer_outcome = {
            let mut emit = |observation: Observation| {
                metrics.entries_seen = metrics.entries_seen.saturating_add(1);
                if request.cancellation.load(Ordering::Relaxed) {
                    failed = true;
                    return;
                }
                if !request.filesystem_parent_first
                    && matches!(observation.identity, ResourceIdentity::Filesystem { .. })
                    && observation_spool_complete
                {
                    match FilesystemSpoolRecord::from_observation(&observation) {
                        Some(record)
                            if within_byte_budget(
                                observation_spool_bytes,
                                record.encoded_len(),
                                2 * 1024 * 1024 * 1024,
                            ) =>
                        {
                            observation_spool_bytes =
                                observation_spool_bytes.saturating_add(record.encoded_len());
                            if record.write_to(&mut observation_spool).is_err() {
                                failed = true;
                                return;
                            }
                        }
                        Some(_) => {
                            observation_spool_complete = false;
                            logical_estimates_complete = false;
                            physical_estimates_complete = false;
                            overall.join_assign(&CoverageStatus::Partial);
                        }
                        None => {
                            failed = true;
                            return;
                        }
                    }
                }
                metrics.route_lookups = metrics.route_lookups.saturating_add(1);
                let routed = CatalogDetector::is_candidate(&observation);
                if routed {
                    metrics.detector_visits = metrics.detector_visits.saturating_add(1);
                }
                let one = [observation];
                let outcome = if routed {
                    detector.detect(DetectorContext {
                        observations: &one,
                        artifact_limit: 16,
                    })
                } else {
                    devclean_core::DetectorOutcome::bounded(Vec::new(), 16)
                };
                overall.join_assign(&outcome.coverage);
                for artifact in outcome.artifacts {
                    if let ResourceIdentity::Filesystem { path } = &artifact.identity {
                        let root_owners = candidate_roots.entry(path.clone()).or_default();
                        if !root_owners.contains(&artifact.id) {
                            root_owners.push(artifact.id.clone());
                        }
                    }
                    let inode_key = inode_key(&one[0]);
                    if sink
                        .retain(
                            &artifact.id.0.to_string(),
                            &one[0],
                            inode_key.clone(),
                            &mut budget,
                        )
                        .is_err()
                    {
                        failed = true;
                        return;
                    }
                    let mut coverage = CoverageMap::default();
                    let mut candidate_status = CoverageStatus::Complete;
                    for probe in artifact.required_probes.0.clone() {
                        let status = observation_probe_coverage(&one[0], &probe)
                            .unwrap_or(CoverageStatus::Unknown);
                        if status != CoverageStatus::Complete {
                            candidate_status.join_assign(&status);
                            overall.join_assign(&status);
                        }
                        coverage.insert(artifact.id.clone(), probe, status);
                    }
                    let mut value = classify(artifact, &coverage, &self.policy).into_advisory();
                    value.coverage = candidate_status;
                    if !matches!(value.identity, ResourceIdentity::Filesystem { .. }) {
                        value.logical_bytes_estimate = one[0].logical_bytes;
                        value.physical_bytes_estimate = one[0].allocated_bytes;
                        value.shared_physical_bytes = Some(0);
                    }
                    if candidate_spool_complete {
                        match serde_json::to_vec(&value) {
                            Ok(encoded)
                                if within_byte_budget(
                                    candidate_spool_bytes,
                                    encoded.len() as u64 + 1,
                                    256 * 1024 * 1024,
                                ) =>
                            {
                                candidate_spool_bytes = candidate_spool_bytes
                                    .saturating_add(encoded.len() as u64)
                                    .saturating_add(1);
                                if spool.write_all(&encoded).is_err()
                                    || spool.write_all(b"\n").is_err()
                                {
                                    failed = true;
                                }
                            }
                            Ok(_) => {
                                candidate_spool_complete = false;
                                logical_estimates_complete = false;
                                physical_estimates_complete = false;
                                overall.join_assign(&CoverageStatus::Partial);
                            }
                            Err(_) => failed = true,
                        }
                    }
                }
                if request.filesystem_parent_first
                    && let Some(record) = FilesystemSpoolRecord::from_observation(&one[0])
                {
                    match account_record(
                        record,
                        &candidate_roots,
                        &mut logical_bytes,
                        &mut extent_spool,
                    ) {
                        Ok(completeness) => {
                            logical_estimates_complete &= completeness.logical;
                            physical_estimates_complete &= completeness.physical;
                            if !completeness.logical || !completeness.physical {
                                overall.join_assign(&CoverageStatus::Partial);
                            }
                        }
                        Err(_) => {
                            physical_estimates_complete = false;
                            overall.join_assign(&CoverageStatus::Partial);
                        }
                    }
                }
            };
            producer(&mut emit).into()
        };
        if request.cancellation.load(Ordering::Relaxed) {
            return Err(ReportError::Cancelled);
        }
        if sink.overflow.is_some() {
            logical_estimates_complete = false;
            physical_estimates_complete = false;
        }
        observation_spool
            .flush()
            .map_err(|_| ReportError::Internal)?;
        let mut observation_spool = observation_spool
            .into_inner()
            .map_err(|_| ReportError::Internal)?;
        observation_spool
            .seek(SeekFrom::Start(0))
            .map_err(|_| ReportError::Internal)?;
        if !request.filesystem_parent_first {
            let mut observation_reader = BufReader::new(observation_spool);
            while let Some(record) = FilesystemSpoolRecord::read_from(&mut observation_reader)
                .map_err(|_| ReportError::Internal)?
            {
                if request.cancellation.load(Ordering::Relaxed) {
                    return Err(ReportError::Cancelled);
                }
                match account_record(
                    record,
                    &candidate_roots,
                    &mut logical_bytes,
                    &mut extent_spool,
                ) {
                    Ok(completeness) => {
                        logical_estimates_complete &= completeness.logical;
                        physical_estimates_complete &= completeness.physical;
                        if !completeness.logical || !completeness.physical {
                            overall.join_assign(&CoverageStatus::Partial);
                        }
                    }
                    Err(_) => {
                        physical_estimates_complete = false;
                        overall.join_assign(&CoverageStatus::Partial);
                    }
                }
            }
        }
        let accounting = match extent_spool.account(request.cancellation) {
            Ok(value) => value,
            Err(devclean_core::AccountingError::Cancelled) => return Err(ReportError::Cancelled),
            Err(devclean_core::AccountingError::Overflow(_)) => {
                physical_estimates_complete = false;
                overall.join_assign(&CoverageStatus::Partial);
                PhysicalAccounting::default()
            }
            Err(devclean_core::AccountingError::Io(_)) => return Err(ReportError::UnsafeAuthority),
        };
        let relationships = relationship_count(candidate_roots.keys(), request.cancellation)
            .ok_or(ReportError::Cancelled)?;
        if sink.overflow.is_some() {
            overall.join_assign(&CoverageStatus::Partial);
        }
        overall.join_assign(&producer_outcome.coverage);
        if request.cancellation.load(Ordering::Relaxed) {
            return Err(ReportError::Cancelled);
        }
        if failed {
            return Err(ReportError::UnsafeAuthority);
        }
        spool.flush().map_err(|_| ReportError::Internal)?;
        let mut spool = spool.into_inner().map_err(|_| ReportError::Internal)?;
        spool
            .seek(SeekFrom::Start(0))
            .map_err(|_| ReportError::Internal)?;
        let mut warnings = vec![
            if overall == CoverageStatus::Complete {
                "scan coverage complete".into()
            } else {
                "scan coverage incomplete; inspect candidate coverage fields".into()
            },
            format!(
                "metrics entries={} route_lookups={} detector_visits={} candidates={} candidate_bytes={} inode_entries={} observation_spool_bytes={} candidate_spool_bytes={} unique_bytes={} shared_candidates={} relationships={}",
                metrics.entries_seen,
                metrics.route_lookups,
                metrics.detector_visits,
                budget.used(BudgetKind::CandidateCount),
                budget.used(BudgetKind::CandidateBytes),
                budget.used(BudgetKind::InodeEntries),
                observation_spool_bytes,
                candidate_spool_bytes,
                accounting.unique_bytes,
                accounting.shared_bytes.len(),
                relationships
            ),
        ];
        if !observation_spool_complete {
            warnings.push(
                "observation_spool_byte_limit reached; filesystem estimates withheld globally"
                    .into(),
            );
        }
        if !candidate_spool_complete {
            warnings.push("candidate_spool_byte_limit reached; later candidates omitted".into());
        }
        if !physical_estimates_complete {
            warnings.push(
                "physical extent accounting incomplete; physical candidate estimates withheld"
                    .into(),
            );
        }
        let header = ScanReportHeader {
            scan_id: request.scan_id.into(),
            safety_fingerprint: request.safety_fingerprint.into(),
            scope_fingerprint: request.scope_fingerprint.into(),
            coverage: overall.clone(),
            warnings,
        };
        let write_result = self.reports.write_streaming_fallible_cancellable(
            &header,
            SpoolIter {
                lines: BufReader::new(spool).lines(),
                logical_bytes: &logical_bytes,
                accounting: &accounting,
                logical_estimates_complete,
                physical_estimates_complete,
                incomplete_roots: &producer_outcome.incomplete_roots,
                global_estimates_incomplete: producer_outcome.global_estimates_incomplete,
            },
            request.memory_items,
            request.cancellation,
        );
        if let Err(error) = write_result {
            if overall == CoverageStatus::Complete {
                return Err(error);
            }
            let mut marker = header.clone();
            marker
                .warnings
                .push("incomplete report exceeded storage budget; candidates omitted".into());
            self.reports.write_streaming_cancellable(
                &marker,
                std::iter::empty(),
                1,
                request.cancellation,
            )?;
        }
        Ok(if overall == CoverageStatus::Complete {
            ExitCode::Complete
        } else {
            ExitCode::Incomplete
        })
    }
}

fn inode_key(observation: &Observation) -> Option<String> {
    Some(format!(
        "{}:{}",
        observation.attributes.get("device")?,
        observation.attributes.get("inode")?
    ))
}

fn within_byte_budget(current: u64, additional: u64, limit: u64) -> bool {
    current
        .checked_add(additional)
        .is_some_and(|total| total <= limit)
}

#[cfg(test)]
mod byte_budget_tests {
    use super::{FilesystemSpoolRecord, within_byte_budget};
    use devclean_core::{Observation, ResourceFingerprint, ResourceIdentity};
    use std::collections::BTreeMap;

    #[test]
    fn byte_budget_is_exact_and_overflow_safe() {
        assert!(within_byte_budget(7, 3, 10));
        assert!(!within_byte_budget(8, 3, 10));
        assert!(!within_byte_budget(u64::MAX, 1, u64::MAX));
    }

    #[test]
    fn performance_contract_accounting_spool_is_compact_and_lossless() {
        let observation = Observation {
            identity: ResourceIdentity::Filesystem {
                path: "/tmp/project/target/debug/deps/example".into(),
            },
            fingerprint: ResourceFingerprint::filesystem(1, 2, "file", 4096, 3),
            logical_bytes: Some(4096),
            allocated_bytes: Some(8192),
            attributes: BTreeMap::from([
                ("device".into(), "1".into()),
                ("inode".into(), "2".into()),
                ("links".into(), "1".into()),
                ("probe_filesystem_identity".into(), "complete".into()),
            ]),
        };
        let full = serde_json::to_vec(&observation).unwrap();
        let compact = FilesystemSpoolRecord::from_observation(&observation).unwrap();
        let mut encoded = Vec::new();
        compact.write_to(&mut encoded).unwrap();
        let decoded = FilesystemSpoolRecord::read_from(&mut encoded.as_slice())
            .unwrap()
            .unwrap();

        assert!(encoded.len() * 2 < full.len());
        assert_eq!(decoded.0.as_str(), "/tmp/project/target/debug/deps/example");
        assert_eq!(
            (decoded.1, decoded.2, decoded.3, decoded.4),
            (Some(4096), Some(8192), Some(1), Some(2))
        );
    }
}

fn filesystem_extent(observation: &Observation) -> Option<(u64, u64)> {
    match (
        observation.attributes.get("device"),
        observation.attributes.get("inode"),
    ) {
        (Some(device), Some(inode)) => Some((device.parse().ok()?, inode.parse().ok()?)),
        _ => observation.fingerprint.extent_identity(),
    }
}

/// Minimal binary replay state for recursive size accounting. Full observations
/// contain a fingerprint and string attribute map that accounting never reads.
struct FilesystemSpoolRecord(
    camino::Utf8PathBuf,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);

impl FilesystemSpoolRecord {
    fn from_observation(observation: &Observation) -> Option<Self> {
        let ResourceIdentity::Filesystem { path } = &observation.identity else {
            return None;
        };
        let extent = filesystem_extent(observation);
        Some(Self(
            path.clone(),
            observation.logical_bytes,
            observation.allocated_bytes,
            extent.map(|value| value.0),
            extent.map(|value| value.1),
        ))
    }

    fn encoded_len(&self) -> u64 {
        let present = [self.1, self.2, self.3, self.4]
            .into_iter()
            .filter(Option::is_some)
            .count() as u64;
        4_u64
            .saturating_add(self.0.as_str().len() as u64)
            .saturating_add(1)
            .saturating_add(present.saturating_mul(8))
    }

    fn write_to(&self, output: &mut impl Write) -> std::io::Result<()> {
        let path = self.0.as_str().as_bytes();
        let path_len = u32::try_from(path.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "spool path too long")
        })?;
        output.write_all(&path_len.to_le_bytes())?;
        output.write_all(path)?;
        let values = [self.1, self.2, self.3, self.4];
        let flags = values
            .iter()
            .enumerate()
            .fold(0_u8, |flags, (index, value)| {
                flags | (u8::from(value.is_some()) << index)
            });
        output.write_all(&[flags])?;
        for value in values.into_iter().flatten() {
            output.write_all(&value.to_le_bytes())?;
        }
        Ok(())
    }

    fn read_from(input: &mut impl Read) -> std::io::Result<Option<Self>> {
        let mut path_len = [0_u8; 4];
        match input.read(&mut path_len[..1])? {
            0 => return Ok(None),
            1 => input.read_exact(&mut path_len[1..])?,
            _ => unreachable!("one-byte read returned more than one byte"),
        }
        let path_len = u32::from_le_bytes(path_len) as usize;
        let mut path = vec![0_u8; path_len];
        input.read_exact(&mut path)?;
        let path = String::from_utf8(path)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 path"))?;
        let mut flags = [0_u8; 1];
        input.read_exact(&mut flags)?;
        let mut read_value = |index: usize| -> std::io::Result<Option<u64>> {
            if flags[0] & (1 << index) == 0 {
                return Ok(None);
            }
            let mut value = [0_u8; 8];
            input.read_exact(&mut value)?;
            Ok(Some(u64::from_le_bytes(value)))
        };
        Ok(Some(Self(
            path.into(),
            read_value(0)?,
            read_value(1)?,
            read_value(2)?,
            read_value(3)?,
        )))
    }
}

#[derive(Clone, Copy)]
struct AccountingCompleteness {
    logical: bool,
    physical: bool,
}

fn account_record(
    record: FilesystemSpoolRecord,
    candidate_roots: &BTreeMap<camino::Utf8PathBuf, Vec<LogicalCandidateId>>,
    logical_bytes: &mut BTreeMap<LogicalCandidateId, u64>,
    extent_spool: &mut ExtentSpool,
) -> std::io::Result<AccountingCompleteness> {
    let mut owners = record
        .0
        .ancestors()
        .filter_map(|ancestor| candidate_roots.get(ancestor))
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    if owners.is_empty() {
        return Ok(AccountingCompleteness {
            logical: true,
            physical: true,
        });
    }
    let logical = if let Some(bytes) = record.1 {
        for owner in &owners {
            let total = logical_bytes.entry(owner.clone()).or_default();
            *total = total.saturating_add(bytes);
        }
        true
    } else {
        false
    };
    let physical = match (record.3, record.4, record.2) {
        (Some(device), Some(inode), Some(allocated_bytes)) => {
            extent_spool.push(ExtentRecord {
                device,
                inode,
                allocated_bytes,
                candidates: owners,
            })?;
            true
        }
        _ => false,
    };
    Ok(AccountingCompleteness { logical, physical })
}

const EXTENT_PARTITIONS: usize = 64;
// 64 partitions bound the physical-accounting spool to 1 GiB total. The scan
// admission reserve is 3 GiB, leaving room for the candidate/report spools.
const EXTENT_PARTITION_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct ExtentRecord {
    device: u64,
    inode: u64,
    allocated_bytes: u64,
    candidates: Vec<LogicalCandidateId>,
}

struct ExtentSpool {
    partitions: Vec<BufWriter<std::fs::File>>,
    bytes: Vec<u64>,
}

impl ExtentSpool {
    fn new() -> std::io::Result<Self> {
        let partitions = (0..EXTENT_PARTITIONS)
            .map(|_| tempfile::tempfile().map(BufWriter::new))
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(Self {
            partitions,
            bytes: vec![0; EXTENT_PARTITIONS],
        })
    }

    fn push(&mut self, record: ExtentRecord) -> std::io::Result<()> {
        let mut encoded = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        encoded.push(b'\n');
        let key = format!("{}:{}", record.device, record.inode);
        let digest = blake3::hash(key.as_bytes());
        let partition = digest.as_bytes()[0] as usize % EXTENT_PARTITIONS;
        let attempted = self.bytes[partition].saturating_add(encoded.len() as u64);
        if attempted > EXTENT_PARTITION_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "extent partition limit",
            ));
        }
        self.partitions[partition].write_all(&encoded)?;
        self.bytes[partition] = attempted;
        Ok(())
    }

    fn account(
        &mut self,
        cancellation: &AtomicBool,
    ) -> Result<PhysicalAccounting, devclean_core::AccountingError> {
        let mut total = PhysicalAccounting::default();
        for writer in &mut self.partitions {
            if cancellation.load(Ordering::Relaxed) {
                return Err(devclean_core::AccountingError::Cancelled);
            }
            writer.flush()?;
            let file = writer.get_mut();
            file.seek(SeekFrom::Start(0))?;
            let mut extents = BTreeMap::<(u64, u64), PhysicalExtent>::new();
            for line in BufReader::new(file).lines() {
                if cancellation.load(Ordering::Relaxed) {
                    return Err(devclean_core::AccountingError::Cancelled);
                }
                let record: ExtentRecord = serde_json::from_str(&line?)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                let extent = extents
                    .entry((record.device, record.inode))
                    .or_insert_with(|| PhysicalExtent {
                        device: record.device,
                        inode: record.inode,
                        allocated_bytes: record.allocated_bytes,
                        candidates: Vec::new(),
                    });
                for candidate in record.candidates {
                    if !extent.candidates.contains(&candidate) {
                        extent.candidates.push(candidate);
                    }
                }
            }
            let part = PhysicalAccounting::from_extents_cancellable(
                extents.into_values(),
                1_000_000,
                &mut TrustedUniqueSpill,
                cancellation,
            )?;
            total.unique_bytes = total
                .unique_bytes
                .checked_add(part.unique_bytes)
                .ok_or_else(accounting_overflow)?;
            merge_accounting(&mut total.additive_bytes, part.additive_bytes)?;
            merge_accounting(&mut total.shared_bytes, part.shared_bytes)?;
        }
        Ok(total)
    }
}

// Extents have already been deduplicated by (device, inode) within their hash
// partition, and a key can occur in only one partition.
struct TrustedUniqueSpill;

impl devclean_core::InodeSpill for TrustedUniqueSpill {
    fn contains(&mut self, _: u16, _: &str) -> std::io::Result<bool> {
        Ok(false)
    }

    fn spill(&mut self, _: u16, _: &[(String, u64)]) -> std::io::Result<()> {
        Ok(())
    }
}

fn accounting_overflow() -> devclean_core::AccountingError {
    devclean_core::AccountingError::Overflow(devclean_core::OverflowEvent {
        kind: BudgetKind::InodeEntries,
        limit: u64::MAX,
        attempted: u64::MAX,
    })
}

fn merge_accounting(
    target: &mut BTreeMap<LogicalCandidateId, u64>,
    source: BTreeMap<LogicalCandidateId, u64>,
) -> Result<(), devclean_core::AccountingError> {
    for (candidate, bytes) in source {
        let value = target.entry(candidate).or_default();
        *value = value.checked_add(bytes).ok_or_else(accounting_overflow)?;
    }
    Ok(())
}

fn relationship_count<'a>(
    paths: impl IntoIterator<Item = &'a camino::Utf8PathBuf>,
    cancellation: &AtomicBool,
) -> Option<usize> {
    let mut stack: Vec<&camino::Utf8Path> = Vec::new();
    let mut count = 0usize;
    for path in paths {
        if cancellation.load(Ordering::Relaxed) {
            return None;
        }
        while stack
            .last()
            .is_some_and(|parent| parent.as_str() == path.as_str() || !path.starts_with(parent))
        {
            stack.pop();
        }
        if !stack.is_empty() {
            count = count.saturating_add(1);
        }
        stack.push(path);
    }
    Some(count)
}

fn observation_probe_coverage(
    observation: &Observation,
    probe: &devclean_core::ProbeKind,
) -> Option<CoverageStatus> {
    let key = match probe {
        devclean_core::ProbeKind::FilesystemIdentity => "probe_filesystem_identity",
        devclean_core::ProbeKind::Activity => "probe_activity",
        devclean_core::ProbeKind::OpenFiles => "probe_open_files",
        devclean_core::ProbeKind::GitStatus => "probe_git_status",
        devclean_core::ProbeKind::GitRegistration => "probe_git_registration",
        devclean_core::ProbeKind::GitReachability => "probe_git_reachability",
        devclean_core::ProbeKind::DockerSnapshot => "probe_docker_snapshot",
        devclean_core::ProbeKind::DockerReferences => "probe_docker_references",
        devclean_core::ProbeKind::Metadata => "probe_metadata",
        devclean_core::ProbeKind::ApprovedScope => "probe_approved_scope",
        devclean_core::ProbeKind::Rebuildability => "probe_rebuildability",
    };
    observation
        .attributes
        .get(key)
        .map(String::as_str)
        .map(|value| match value {
            "complete" => CoverageStatus::Complete,
            "unsupported" => CoverageStatus::Unsupported,
            "skipped" => CoverageStatus::Skipped,
            "partial" => CoverageStatus::Partial,
            "failed" => CoverageStatus::Failed,
            "timed_out" => CoverageStatus::TimedOut,
            "truncated" => CoverageStatus::Truncated,
            "stale" => CoverageStatus::Stale,
            _ => CoverageStatus::Unknown,
        })
}

struct SpoolIter<'a> {
    lines: std::io::Lines<BufReader<std::fs::File>>,
    logical_bytes: &'a BTreeMap<LogicalCandidateId, u64>,
    accounting: &'a PhysicalAccounting,
    logical_estimates_complete: bool,
    physical_estimates_complete: bool,
    incomplete_roots: &'a BTreeSet<camino::Utf8PathBuf>,
    global_estimates_incomplete: bool,
}
impl Iterator for SpoolIter<'_> {
    type Item = Result<devclean_core::AdvisoryCandidate, ReportError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.lines.next().map(|line| {
            let mut value = decode_spool_line(line)?;
            if let ResourceIdentity::Filesystem { path } = &value.identity {
                let root_complete = !self.global_estimates_incomplete
                    && !path
                        .ancestors()
                        .any(|ancestor| self.incomplete_roots.contains(ancestor));
                if self.logical_estimates_complete && root_complete {
                    value.logical_bytes_estimate = self.logical_bytes.get(&value.id).copied();
                }
                if self.physical_estimates_complete && root_complete {
                    let additive = self
                        .accounting
                        .additive_bytes
                        .get(&value.id)
                        .copied()
                        .unwrap_or(0);
                    let shared = self
                        .accounting
                        .shared_bytes
                        .get(&value.id)
                        .copied()
                        .unwrap_or(0);
                    value.physical_bytes_estimate = Some(additive.saturating_add(shared));
                    value.shared_physical_bytes = Some(shared);
                }
            }
            Ok(value)
        })
    }
}

fn decode_spool_line(
    line: std::io::Result<String>,
) -> Result<devclean_core::AdvisoryCandidate, ReportError> {
    let line = line.map_err(|error| ReportError::Store(error.into()))?;
    serde_json::from_str(&line).map_err(|_| ReportError::Malformed)
}

#[cfg(test)]
mod spool_decode_tests {
    use super::*;

    #[test]
    fn malformed_and_io_spool_lines_are_typed_without_panicking() {
        assert!(matches!(
            decode_spool_line(Ok("{not-json".into())),
            Err(ReportError::Malformed)
        ));
        assert!(matches!(
            decode_spool_line(Err(std::io::Error::other("injected"))),
            Err(ReportError::Store(_))
        ));
    }
}
