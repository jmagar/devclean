use crate::private_store::{PrivateStore, StoreError};
use camino::Utf8PathBuf;
use devclean_core::{AdvisoryCandidate, CoverageStatus, LogicalCandidateId, Tier};
use schemars::JsonSchema;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanReportV1 {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    #[schemars(length(min = 1))]
    pub scan_id: String,
    #[schemars(length(min = 1))]
    pub safety_fingerprint: String,
    #[schemars(length(min = 1))]
    pub scope_fingerprint: String,
    pub coverage: CoverageStatus,
    pub candidates: Vec<AdvisoryCandidate>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanReportHeader {
    pub scan_id: String,
    pub safety_fingerprint: String,
    pub scope_fingerprint: String,
    pub coverage: CoverageStatus,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportSummary {
    pub header: ScanReportHeader,
    pub candidate_count: u64,
}

pub enum ReportSelector<'a> {
    ScanId(&'a str),
    Latest {
        ids: Vec<&'a str>,
        safety: &'a str,
        scope: &'a str,
    },
}

impl ScanReportV1 {
    pub fn validate(&self) -> Result<(), ReportError> {
        if self.schema_version != 1 {
            return Err(ReportError::UnsupportedVersion(self.schema_version));
        }
        if self.scan_id.is_empty()
            || self.safety_fingerprint.is_empty()
            || self.scope_fingerprint.is_empty()
        {
            return Err(ReportError::Malformed);
        }
        Ok(())
    }
}

pub struct ReportStore {
    store: PrivateStore,
    max_bytes: u64,
}
impl ReportStore {
    pub fn temporary_store(&self) -> Result<(tempfile::TempDir, PrivateStore), ReportError> {
        self.store.temporary_child().map_err(ReportError::Store)
    }
    pub fn new(store: PrivateStore, max_bytes: u64) -> Self {
        Self { store, max_bytes }
    }
    pub fn try_lock(&self) -> Result<ReportLock, ReportError> {
        let file = self.store.open_lock("scan.lock")?;
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(ReportError::Locked);
        }
        Ok(ReportLock(file))
    }
    pub fn write(&self, report: &ScanReportV1) -> Result<Utf8PathBuf, ReportError> {
        report.validate()?;
        let name = format!("{}.json", safe_id(&report.scan_id)?);
        self.store
            .replace_atomic(&name, |file| {
                let mut limited = CountingWriter::new(file, self.max_bytes);
                serde_json::to_writer(&mut limited, report).map_err(|_| {
                    StoreError::Io(std::io::Error::other("report serialization failed"))
                })?;
                limited.flush().map_err(StoreError::from)
            })
            .map_err(ReportError::Store)
    }
    pub fn write_streaming(
        &self,
        header: &ScanReportHeader,
        candidates: impl IntoIterator<Item = AdvisoryCandidate>,
        memory_items: usize,
    ) -> Result<Utf8PathBuf, ReportError> {
        self.write_streaming_cancellable(header, candidates, memory_items, &AtomicBool::new(false))
    }
    pub fn write_streaming_cancellable(
        &self,
        header: &ScanReportHeader,
        candidates: impl IntoIterator<Item = AdvisoryCandidate>,
        memory_items: usize,
        cancellation: &AtomicBool,
    ) -> Result<Utf8PathBuf, ReportError> {
        self.write_streaming_fallible_cancellable(
            header,
            candidates.into_iter().map(Ok),
            memory_items,
            cancellation,
        )
    }

    pub fn write_streaming_fallible_cancellable(
        &self,
        header: &ScanReportHeader,
        candidates: impl IntoIterator<Item = Result<AdvisoryCandidate, ReportError>>,
        memory_items: usize,
        cancellation: &AtomicBool,
    ) -> Result<Utf8PathBuf, ReportError> {
        if memory_items == 0 {
            return Err(ReportError::Malformed);
        }
        let chunk_limit = memory_items.min(4096);
        validate_header(header)?;
        let mut runs = Vec::new();
        let mut chunk = Vec::with_capacity(chunk_limit);
        for candidate in candidates {
            if cancellation.load(AtomicOrdering::Relaxed) {
                return Err(ReportError::Cancelled);
            }
            chunk.push(candidate?);
            if chunk.len() == chunk_limit {
                runs.push(write_run(std::mem::take(&mut chunk))?);
                if runs.len() > 256 {
                    return Err(ReportError::TooManyRuns);
                }
            }
        }
        if !chunk.is_empty() {
            runs.push(write_run(chunk)?);
        }
        let name = format!("{}.json", header.scan_id);
        self.store
            .replace_atomic(&name, |file| {
                let mut out = CountingWriter::new(file, self.max_bytes);
                write!(out, "{{\"schema_version\":1,\"scan_id\":").map_err(StoreError::from)?;
                serde_json::to_writer(&mut out, &header.scan_id).map_err(json_store)?;
                write!(out, ",\"safety_fingerprint\":").map_err(StoreError::from)?;
                serde_json::to_writer(&mut out, &header.safety_fingerprint).map_err(json_store)?;
                write!(out, ",\"scope_fingerprint\":").map_err(StoreError::from)?;
                serde_json::to_writer(&mut out, &header.scope_fingerprint).map_err(json_store)?;
                write!(out, ",\"coverage\":").map_err(StoreError::from)?;
                serde_json::to_writer(&mut out, &header.coverage).map_err(json_store)?;
                write!(out, ",\"candidates\":").map_err(StoreError::from)?;
                write_merged(&mut out, &mut runs, cancellation).map_err(StoreError::from)?;
                write!(out, ",\"warnings\":").map_err(StoreError::from)?;
                serde_json::to_writer(&mut out, &header.warnings).map_err(json_store)?;
                write!(out, "}}").map_err(StoreError::from)?;
                out.flush().map_err(StoreError::from)
            })
            .map_err(ReportError::Store)
    }
    pub fn read(&self, scan_id: &str) -> Result<ScanReportV1, ReportError> {
        let name = format!("{}.json", safe_id(scan_id)?);
        let bytes = self
            .store
            .read_if_exists(&name, self.max_bytes)?
            .ok_or(ReportError::NotFound)?;
        parse_strict(&bytes)
    }
    pub fn latest_compatible<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a str>,
        safety: &str,
        scope: &str,
    ) -> Result<ScanReportV1, ReportError> {
        let mut matches = Vec::new();
        for id in ids {
            let report = self.read(id)?;
            if report.safety_fingerprint == safety && report.scope_fingerprint == scope {
                matches.push(report);
            }
        }
        match matches.len() {
            0 => Err(ReportError::NotFound),
            1 => Ok(matches.remove(0)),
            _ => Err(ReportError::AmbiguousLatest),
        }
    }
    pub fn stream_summary(&self, scan_id: &str) -> Result<ReportSummary, ReportError> {
        let file = self
            .store
            .open_read(&format!("{}.json", safe_id(scan_id)?))?;
        inspect_reader(BoundedReader::new(file, self.max_bytes), None).map(|value| value.0)
    }
    pub fn stream_explain(
        &self,
        scan_id: &str,
        id: &LogicalCandidateId,
    ) -> Result<Option<AdvisoryCandidate>, ReportError> {
        let file = self
            .store
            .open_read(&format!("{}.json", safe_id(scan_id)?))?;
        inspect_reader(BoundedReader::new(file, self.max_bytes), Some(id)).map(|value| value.1)
    }
    pub fn select_summary(
        &self,
        selector: ReportSelector<'_>,
    ) -> Result<ReportSummary, ReportError> {
        match selector {
            ReportSelector::ScanId(id) => self.stream_summary(id),
            ReportSelector::Latest { ids, safety, scope } => {
                let mut found = None;
                for id in ids {
                    let value = self.stream_summary(id)?;
                    if value.header.safety_fingerprint == safety
                        && value.header.scope_fingerprint == scope
                    {
                        if found.is_some() {
                            return Err(ReportError::AmbiguousLatest);
                        }
                        found = Some(value);
                    }
                }
                found.ok_or(ReportError::NotFound)
            }
        }
    }
}

fn inspect_reader(
    reader: impl std::io::Read,
    target: Option<&LogicalCandidateId>,
) -> Result<(ReportSummary, Option<AdvisoryCandidate>), ReportError> {
    let mut de = serde_json::Deserializer::from_reader(reader);
    let value = InspectSeed { target }
        .deserialize(&mut de)
        .map_err(|_| ReportError::Malformed)?;
    de.end().map_err(|_| ReportError::TrailingData)?;
    Ok(value)
}

struct InspectSeed<'a> {
    target: Option<&'a LogicalCandidateId>,
}
impl<'de> DeserializeSeed<'de> for InspectSeed<'_> {
    type Value = (ReportSummary, Option<AdvisoryCandidate>);
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(InspectVisitor {
            target: self.target,
        })
    }
}
struct InspectVisitor<'a> {
    target: Option<&'a LogicalCandidateId>,
}
impl<'de> Visitor<'de> for InspectVisitor<'_> {
    type Value = (ReportSummary, Option<AdvisoryCandidate>);
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scan report v1")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let (mut version, mut scan, mut safety, mut scope, mut coverage, mut warnings) =
            (None, None, None, None, None, None);
        let mut count = 0;
        let mut found = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::duplicate_field("report field"));
            }
            match key.as_str() {
                "schema_version" => version = Some(map.next_value::<u32>()?),
                "scan_id" => scan = Some(map.next_value()?),
                "safety_fingerprint" => safety = Some(map.next_value()?),
                "scope_fingerprint" => scope = Some(map.next_value()?),
                "coverage" => coverage = Some(map.next_value()?),
                "warnings" => warnings = Some(map.next_value::<Vec<String>>()?),
                "candidates" => {
                    let (n, hit) = map.next_value_seed(CandidateSeed {
                        target: self.target,
                    })?;
                    count = n;
                    found = hit;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    return Err(serde::de::Error::unknown_field(&key, &[]));
                }
            }
        }
        let header = ScanReportHeader {
            scan_id: scan.ok_or_else(|| serde::de::Error::missing_field("scan_id"))?,
            safety_fingerprint: safety
                .ok_or_else(|| serde::de::Error::missing_field("safety_fingerprint"))?,
            scope_fingerprint: scope
                .ok_or_else(|| serde::de::Error::missing_field("scope_fingerprint"))?,
            coverage: coverage.ok_or_else(|| serde::de::Error::missing_field("coverage"))?,
            warnings: warnings.ok_or_else(|| serde::de::Error::missing_field("warnings"))?,
        };
        if version != Some(1) {
            return Err(serde::de::Error::custom("unsupported version"));
        }
        validate_header(&header).map_err(serde::de::Error::custom)?;
        Ok((
            ReportSummary {
                header,
                candidate_count: count,
            },
            found,
        ))
    }
}
struct CandidateSeed<'a> {
    target: Option<&'a LogicalCandidateId>,
}
impl<'de> DeserializeSeed<'de> for CandidateSeed<'_> {
    type Value = (u64, Option<AdvisoryCandidate>);
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(CandidateVisitor {
            target: self.target,
        })
    }
}
struct CandidateVisitor<'a> {
    target: Option<&'a LogicalCandidateId>,
}
impl<'de> Visitor<'de> for CandidateVisitor<'_> {
    type Value = (u64, Option<AdvisoryCandidate>);
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("candidate array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut count = 0;
        let mut found = None;
        while let Some(value) = seq.next_element::<AdvisoryCandidate>()? {
            count += 1;
            if self.target.is_some_and(|id| id == &value.id) {
                found = Some(value);
            }
        }
        Ok((count, found))
    }
}

fn json_store(_: serde_json::Error) -> StoreError {
    StoreError::Io(std::io::Error::other("report serialization failed"))
}

fn write_run(mut values: Vec<AdvisoryCandidate>) -> Result<tempfile::NamedTempFile, ReportError> {
    values.sort_by_key(|value| value.id.clone());
    let mut file = tempfile::NamedTempFile::new().map_err(StoreError::from)?;
    for value in values {
        serde_json::to_writer(&mut file, &value).map_err(|_| ReportError::Malformed)?;
        file.write_all(b"\n").map_err(StoreError::from)?;
    }
    file.as_file_mut().sync_all().map_err(StoreError::from)?;
    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(StoreError::from)?;
    Ok(file)
}

fn write_merged(
    out: &mut impl Write,
    runs: &mut [tempfile::NamedTempFile],
    cancellation: &AtomicBool,
) -> std::io::Result<()> {
    let mut readers: Vec<_> = runs
        .iter_mut()
        .map(|run| BufReader::new(run.as_file_mut()))
        .collect();
    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::new();
    for (index, reader) in readers.iter_mut().enumerate() {
        if let Some(value) = read_candidate(reader)? {
            heap.push(HeapItem {
                key: value.id.clone(),
                index,
                value,
            });
        }
    }
    out.write_all(b"[")?;
    let mut first = true;
    while let Some(HeapItem { index, value, .. }) = heap.pop() {
        if cancellation.load(AtomicOrdering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "report cancelled",
            ));
        }
        if !first {
            out.write_all(b",")?;
        }
        first = false;
        serde_json::to_writer(&mut *out, &value).map_err(std::io::Error::other)?;
        if let Some(next) = read_candidate(&mut readers[index])? {
            heap.push(HeapItem {
                key: next.id.clone(),
                index,
                value: next,
            });
        }
    }
    out.write_all(b"]")
}
struct HeapItem {
    key: LogicalCandidateId,
    index: usize,
    value: AdvisoryCandidate,
}
impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.index == other.index
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .key
            .cmp(&self.key)
            .then_with(|| other.index.cmp(&self.index))
    }
}
fn read_candidate(reader: &mut impl BufRead) -> std::io::Result<Option<AdvisoryCandidate>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    serde_json::from_str(&line)
        .map(Some)
        .map_err(std::io::Error::other)
}

pub fn parse_strict(bytes: &[u8]) -> Result<ScanReportV1, ReportError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let report =
        ScanReportV1::deserialize(&mut deserializer).map_err(|_| ReportError::Malformed)?;
    deserializer.end().map_err(|_| ReportError::TrailingData)?;
    report.validate()?;
    Ok(report)
}

pub fn render_summary(report: &ScanReportV1, max_rows: usize, tty: bool) -> String {
    let mut out = format!(
        "scan {} coverage {:?}\n",
        safe_terminal_bounded(&report.scan_id, 128),
        report.coverage
    );
    for candidate in report.candidates.iter().take(max_rows) {
        let location = match &candidate.identity {
            devclean_core::ResourceIdentity::Filesystem { path } => path.as_str(),
            _ => "<external-resource>",
        };
        let protections = candidate
            .protections
            .iter()
            .take(16)
            .map(|v| safe_terminal_bounded(v, 128))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "{:?}\t{}\tlogical={}\tphysical={}\tshared={}\t{}\n",
            candidate.tier,
            safe_terminal_bounded(location, 512),
            candidate
                .logical_bytes_estimate
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            candidate
                .physical_bytes_estimate
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            candidate
                .shared_physical_bytes
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            protections
        ));
    }
    if report.candidates.len() > max_rows {
        out.push_str(&format!(
            "... {} more candidates\n",
            report.candidates.len() - max_rows
        ));
    }
    for warning in report.warnings.iter().take(16) {
        out.push_str(&format!(
            "warning: {}\n",
            safe_terminal_bounded(warning, 256)
        ));
    }
    if report.warnings.len() > 16 {
        out.push_str(&format!(
            "... {} more warnings\n",
            report.warnings.len() - 16
        ));
    }
    if tty {
        out.push_str("interactive: disabled in inventory v1\n");
    }
    out
}

fn safe_terminal_bounded(value: &str, max_chars: usize) -> String {
    safe_terminal(&value.chars().take(max_chars).collect::<String>())
}

pub fn write_redacted(report: &ScanReportV1, mut writer: impl Write) -> Result<(), ReportError> {
    #[derive(Serialize)]
    struct Export<'a> {
        schema_version: u32,
        usable_for_cleanup: bool,
        scan: String,
        coverage: &'a CoverageStatus,
        candidates: Vec<Redacted>,
    }
    #[derive(Serialize)]
    struct Redacted {
        id: String,
        tier: Tier,
        protections: Vec<String>,
    }
    let candidates = report
        .candidates
        .iter()
        .map(|value| Redacted {
            id: format!(
                "candidate-{}",
                &blake3::hash(format!("devclean-redacted-v1\0{}", value.id.0).as_bytes()).to_hex()
                    [..16]
            ),
            tier: value.tier,
            protections: value
                .protections
                .iter()
                .filter_map(|value| match value.as_str() {
                    "active" | "open_file" | "mounted" | "dirty" | "untracked" | "unpublished"
                    | "unreachable_commit" | "docker_volume" | "database" | "archive"
                    | "unique_state" | "inaccessible" | "unknown_ownership" => Some(value.clone()),
                    _ => None,
                })
                .collect(),
        })
        .collect();
    serde_json::to_writer(
        &mut writer,
        &Export {
            schema_version: 1,
            usable_for_cleanup: false,
            scan: "redacted".into(),
            coverage: &report.coverage,
            candidates,
        },
    )
    .map_err(|_| ReportError::Malformed)
}

pub fn explain_candidate(report: &ScanReportV1, id: &LogicalCandidateId) -> Option<String> {
    report
        .candidates
        .iter()
        .find(|value| &value.id == id)
        .map(render_explanation)
}

pub fn render_explanation(value: &AdvisoryCandidate) -> String {
    let evidence = value
        .positive_evidence
        .iter()
        .take(16)
        .map(|item| {
            format!(
                "{:?}:{}:{:?}",
                item.code,
                safe_terminal(&item.source),
                item.confidence
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let protections = value
        .protections
        .iter()
        .take(32)
        .map(|item| safe_terminal(item))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "tier={:?} category={:?} evidence=[{}] protections=[{}] logical={} physical={} shared={} size_provenance={:?}",
        value.tier,
        value.category,
        evidence,
        protections,
        value
            .logical_bytes_estimate
            .map_or_else(|| "unknown".into(), |v| v.to_string()),
        value
            .physical_bytes_estimate
            .map_or_else(|| "unknown".into(), |v| v.to_string()),
        value
            .shared_physical_bytes
            .map_or_else(|| "unknown".into(), |v| v.to_string()),
        value.size_provenance,
    )
}

pub fn scan_report_v1_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ScanReportV1)).expect("schema serialization")
}

fn validate_header(header: &ScanReportHeader) -> Result<(), ReportError> {
    safe_id(&header.scan_id)?;
    if header.safety_fingerprint.is_empty() || header.scope_fingerprint.is_empty() {
        Err(ReportError::Malformed)
    } else {
        Ok(())
    }
}

pub fn safe_terminal(value: &str) -> String {
    value.chars().flat_map(|ch| {
        if ch.is_control() || matches!(ch, '\u{001b}' | '\u{0085}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            format!("\\u{{{:x}}}", ch as u32).chars().collect::<Vec<_>>()
        } else { vec![ch] }
    }).collect()
}

fn safe_id(value: &str) -> Result<&str, ReportError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Err(ReportError::Malformed)
    } else {
        Ok(value)
    }
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    checked_end: bool,
}
impl<R> BoundedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            checked_end: false,
        }
    }
}
impl<R: std::io::Read> std::io::Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining > 0 {
            let allowed = buffer.len().min(self.remaining as usize);
            let count = self.inner.read(&mut buffer[..allowed])?;
            self.remaining -= count as u64;
            return Ok(count);
        }
        if self.checked_end {
            return Ok(0);
        }
        self.checked_end = true;
        let mut byte = [0];
        if self.inner.read(&mut byte)? == 0 {
            Ok(0)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "report read limit",
            ))
        }
    }
}
impl<W> CountingWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }
}
impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.written.saturating_add(bytes.len() as u64) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "report limit",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("malformed report")]
    Malformed,
    #[error("trailing report data")]
    TrailingData,
    #[error("unsupported report version {0}")]
    UnsupportedVersion(u32),
    #[error("report not found")]
    NotFound,
    #[error("latest report is ambiguous across compatible scans")]
    AmbiguousLatest,
    #[error("external sort run limit exceeded")]
    TooManyRuns,
    #[error("report operation cancelled")]
    Cancelled,
    #[error("another scan owns the report store lock")]
    Locked,
    #[error("internal report failure")]
    Internal,
    #[error("incomplete evidence attempted to grant safe authority")]
    UnsafeAuthority,
    #[error(transparent)]
    Store(#[from] StoreError),
}
pub struct ReportLock(std::fs::File);
impl Drop for ReportLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}
