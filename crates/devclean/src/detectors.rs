use camino::Utf8Path;
use devclean_core::{
    ArtifactCategory, Confidence, CoverageStatus, DetectedArtifact, Detector, DetectorContext,
    DetectorDescriptor, DetectorOutcome, Evidence, EvidenceCode, LogicalCandidateId, Observation,
    ObservationInterest, ProbeKind, ProtectionSignal, RequiredProbeSet, ResourceIdentity,
};
use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DetectorFamily {
    Rust,
    Python,
    Node,
    ElixirErlang,
    Go,
    JvmAndroid,
    Apple,
    BrowserTest,
    EditorAgent,
    LogsDiagnostics,
    General,
}

#[derive(Clone)]
struct Rule {
    family: DetectorFamily,
    basename: &'static str,
    category: ArtifactCategory,
    marker: Option<&'static str>,
    protection: Option<ProtectionSignal>,
}

const RULES: &[Rule] = &[
    Rule {
        family: DetectorFamily::Rust,
        basename: "target",
        category: ArtifactCategory::Build,
        marker: Some("Cargo.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Rust,
        basename: "registry",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Rust,
        basename: "git",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Rust,
        basename: "toolchains",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::Rust,
        basename: "incremental",
        category: ArtifactCategory::Build,
        marker: Some("Cargo.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: "__pycache__",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".pytest_cache",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".mypy_cache",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".ruff_cache",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".tox",
        category: ArtifactCategory::Cache,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".nox",
        category: ArtifactCategory::Cache,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: "wheels",
        category: ArtifactCategory::Cache,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: "pip",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Python,
        basename: "uv",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".eggs",
        category: ArtifactCategory::Cache,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: ".venv",
        category: ArtifactCategory::Dependency,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Python,
        basename: "venv",
        category: ArtifactCategory::Dependency,
        marker: Some("pyproject.toml"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: "node_modules",
        category: ArtifactCategory::Dependency,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".next",
        category: ArtifactCategory::Build,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: "dist",
        category: ArtifactCategory::Build,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".turbo",
        category: ArtifactCategory::Cache,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".nx",
        category: ArtifactCategory::Cache,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".vite",
        category: ArtifactCategory::Cache,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".yarn",
        category: ArtifactCategory::Cache,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".pnpm-store",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Node,
        basename: ".npm",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::ElixirErlang,
        basename: "_build",
        category: ArtifactCategory::Build,
        marker: Some("mix.exs"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::ElixirErlang,
        basename: ".hex",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::ElixirErlang,
        basename: ".cache.rebar3",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::ElixirErlang,
        basename: "deps",
        category: ArtifactCategory::Dependency,
        marker: Some("mix.exs"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Go,
        basename: "go-build",
        category: ArtifactCategory::Cache,
        marker: Some("go.mod"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Go,
        basename: "mod",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::Go,
        basename: "testcache",
        category: ArtifactCategory::Cache,
        marker: Some("go.mod"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: ".gradle",
        category: ArtifactCategory::Cache,
        marker: Some("build.gradle"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: ".m2",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: "caches",
        category: ArtifactCategory::Cache,
        marker: Some("build.gradle"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: "build",
        category: ArtifactCategory::Build,
        marker: Some("build.gradle"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: ".android",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: "sdk",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: "avd",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::JvmAndroid,
        basename: "snapshots",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: "DerivedData",
        category: ArtifactCategory::Build,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: "Archives",
        category: ArtifactCategory::Unknown,
        marker: None,
        protection: Some(ProtectionSignal::Archive),
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: "DeviceSupport",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: "iOS DeviceSupport",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: ".build",
        category: ArtifactCategory::Build,
        marker: Some("Package.swift"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::Apple,
        basename: "CoreSimulator",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "playwright-report",
        category: ArtifactCategory::Log,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "cypress",
        category: ArtifactCategory::Cache,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "screenshots",
        category: ArtifactCategory::Log,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "videos",
        category: ArtifactCategory::Log,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "traces",
        category: ArtifactCategory::Log,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "test-results",
        category: ArtifactCategory::Log,
        marker: Some("package.json"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::BrowserTest,
        basename: "ms-playwright",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: None,
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: ".codex",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: ".cache",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: "indexes",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: "lsp",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UnknownOwnership),
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: ".claude",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::EditorAgent,
        basename: "workspaceStorage",
        category: ArtifactCategory::Cache,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::LogsDiagnostics,
        basename: "logs",
        category: ArtifactCategory::Log,
        marker: Some("log_owner"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::LogsDiagnostics,
        basename: "CrashReporter",
        category: ArtifactCategory::Log,
        marker: None,
        protection: Some(ProtectionSignal::UniqueState),
    },
    Rule {
        family: DetectorFamily::LogsDiagnostics,
        basename: "profiles",
        category: ArtifactCategory::Log,
        marker: Some("generated"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::LogsDiagnostics,
        basename: "benchmarks",
        category: ArtifactCategory::Log,
        marker: Some("generated"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::General,
        basename: "tmp",
        category: ArtifactCategory::Cache,
        marker: Some("generated"),
        protection: None,
    },
    Rule {
        family: DetectorFamily::General,
        basename: "doc",
        category: ArtifactCategory::Build,
        marker: Some("generated"),
        protection: None,
    },
];

const INTERESTS: &[ObservationInterest] = &[
    ObservationInterest::Basename("target"),
    ObservationInterest::Basename("__pycache__"),
    ObservationInterest::Basename(".pytest_cache"),
    ObservationInterest::Basename(".mypy_cache"),
    ObservationInterest::Basename(".ruff_cache"),
    ObservationInterest::Basename(".venv"),
    ObservationInterest::Basename("venv"),
    ObservationInterest::Basename("node_modules"),
    ObservationInterest::Basename(".next"),
    ObservationInterest::Basename("dist"),
    ObservationInterest::Basename("_build"),
    ObservationInterest::Basename("deps"),
    ObservationInterest::Basename("go-build"),
    ObservationInterest::Basename(".gradle"),
    ObservationInterest::Basename("build"),
    ObservationInterest::Basename(".android"),
    ObservationInterest::Basename("DerivedData"),
    ObservationInterest::Basename(".build"),
    ObservationInterest::Basename("CoreSimulator"),
    ObservationInterest::Basename("playwright-report"),
    ObservationInterest::Basename("test-results"),
    ObservationInterest::Basename("ms-playwright"),
    ObservationInterest::Basename(".codex"),
    ObservationInterest::Basename(".claude"),
    ObservationInterest::Basename("workspaceStorage"),
    ObservationInterest::Basename("logs"),
    ObservationInterest::Basename("tmp"),
    ObservationInterest::Basename(".tox"),
    ObservationInterest::Basename(".nox"),
    ObservationInterest::Basename("wheels"),
    ObservationInterest::Basename(".turbo"),
    ObservationInterest::Basename(".nx"),
    ObservationInterest::Basename(".vite"),
    ObservationInterest::Basename(".yarn"),
    ObservationInterest::Basename(".pnpm-store"),
    ObservationInterest::Basename(".hex"),
    ObservationInterest::Basename(".cache.rebar3"),
    ObservationInterest::Basename("mod"),
    ObservationInterest::Basename(".m2"),
    ObservationInterest::Basename("caches"),
    ObservationInterest::Basename("Archives"),
    ObservationInterest::Basename("DeviceSupport"),
    ObservationInterest::Basename("cypress"),
    ObservationInterest::Basename("screenshots"),
    ObservationInterest::Basename("videos"),
    ObservationInterest::Basename("traces"),
    ObservationInterest::Basename(".cache"),
    ObservationInterest::Basename("indexes"),
    ObservationInterest::Basename("registry"),
    ObservationInterest::Basename("git"),
    ObservationInterest::Basename("toolchains"),
    ObservationInterest::Basename("incremental"),
    ObservationInterest::Basename("pip"),
    ObservationInterest::Basename("uv"),
    ObservationInterest::Basename(".eggs"),
    ObservationInterest::Basename(".npm"),
    ObservationInterest::Basename("testcache"),
    ObservationInterest::Basename("sdk"),
    ObservationInterest::Basename("avd"),
    ObservationInterest::Basename("snapshots"),
    ObservationInterest::Basename("iOS DeviceSupport"),
    ObservationInterest::Basename("lsp"),
    ObservationInterest::Basename("CrashReporter"),
    ObservationInterest::Basename("profiles"),
    ObservationInterest::Basename("benchmarks"),
    ObservationInterest::Basename("doc"),
    ObservationInterest::Extension("log"),
    ObservationInterest::Extension("zip"),
    ObservationInterest::Extension("tar"),
    ObservationInterest::Extension("gz"),
    ObservationInterest::Extension("xz"),
    ObservationInterest::Extension("7z"),
    ObservationInterest::Extension("db"),
    ObservationInterest::Extension("sqlite"),
    ObservationInterest::Extension("sqlite3"),
    ObservationInterest::Extension("dump"),
    ObservationInterest::Extension("dmp"),
    ObservationInterest::Extension("core"),
    ObservationInterest::ResourceKind("git_worktree"),
    ObservationInterest::ResourceKind("container"),
    ObservationInterest::ResourceKind("image"),
    ObservationInterest::ResourceKind("layer"),
    ObservationInterest::ResourceKind("build_cache"),
    ObservationInterest::ResourceKind("network"),
    ObservationInterest::ResourceKind("volume"),
    ObservationInterest::ResourceKind("mystery"),
];

#[derive(Default)]
pub struct CatalogDetector {
    metadata: MetadataProbeCache<Vec<String>>,
}

pub fn interests_for_family(family: DetectorFamily) -> Vec<ObservationInterest> {
    RULES
        .iter()
        .filter(|rule| rule.family == family)
        .map(|rule| ObservationInterest::Basename(rule.basename))
        .collect()
}

pub fn mandatory_probes_for(family: DetectorFamily, metadata_backed: bool) -> RequiredProbeSet {
    let mut probes = [
        ProbeKind::ApprovedScope,
        ProbeKind::Rebuildability,
        ProbeKind::FilesystemIdentity,
        ProbeKind::Activity,
        ProbeKind::OpenFiles,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    if metadata_backed
        || matches!(
            family,
            DetectorFamily::BrowserTest
                | DetectorFamily::LogsDiagnostics
                | DetectorFamily::EditorAgent
        )
    {
        probes.insert(ProbeKind::Metadata);
    }
    RequiredProbeSet(probes)
}

impl Detector for CatalogDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: "filesystem-catalog",
            version: 1,
        }
    }
    fn interests(&self) -> &'static [ObservationInterest] {
        INTERESTS
    }
    fn detect(&self, context: DetectorContext<'_>) -> DetectorOutcome {
        let mut artifacts = Vec::new();
        let mut coverage = CoverageStatus::Complete;
        for observation in context.observations {
            match self.detect_one(observation) {
                Ok(Some(value)) => {
                    if value.required_probes.0.contains(&ProbeKind::Metadata) {
                        let status = metadata_coverage(observation);
                        if status != CoverageStatus::Complete {
                            coverage.join_assign(&status);
                        }
                    }
                    artifacts.push(value)
                }
                Ok(None) => {}
                Err(status) => coverage.join_assign(&status),
            }
        }
        let mut outcome = DetectorOutcome::bounded(artifacts, context.artifact_limit);
        outcome.coverage.join_assign(&coverage);
        outcome
    }
}

impl CatalogDetector {
    fn detect_one(
        &self,
        observation: &Observation,
    ) -> Result<Option<DetectedArtifact>, CoverageStatus> {
        match &observation.identity {
            ResourceIdentity::GitWorktree {
                common_dir,
                worktree_id,
            } => {
                return Ok(Some(external_artifact(
                    observation,
                    "git-worktree",
                    common_dir.as_str(),
                    worktree_id,
                    ArtifactCategory::Worktree,
                    [
                        ProbeKind::ApprovedScope,
                        ProbeKind::FilesystemIdentity,
                        ProbeKind::Activity,
                        ProbeKind::OpenFiles,
                        ProbeKind::GitStatus,
                        ProbeKind::GitRegistration,
                        ProbeKind::GitReachability,
                    ],
                )));
            }
            ResourceIdentity::Docker {
                daemon,
                object_kind,
                id,
            } => {
                let category = match object_kind.as_str() {
                    "container" => ArtifactCategory::Container,
                    "image" => ArtifactCategory::Image,
                    "volume" => ArtifactCategory::Volume,
                    "layer" | "build_cache" => ArtifactCategory::Cache,
                    _ => ArtifactCategory::Unknown,
                };
                let unknown = category == ArtifactCategory::Unknown;
                let mut artifact = external_artifact(
                    observation,
                    "docker",
                    daemon,
                    &format!("{object_kind}:{id}"),
                    category,
                    [
                        ProbeKind::Rebuildability,
                        ProbeKind::DockerSnapshot,
                        ProbeKind::DockerReferences,
                    ],
                );
                if unknown {
                    artifact.evidence[0].code = EvidenceCode::Ambiguous;
                }
                return Ok(Some(artifact));
            }
            ResourceIdentity::Filesystem { .. } => {}
        }
        let ResourceIdentity::Filesystem { path } = &observation.identity else {
            unreachable!()
        };
        let Some(basename) = path.file_name() else {
            return Ok(None);
        };
        if let Some(rule) = RULES.iter().find(|rule| rule.basename == basename) {
            if let Some(marker) = rule.marker {
                let marker_present = observation
                    .attributes
                    .get("markers")
                    .is_some_and(|markers| markers.split(',').any(|value| value == marker));
                if !marker_present {
                    return Ok(None);
                }
                let owner = observation
                    .attributes
                    .get("project_owner")
                    .map(String::as_str)
                    .unwrap_or("unowned");
                let family = format!("{:?}", rule.family);
                if metadata_coverage(observation) == CoverageStatus::Complete {
                    let markers = self.metadata.get_or_probe(owner, &family, || {
                        Ok(observation
                            .attributes
                            .get("markers")
                            .map(|value| value.split(',').map(str::to_owned).collect())
                            .unwrap_or_default())
                    });
                    if !markers.is_ok_and(|markers| markers.iter().any(|value| value == marker)) {
                        return Ok(None);
                    }
                }
            } else if rule.protection.is_none()
                && observation
                    .attributes
                    .get("known_cache")
                    .map(String::as_str)
                    != Some("true")
            {
                return Ok(None);
            }
            return Ok(Some(artifact(
                observation,
                path,
                rule.family,
                rule.category.clone(),
                rule.protection.clone(),
                rule.marker.is_some(),
            )));
        }
        let extension = path.extension().unwrap_or_default();
        let (family, category, protection) = match extension {
            "log" => (DetectorFamily::LogsDiagnostics, ArtifactCategory::Log, None),
            "zip" | "tar" | "gz" | "xz" | "7z" => (
                DetectorFamily::General,
                ArtifactCategory::Unknown,
                Some(ProtectionSignal::Archive),
            ),
            "db" | "sqlite" | "sqlite3" => (
                DetectorFamily::General,
                ArtifactCategory::Unknown,
                Some(ProtectionSignal::Database),
            ),
            "dump" | "dmp" | "core" => (
                DetectorFamily::LogsDiagnostics,
                ArtifactCategory::Log,
                Some(ProtectionSignal::UniqueState),
            ),
            _ => return Ok(None),
        };
        if extension == "log"
            && observation.attributes.get("known_log").map(String::as_str) != Some("true")
        {
            return Ok(None);
        }
        Ok(Some(artifact(
            observation,
            path,
            family,
            category,
            protection,
            false,
        )))
    }
}

fn metadata_coverage(observation: &Observation) -> CoverageStatus {
    match observation
        .attributes
        .get("metadata_coverage")
        .map(String::as_str)
    {
        Some("complete") => CoverageStatus::Complete,
        Some("unsupported") => CoverageStatus::Unsupported,
        Some("skipped") => CoverageStatus::Skipped,
        Some("partial") => CoverageStatus::Partial,
        Some("failed") => CoverageStatus::Failed,
        Some("timed_out") => CoverageStatus::TimedOut,
        Some("truncated") => CoverageStatus::Truncated,
        Some("stale") => CoverageStatus::Stale,
        Some("unknown") | Some(_) | None => CoverageStatus::Unknown,
    }
}

fn external_artifact<const N: usize>(
    observation: &Observation,
    detector: &str,
    owner: &str,
    location: &str,
    category: ArtifactCategory,
    probes: [ProbeKind; N],
) -> DetectedArtifact {
    DetectedArtifact {
        id: LogicalCandidateId::derive(detector, owner, location),
        identity: observation.identity.clone(),
        fingerprint: observation.fingerprint.clone(),
        category,
        evidence: vec![Evidence {
            code: EvidenceCode::KnownCache,
            source: detector.into(),
            confidence: Confidence::High,
        }],
        required_probes: probes.into_iter().collect(),
        protection_signals: observation_protections(observation),
    }
}

fn observation_protections(observation: &Observation) -> Vec<ProtectionSignal> {
    [
        ("active", ProtectionSignal::Active),
        ("open", ProtectionSignal::OpenFile),
        ("dirty", ProtectionSignal::Dirty),
        ("untracked", ProtectionSignal::Untracked),
        ("unpublished", ProtectionSignal::Unpublished),
        ("unreachable", ProtectionSignal::UnreachableCommit),
        ("volume", ProtectionSignal::DockerVolume),
        ("inaccessible", ProtectionSignal::Inaccessible),
        ("shared", ProtectionSignal::UnknownOwnership),
    ]
    .into_iter()
    .filter_map(|(key, signal)| {
        observation
            .attributes
            .get(key)
            .is_some_and(|value| value == "true")
            .then_some(signal)
    })
    .collect()
}

fn artifact(
    observation: &Observation,
    path: &Utf8Path,
    family: DetectorFamily,
    category: ArtifactCategory,
    protection: Option<ProtectionSignal>,
    metadata_backed: bool,
) -> DetectedArtifact {
    let owner = observation
        .attributes
        .get("project_owner")
        .map(String::as_str)
        .unwrap_or("unowned");
    let mut protections: Vec<_> = protection.into_iter().collect();
    for (attribute, signal) in [
        ("active", ProtectionSignal::Active),
        ("open", ProtectionSignal::OpenFile),
        ("failed_test", ProtectionSignal::UniqueState),
        ("required_sdk", ProtectionSignal::UniqueState),
        ("retained", ProtectionSignal::UniqueState),
        ("recent", ProtectionSignal::UniqueState),
        ("dirty", ProtectionSignal::Dirty),
        ("untracked", ProtectionSignal::Untracked),
        ("shared", ProtectionSignal::UnknownOwnership),
    ] {
        if observation
            .attributes
            .get(attribute)
            .is_some_and(|value| value == "true")
        {
            protections.push(signal);
        }
    }
    protections.sort();
    protections.dedup();
    DetectedArtifact {
        id: LogicalCandidateId::derive("filesystem-catalog", owner, path.as_str()),
        identity: observation.identity.clone(),
        fingerprint: observation.fingerprint.clone(),
        category,
        evidence: vec![Evidence {
            code: EvidenceCode::GeneratedLayout,
            source: format!("{:?}", family),
            confidence: Confidence::High,
        }],
        required_probes: mandatory_probes_for(family, metadata_backed),
        protection_signals: protections,
    }
}

enum ProbeState<T> {
    Loading,
    Ready(Result<T, String>),
}
pub struct MetadataProbeCache<T> {
    values: Mutex<BTreeMap<(String, String), ProbeState<T>>>,
    ready: Condvar,
}
impl<T> Default for MetadataProbeCache<T> {
    fn default() -> Self {
        Self {
            values: Mutex::new(BTreeMap::new()),
            ready: Condvar::new(),
        }
    }
}
impl<T: Clone> MetadataProbeCache<T> {
    pub fn get_or_probe(
        &self,
        owner: &str,
        tool: &str,
        probe: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let key = (owner.to_owned(), tool.to_owned());
        let mut values = self.values.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match values.get(&key) {
                Some(ProbeState::Ready(value)) => return value.clone(),
                Some(ProbeState::Loading) => {
                    values = self.ready.wait(values).unwrap_or_else(|p| p.into_inner())
                }
                None => {
                    values.insert(key.clone(), ProbeState::Loading);
                    break;
                }
            }
        }
        drop(values);
        let result = probe();
        let mut values = self.values.lock().unwrap_or_else(|p| p.into_inner());
        values.insert(key, ProbeState::Ready(result.clone()));
        self.ready.notify_all();
        result
    }
}
