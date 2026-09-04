use camino::Utf8PathBuf;
use devclean_core::ApprovedRootIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub approved_roots: BTreeSet<Utf8PathBuf>,
    #[serde(default)]
    pub approved_caches: BTreeSet<Utf8PathBuf>,
    #[serde(default)]
    pub exclusions: BTreeSet<Utf8PathBuf>,
    pub docker: Option<DockerScope>,
    #[serde(default)]
    pub presentation: Presentation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DockerScope {
    pub context: String,
    pub endpoint: String,
    pub engine_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerScopeIdentity {
    pub context: String,
    pub endpoint: String,
    pub engine_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyFingerprint(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationFingerprint(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTraversalScope {
    pub roots: Vec<Utf8PathBuf>,
    pub root_identities: Vec<ApprovedRootIdentity>,
    pub caches: BTreeSet<Utf8PathBuf>,
    pub exclusions: Vec<Utf8PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    #[serde(default)]
    pub terminal_rows: usize,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }
    pub fn safety_fingerprint(&self) -> SafetyFingerprint {
        let material = serde_json::to_string(&(
            self.approved_roots.clone(),
            self.approved_caches.clone(),
            self.exclusions.clone(),
            self.docker
                .as_ref()
                .map(|d| (&d.context, &d.endpoint, &d.engine_id)),
        ))
        .expect("serializable config");
        SafetyFingerprint(blake3::hash(material.as_bytes()).to_hex().to_string())
    }
    pub fn presentation_fingerprint(&self) -> PresentationFingerprint {
        PresentationFingerprint(
            blake3::hash(
                serde_json::to_string(&self.presentation)
                    .expect("serializable presentation")
                    .as_bytes(),
            )
            .to_hex()
            .to_string(),
        )
    }
    pub fn authorized_traversal_scope(&self) -> Result<AuthorizedTraversalScope, String> {
        let mut roots = Vec::new();
        let mut caches = BTreeSet::new();
        for configured in self.approved_roots.iter().chain(&self.approved_caches) {
            let identity = ApprovedRootIdentity::inspect(configured)
                .map_err(|error| format!("invalid approved traversal root: {error}"))?;
            if self.approved_caches.contains(configured) {
                caches.insert(identity.path.clone());
            }
            roots.push(identity);
        }
        roots.sort_by(|left, right| left.path.cmp(&right.path));
        let mut root_identities = Vec::<ApprovedRootIdentity>::new();
        for root in roots {
            if root_identities
                .iter()
                .any(|parent| root.path.starts_with(&parent.path))
            {
                continue;
            }
            root_identities.retain(|child| !child.path.starts_with(&root.path));
            root_identities.push(root);
        }
        let normalized_roots: Vec<_> = root_identities
            .iter()
            .map(|identity| identity.path.clone())
            .collect();

        let mut exclusions = Vec::<Utf8PathBuf>::new();
        for configured in &self.exclusions {
            let metadata = std::fs::symlink_metadata(configured)
                .map_err(|error| format!("invalid exclusion: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("exclusion must not be a symlink".into());
            }
            let canonical = std::fs::canonicalize(configured)
                .map_err(|error| format!("invalid exclusion: {error}"))?;
            let canonical = Utf8PathBuf::from_path_buf(canonical)
                .map_err(|_| "exclusion path must be UTF-8".to_string())?;
            if &canonical != configured {
                return Err(
                    "exclusion must be an absolute canonical path without symlink aliases".into(),
                );
            }
            if !normalized_roots
                .iter()
                .any(|root| canonical.starts_with(root))
            {
                return Err("exclusion must remain inside an approved traversal root".into());
            }
            exclusions.push(canonical);
        }
        exclusions.sort();
        let mut normalized_exclusions = Vec::<Utf8PathBuf>::new();
        for exclusion in exclusions {
            if normalized_exclusions
                .iter()
                .any(|parent| exclusion.starts_with(parent))
            {
                continue;
            }
            normalized_exclusions.retain(|child| !child.starts_with(&exclusion));
            normalized_exclusions.push(exclusion);
        }
        Ok(AuthorizedTraversalScope {
            roots: normalized_roots,
            root_identities,
            caches,
            exclusions: normalized_exclusions,
        })
    }
    pub fn approved_docker(&self) -> Result<Option<DockerScopeIdentity>, &'static str> {
        self.docker
            .as_ref()
            .map(|d| {
                let authority = d
                    .endpoint
                    .split_once("://")
                    .map(|(_, rest)| rest.split('/').next().unwrap_or(rest))
                    .unwrap_or(&d.endpoint);
                if authority.contains('@') {
                    return Err("Docker endpoint must not embed credentials");
                }
                if d.context.is_empty() || d.endpoint.is_empty() || d.engine_id.is_empty() {
                    return Err("Docker identity fields must be non-empty");
                }
                Ok(DockerScopeIdentity {
                    context: d.context.clone(),
                    endpoint: d.endpoint.clone(),
                    engine_id: d.engine_id.clone(),
                })
            })
            .transpose()
    }
    pub fn import_proposed(input: &str, roots_approved: bool) -> Result<Self, String> {
        if !roots_approved {
            return Err("imported roots require explicit approval".into());
        }
        Self::parse(input).map_err(|e| e.to_string())
    }
}
