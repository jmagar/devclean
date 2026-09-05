pub mod service;

use devclean_core::{AdvisoryCandidate, ArtifactCategory, ResourceIdentity, Tier};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TierFilter {
    #[default]
    All,
    Safe,
    Review,
    Protected,
    Unknown,
}

impl TierFilter {
    pub fn matches(self, tier: Tier) -> bool {
        matches!(self, Self::All)
            || matches!(
                (self, tier),
                (Self::Safe, Tier::Safe)
                    | (Self::Review, Tier::Review)
                    | (Self::Protected, Tier::Protected)
                    | (Self::Unknown, Tier::Unknown)
            )
    }
}

pub fn filter_candidates(
    candidates: &[AdvisoryCandidate],
    filter: TierFilter,
) -> Vec<&AdvisoryCandidate> {
    candidates
        .iter()
        .filter(|candidate| filter.matches(candidate.tier))
        .collect()
}

pub fn candidate_location(candidate: &AdvisoryCandidate) -> String {
    match &candidate.identity {
        ResourceIdentity::Filesystem { path } => path.to_string(),
        ResourceIdentity::Docker {
            object_kind, id, ..
        } => format!("Docker {object_kind} · {id}"),
        ResourceIdentity::GitWorktree { worktree_id, .. } => {
            format!("Git worktree · {worktree_id}")
        }
    }
}

pub fn category_label(category: &ArtifactCategory) -> &'static str {
    match category {
        ArtifactCategory::Build => "Build output",
        ArtifactCategory::Cache => "Cache",
        ArtifactCategory::Dependency => "Dependencies",
        ArtifactCategory::Log => "Logs",
        ArtifactCategory::Worktree => "Worktree",
        ArtifactCategory::Container => "Container",
        ArtifactCategory::Image => "Image",
        ArtifactCategory::Volume => "Volume",
        ArtifactCategory::Unknown => "Unknown",
    }
}

pub fn format_bytes(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return "Size unavailable".into();
    };
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_format_is_compact_and_honest_about_unknown_values() {
        assert_eq!(format_bytes(None), "Size unavailable");
        assert_eq!(format_bytes(Some(999)), "999 B");
        assert_eq!(format_bytes(Some(1_500_000)), "1.5 MB");
    }

    #[test]
    fn tier_filter_does_not_blur_protected_and_review_candidates() {
        assert!(TierFilter::All.matches(Tier::Protected));
        assert!(TierFilter::Protected.matches(Tier::Protected));
        assert!(!TierFilter::Review.matches(Tier::Protected));
    }
}
