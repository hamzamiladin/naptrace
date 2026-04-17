use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use std::path::Path;

use crate::retrieve::CandidateSite;
use crate::Language;

pub use naptrace_joern::cpg::{CpgPath, CpgNode};

/// A candidate enriched with CPG path information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlicedCandidate {
    /// The original candidate site.
    pub candidate: CandidateSite,
    /// CPG paths reaching this candidate (empty if Joern unavailable).
    pub cpg_paths: Vec<CpgPath>,
    /// Whether CPG slicing was performed.
    pub sliced: bool,
}

/// Slice CPG paths for each candidate site.
///
/// If Joern is not available, returns candidates with empty paths
/// and `sliced: false` — downstream stages still work, just with
/// less information for the LLM to reason about.
pub async fn slice_candidates(
    candidates: Vec<CandidateSite>,
    target_dir: &Path,
    language: Language,
) -> Result<Vec<SlicedCandidate>> {
    // Ensure Java + Joern are available (auto-installs both if needed)
    match naptrace_joern::download::ensure_joern().await {
        Ok(install_dir) => {
            info!(path = %install_dir.display(), "Joern ready");
        }
        Err(e) => {
            warn!("Joern setup failed: {e} — skipping CPG slicing");
            return Ok(candidates_without_cpg(candidates));
        }
    }

    // Build CPG
    let lang_str = joern_language_name(language);
    let cpg_path = match naptrace_joern::cpg::build_cpg(target_dir, lang_str) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to build CPG: {e} — skipping CPG slicing");
            return Ok(candidates_without_cpg(candidates));
        }
    };

    // Query paths for each candidate
    let mut sliced = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let paths = naptrace_joern::cpg::query_paths(
            &cpg_path,
            &candidate.function_name,
            &candidate.file_path,
            candidate.start_line,
        )
        .unwrap_or_default();

        info!(
            function = %candidate.function_name,
            paths = paths.len(),
            "sliced candidate"
        );

        sliced.push(SlicedCandidate {
            candidate,
            cpg_paths: paths,
            sliced: true,
        });
    }

    Ok(sliced)
}

/// Wrap candidates without CPG information.
fn candidates_without_cpg(candidates: Vec<CandidateSite>) -> Vec<SlicedCandidate> {
    candidates
        .into_iter()
        .map(|candidate| SlicedCandidate {
            candidate,
            cpg_paths: Vec::new(),
            sliced: false,
        })
        .collect()
}

/// Map our Language enum to Joern's language name.
fn joern_language_name(lang: Language) -> &'static str {
    match lang {
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Java => "java",
        Language::Python => "python",
        Language::Javascript => "javascript",
        Language::Typescript => "javascript", // Joern uses JS parser for TS
        Language::Go => "golang",
        Language::Rust => "c", // Joern doesn't have native Rust support; use C as fallback
    }
}
