use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

use crate::retrieve::CandidateSite;
use crate::signature::VulnSignature;
use crate::Language;

pub use naptrace_joern::cpg::{CpgNode, CpgPath};

/// A candidate enriched with CPG path information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlicedCandidate {
    /// The original candidate site.
    pub candidate: CandidateSite,
    /// CPG paths reaching this candidate (empty if Joern unavailable).
    pub cpg_paths: Vec<CpgPath>,
    /// Whether CPG slicing was performed.
    pub sliced: bool,
    /// Minimal code slice extracted from CPG (reduced context for LLM).
    pub code_slice: Option<String>,
}

/// Slice CPG paths for each candidate site.
/// Uses the vulnerability signature for targeted queries when available.
pub async fn slice_candidates(
    candidates: Vec<CandidateSite>,
    target_dir: &Path,
    language: Language,
    signature: Option<&VulnSignature>,
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

        // Build a minimal code slice from CPG path data
        let code_slice = build_code_slice(&paths, &candidate, signature);

        info!(
            function = %candidate.function_name,
            paths = paths.len(),
            has_slice = code_slice.is_some(),
            "sliced candidate"
        );

        sliced.push(SlicedCandidate {
            candidate,
            cpg_paths: paths,
            sliced: true,
            code_slice,
        });
    }

    Ok(sliced)
}

/// Build a minimal code slice from CPG paths.
/// Extracts only the lines relevant to the vulnerability pattern,
/// reducing context by 67-90% (per LLMxCPG paper).
fn build_code_slice(
    paths: &[CpgPath],
    _candidate: &CandidateSite,
    signature: Option<&VulnSignature>,
) -> Option<String> {
    if paths.is_empty() {
        return None;
    }

    let mut slice_lines = Vec::new();

    // Add source nodes (function parameters / inputs)
    for path in paths {
        for source in &path.sources {
            if !source.code.is_empty() {
                slice_lines.push(format!("/* source */ {}", source.code));
            }
        }

        // Add path nodes (calls, assignments, arithmetic)
        for node in &path.path_nodes {
            if !node.code.is_empty() {
                let label = match node.node_type.as_str() {
                    "arithmetic" => "/* arithmetic */",
                    "assignment" => "/* assignment */",
                    "call" => "/* call */",
                    "dataflow" => "/* dataflow */",
                    _ => "/**/",
                };
                slice_lines.push(format!("{} {}", label, node.code));
            }
        }

        // Add sanitizer info
        for san in &path.sanitizers {
            slice_lines.push(format!("/* sanitizer: {} */", san));
        }

        // Add type constraints
        for constraint in &path.constraints {
            slice_lines.push(format!("// {}", constraint));
        }
    }

    // Add sink description from signature if available
    if let Some(sig) = signature {
        if let Some(ref sink) = sig.sink_description {
            slice_lines.push(format!("/* sink: {} */", sink));
        }
    }

    if slice_lines.is_empty() {
        None
    } else {
        Some(slice_lines.join("\n"))
    }
}

/// Wrap candidates without CPG information.
fn candidates_without_cpg(candidates: Vec<CandidateSite>) -> Vec<SlicedCandidate> {
    candidates
        .into_iter()
        .map(|candidate| SlicedCandidate {
            candidate,
            cpg_paths: Vec::new(),
            sliced: false,
            code_slice: None,
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
        Language::Typescript => "javascript",
        Language::Go => "golang",
        Language::Rust => "c",
    }
}
