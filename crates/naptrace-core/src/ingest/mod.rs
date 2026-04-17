mod diff_parser;
mod source;

use anyhow::{bail, Result};
use tracing::info;

use crate::{Language, VulnSeed};

pub use diff_parser::parse_unified_diff;
pub use source::PatchSource;

/// Ingest a patch from any supported source and produce a VulnSeed.
pub async fn ingest(patch_source: &str, _target: &str) -> Result<VulnSeed> {
    let source = PatchSource::parse(patch_source)?;

    info!(?source, "ingesting patch");

    let (raw_diff, commit_msg, cve_id) = source.fetch().await?;

    if raw_diff.trim().is_empty() {
        bail!("patch source produced an empty diff");
    }

    let patched_files = parse_unified_diff(&raw_diff)?;

    if patched_files.is_empty() {
        bail!("no files found in the diff — is this a valid unified diff?");
    }

    // Detect primary language from patched files
    let language = detect_language(&patched_files);

    Ok(VulnSeed {
        cve_id,
        patched_files,
        commit_msg,
        cve_metadata: None, // NVD fetch will be added in a follow-up
        language,
        raw_diff,
    })
}

/// Detect the primary language from patched file paths.
/// Uses majority vote across files, favoring C/C++ when tied.
fn detect_language(files: &[crate::PatchedFile]) -> Language {
    let mut counts = std::collections::HashMap::new();
    for f in files {
        if let Some(lang) = f.language {
            *counts.entry(lang).or_insert(0u32) += 1;
        }
    }

    counts
        .into_iter()
        .max_by_key(|(lang, count)| {
            // Favor C/C++ when tied (most common for CVE variant analysis)
            let tiebreak = match lang {
                Language::C => 1,
                Language::Cpp => 1,
                _ => 0,
            };
            (*count, tiebreak)
        })
        .map(|(lang, _)| lang)
        .unwrap_or(Language::C)
}
