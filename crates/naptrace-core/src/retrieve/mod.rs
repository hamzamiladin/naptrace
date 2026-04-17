pub mod cache;
pub mod extract;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

use crate::signature::VulnSignature;
use crate::Language;
pub use extract::ExtractedFunction;

/// A candidate site that may be a variant of the original vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateSite {
    pub file_path: String,
    pub function_name: String,
    pub body: String,
    pub start_line: u32,
    pub end_line: u32,
    pub language: Language,
    /// Cosine similarity to the vulnerability signature embedding.
    pub similarity: f32,
}

/// Retrieve candidate sites from a target directory that are similar to the
/// vulnerability signature.
pub async fn retrieve(
    target_dir: &Path,
    signature: &VulnSignature,
    embedder: &dyn naptrace_embed::Embedder,
    languages: &[Language],
    top_k: usize,
) -> Result<Vec<CandidateSite>> {
    // Step 1: Extract functions from target
    info!(target = %target_dir.display(), "extracting functions from target");
    let functions = extract::extract_functions(target_dir, languages)
        .context("failed to extract functions from target")?;

    if functions.is_empty() {
        bail!(
            "no functions found in {} — check the target path and language filters",
            target_dir.display()
        );
    }

    info!(count = functions.len(), "extracted functions");

    // Step 2: Build the query from the signature
    let query_text = build_query_text(signature);

    // Step 3: Embed the query
    let query_embeddings = embedder
        .embed(&[query_text])
        .await
        .context("failed to embed query")?;

    let query_embedding = query_embeddings
        .into_iter()
        .next()
        .context("empty embedding response for query")?;

    // Step 4: Embed functions (check cache first)
    let mut all_embeddings: Vec<Vec<f32>>;

    if let Some(cached) = cache::load_cached(target_dir) {
        if cached.len() == functions.len() {
            all_embeddings = cached;
        } else {
            info!("cache size mismatch — re-embedding");
            all_embeddings = Vec::with_capacity(functions.len());
        }
    } else {
        all_embeddings = Vec::with_capacity(functions.len());
    }

    if all_embeddings.is_empty() {
        let batch_size = 64;
        let total_batches = functions.len().div_ceil(batch_size);

        for (batch_idx, chunk) in functions.chunks(batch_size).enumerate() {
            info!(
                batch = batch_idx + 1,
                total = total_batches,
                "embedding batch ({}/{})",
                batch_idx + 1,
                total_batches,
            );

            let texts: Vec<String> = chunk.iter().map(|f| truncate_for_embed(&f.body)).collect();

            let embeddings = embedder
                .embed(&texts)
                .await
                .context("failed to embed function batch")?;

            all_embeddings.extend(embeddings);
        }

        info!(count = all_embeddings.len(), "embedded all functions");

        // Save to cache
        cache::save_cache(target_dir, &all_embeddings);
    } // end of cache miss block

    // Step 5: Compute similarities and rank
    let mut scored: Vec<(usize, f32)> = all_embeddings
        .iter()
        .enumerate()
        .map(|(i, emb)| {
            let sim = naptrace_embed::cosine_similarity(&query_embedding, emb);
            (i, sim)
        })
        .collect();

    // Sort by similarity descending
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take top-K
    let candidates: Vec<CandidateSite> = scored
        .into_iter()
        .take(top_k)
        .filter(|(_, sim)| *sim > 0.0)
        .map(|(idx, sim)| {
            let func = &functions[idx];
            CandidateSite {
                file_path: func.file_path.clone(),
                function_name: func.name.clone(),
                body: func.body.clone(),
                start_line: func.start_line,
                end_line: func.end_line,
                language: func.language,
                similarity: sim,
            }
        })
        .collect();

    info!(count = candidates.len(), "candidate sites retrieved");

    Ok(candidates)
}

/// Build a query string from the vulnerability signature for embedding.
fn build_query_text(sig: &VulnSignature) -> String {
    format!(
        "{}\n{}\n{}",
        sig.nl_brief, sig.root_cause, sig.vulnerable_pattern,
    )
}

/// Truncate function body to a reasonable size for embedding.
/// Most embedding models have a token limit; truncating to ~2000 chars
/// covers the function signature and most of the body.
fn truncate_for_embed(body: &str) -> String {
    const MAX_CHARS: usize = 3000;
    if body.len() <= MAX_CHARS {
        body.to_string()
    } else {
        body[..MAX_CHARS].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_from_signature() {
        let sig = VulnSignature {
            root_cause: "Integer overflow".to_string(),
            vulnerable_pattern: "(binary_expression)".to_string(),
            required_preconditions: vec![],
            sanitizer_gaps: vec![],
            nl_brief: "Unchecked addition of user-controlled integers.".to_string(),
            bug_class: "INTEGER_OVERFLOW".to_string(),
            confidence: 8,
            abstract_invariant: None,
            negative_pattern: None,
            source_description: None,
            sink_description: None,
        };

        let query = build_query_text(&sig);
        assert!(query.contains("Integer overflow"));
        assert!(query.contains("binary_expression"));
        assert!(query.contains("Unchecked addition"));
    }

    #[test]
    fn truncate_short_text() {
        let short = "fn foo() {}";
        assert_eq!(truncate_for_embed(short), short);
    }

    #[test]
    fn truncate_long_text() {
        let long = "x".repeat(5000);
        assert_eq!(truncate_for_embed(&long).len(), 3000);
    }
}
