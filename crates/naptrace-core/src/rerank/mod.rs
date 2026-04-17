use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::prompt::load_prompt;
use crate::retrieve::CandidateSite;
use crate::signature::VulnSignature;

/// Result of reranking a candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RerankResult {
    function_name: String,
    role: String, // "vulnerable", "sanitizer", "unrelated"
    relevance: u8,
}

/// Structural signals that suggest a function is a sanitizer, not a vulnerability.
const SANITIZER_NAME_HINTS: &[&str] = &[
    "check",
    "valid",
    "verify",
    "safe",
    "guard",
    "sanitize",
    "assert",
    "ensure",
    "is_ok",
    "bound",
    "limit",
    "clamp",
    "overflow",
    "underflow",
];

/// Rerank candidates: filter out sanitizers and unrelated functions.
/// Returns only candidates likely to be actual vulnerabilities.
pub async fn rerank(
    candidates: Vec<CandidateSite>,
    signature: &VulnSignature,
    llm: &dyn naptrace_llm::LlmClient,
    model_override: Option<&str>,
) -> Result<Vec<CandidateSite>> {
    if candidates.is_empty() {
        return Ok(candidates);
    }

    // Tier 1: Structural pre-filter
    let scored: Vec<(CandidateSite, f32)> = candidates
        .into_iter()
        .map(|c| {
            let penalty = structural_sanitizer_score(&c);
            (c, penalty)
        })
        .collect();

    // Tier 2: Batch LLM reranker
    let prompt_template =
        load_prompt("rerank_candidates").context("failed to load rerank_candidates prompt")?;

    let model = model_override.unwrap_or(&prompt_template.meta.model);

    // Build a batch prompt with all candidate signatures
    let mut candidates_text = String::new();
    for (i, (c, penalty)) in scored.iter().enumerate() {
        let first_lines: String = c.body.lines().take(5).collect::<Vec<_>>().join("\n");
        let all_lines: Vec<&str> = c.body.lines().collect();
        let last_lines: String = all_lines[all_lines.len().saturating_sub(3)..].join("\n");
        candidates_text.push_str(&format!(
            "\n### Candidate {} — {}() at {}:{}-{} (structural_penalty: {:.1})\n```\n{}\n...\n{}\n```\n",
            i + 1,
            c.function_name,
            c.file_path,
            c.start_line,
            c.end_line,
            penalty,
            first_lines,
            last_lines,
        ));
    }

    let user_content = format!(
        "## Vulnerability Brief\n{}\n\n## Bug Class: {}\n\n## Candidates to classify:\n{}",
        signature.nl_brief, signature.bug_class, candidates_text,
    );

    let request = naptrace_llm::LlmRequest {
        model: model.to_string(),
        messages: vec![
            naptrace_llm::Message::system(prompt_template.body.clone()),
            naptrace_llm::Message::user(user_content),
        ],
        temperature: prompt_template.meta.temperature,
        max_tokens: prompt_template.meta.max_tokens,
    };

    let response = match llm.complete(&request).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("reranker LLM call failed: {e} — skipping rerank");
            return Ok(scored.into_iter().map(|(c, _)| c).collect());
        }
    };

    // Parse the reranker's response
    let json_str = crate::signature::extract_json_block(&response.content);
    let rerank_results: Vec<RerankResult> = serde_json::from_str(json_str).unwrap_or_default();

    // Apply reranking
    let mut kept = Vec::new();
    for (i, (candidate, _penalty)) in scored.into_iter().enumerate() {
        let result = rerank_results.get(i);

        // Only filter if explicitly classified as sanitizer
        // Don't filter on low relevance alone — small models give unreliable scores
        let dominated = result
            .map(|r| r.role == "sanitizer")
            .unwrap_or(false);

        if dominated {
            info!(
                function = %candidate.function_name,
                role = result.map(|r| r.role.as_str()).unwrap_or("unknown"),
                "filtered by reranker"
            );
        } else {
            kept.push(candidate);
        }
    }

    info!(
        before = rerank_results.len(),
        after = kept.len(),
        "reranking complete"
    );

    Ok(kept)
}

/// Compute a structural sanitizer score (0.0 = likely vulnerable, 1.0 = likely sanitizer).
fn structural_sanitizer_score(candidate: &CandidateSite) -> f32 {
    let name_lower = candidate.function_name.to_lowercase();
    let mut score = 0.0f32;

    // Name-based signals
    for hint in SANITIZER_NAME_HINTS {
        if name_lower.contains(hint) {
            score += 0.3;
            break;
        }
    }

    // Body-based signals
    let lines: Vec<&str> = candidate.body.lines().collect();
    let total = lines.len().max(1) as f32;

    // High ratio of if-statements suggests validation logic
    let if_count = lines
        .iter()
        .filter(|l| l.trim_start().starts_with("if"))
        .count() as f32;
    if if_count / total > 0.3 {
        score += 0.2;
    }

    // Returns error codes
    let returns_error = lines.iter().any(|l| {
        let t = l.trim();
        t.starts_with("return -1")
            || t.starts_with("return false")
            || t.starts_with("return 1;") // often error code
            || t.contains("return Err(")
            || t.contains("bail!")
    });
    if returns_error {
        score += 0.1;
    }

    score.min(1.0)
}
