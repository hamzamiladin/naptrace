use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::prompt::load_prompt;
use crate::VulnSeed;

/// Output of Stage 2 — the structural vulnerability signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSignature {
    pub root_cause: String,
    pub vulnerable_pattern: String,
    pub required_preconditions: Vec<String>,
    pub sanitizer_gaps: Vec<String>,
    pub nl_brief: String,
    pub bug_class: String,
    pub confidence: u8,
}

/// Distill a vulnerability signature from a VulnSeed using an LLM.
pub async fn distill(
    seed: &VulnSeed,
    llm: &dyn naptrace_llm::LlmClient,
    model_override: Option<&str>,
) -> Result<VulnSignature> {
    let prompt_template = load_prompt("distill_signature")
        .context("failed to load distill_signature prompt")?;

    // Build the context for the prompt
    let diff_text = build_diff_context(seed);
    let pre_patch = build_pre_patch_context(seed);
    let post_patch = build_post_patch_context(seed);
    let commit_msg = seed.commit_msg.as_deref().unwrap_or("(no commit message)");
    let cve_info = seed
        .cve_id
        .as_deref()
        .unwrap_or("(no CVE ID provided)");

    let user_content = format!(
        "## Pre-patch source\n\
         ```\n{pre_patch}\n```\n\n\
         ## Post-patch source\n\
         ```\n{post_patch}\n```\n\n\
         ## Unified diff\n\
         ```diff\n{diff_text}\n```\n\n\
         ## Commit message\n\
         {commit_msg}\n\n\
         ## CVE metadata\n\
         {cve_info}"
    );

    let model = model_override.unwrap_or(&prompt_template.meta.model);

    info!(
        model,
        temperature = prompt_template.meta.temperature,
        "distilling vulnerability signature via LLM"
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

    let response = llm.complete(&request).await
        .context("LLM call failed during signature distillation")?;

    info!(
        output_tokens = response.usage.as_ref().map(|u| u.output_tokens),
        "received LLM response"
    );

    parse_signature_response(&response.content)
}

/// Parse the LLM's JSON response into a VulnSignature.
fn parse_signature_response(content: &str) -> Result<VulnSignature> {
    // The LLM may wrap JSON in ```json ... ``` — strip it
    let json_str = extract_json_block(content);

    let sig: VulnSignature = serde_json::from_str(json_str)
        .with_context(|| {
            format!(
                "failed to parse LLM signature response as JSON.\n\
                 Raw response:\n{content}"
            )
        })?;

    if sig.confidence > 10 {
        bail!("LLM returned confidence > 10: {}", sig.confidence);
    }

    Ok(sig)
}

/// Extract a JSON block from LLM output, handling ```json fences.
fn extract_json_block(content: &str) -> &str {
    let trimmed = content.trim();

    // Try to find ```json ... ``` block
    if let Some(start) = trimmed.find("```json") {
        let after_fence = &trimmed[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }

    // Try to find ``` ... ``` block
    if let Some(start) = trimmed.find("```") {
        let after_fence = &trimmed[start + 3..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }

    // Assume raw JSON
    trimmed
}

/// Build the diff context string from patched files.
fn build_diff_context(seed: &VulnSeed) -> String {
    let mut out = String::new();
    for file in &seed.patched_files {
        for hunk in &file.hunks {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("--- a/{}\n+++ b/{}\n", file.path, file.path));
            out.push_str(&format!(
                "@@ -{},{} +{},{} @@\n",
                hunk.old_start, hunk.old_lines, hunk.new_start, hunk.new_lines
            ));
            out.push_str(&hunk.content);
        }
    }
    out
}

/// Build pre-patch context — the removed lines from all hunks.
fn build_pre_patch_context(seed: &VulnSeed) -> String {
    if let Some(file) = seed.patched_files.first() {
        if let Some(ref src) = file.pre_patch_source {
            return src.clone();
        }
    }

    // Fall back to reconstructing from removed lines
    let mut out = String::new();
    for file in &seed.patched_files {
        out.push_str(&format!("// {}\n", file.path));
        for hunk in &file.hunks {
            for line in &hunk.removed_lines {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Build post-patch context — the added lines from all hunks.
fn build_post_patch_context(seed: &VulnSeed) -> String {
    if let Some(file) = seed.patched_files.first() {
        if let Some(ref src) = file.post_patch_source {
            return src.clone();
        }
    }

    // Fall back to reconstructing from added lines
    let mut out = String::new();
    for file in &seed.patched_files {
        out.push_str(&format!("// {}\n", file.path));
        for hunk in &file.hunks {
            for line in &hunk.added_lines {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_from_fenced_block() {
        let content = r#"Here is the analysis:

```json
{"root_cause": "test", "confidence": 7}
```

Done."#;
        let json = extract_json_block(content);
        assert!(json.starts_with('{'));
        assert!(json.contains("root_cause"));
    }

    #[test]
    fn extract_raw_json() {
        let content = r#"{"root_cause": "test"}"#;
        let json = extract_json_block(content);
        assert_eq!(json, content);
    }

    #[test]
    fn parse_valid_signature() {
        let json = r#"{
            "root_cause": "Integer overflow in arithmetic without bounds check",
            "vulnerable_pattern": "(binary_expression left: (_) operator: \"+\" right: (_))",
            "required_preconditions": ["User-controlled integer operands"],
            "sanitizer_gaps": ["No overflow check before addition"],
            "nl_brief": "The function performs unchecked integer addition.",
            "bug_class": "INTEGER_OVERFLOW",
            "confidence": 8
        }"#;
        let sig = parse_signature_response(json).unwrap();
        assert_eq!(sig.bug_class, "INTEGER_OVERFLOW");
        assert_eq!(sig.confidence, 8);
    }

    #[test]
    fn parse_invalid_confidence() {
        let json = r#"{
            "root_cause": "test",
            "vulnerable_pattern": "test",
            "required_preconditions": [],
            "sanitizer_gaps": [],
            "nl_brief": "test",
            "bug_class": "OTHER",
            "confidence": 15
        }"#;
        assert!(parse_signature_response(json).is_err());
    }
}
