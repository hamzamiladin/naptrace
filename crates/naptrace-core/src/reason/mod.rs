use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::prompt::load_prompt;
use crate::signature::VulnSignature;
use crate::slice::SlicedCandidate;

/// The LLM's feasibility verdict for a candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict: VerdictKind,
    pub justification: String,
    pub blocking_sanitizers: Vec<String>,
    pub reachable_inputs: Vec<String>,
    pub poc_sketch: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    Feasible,
    Infeasible,
    NeedsRuntimeCheck,
}

impl std::fmt::Display for VerdictKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Feasible => write!(f, "FEASIBLE"),
            Self::Infeasible => write!(f, "INFEASIBLE"),
            Self::NeedsRuntimeCheck => write!(f, "NEEDS_CHECK"),
        }
    }
}

/// A candidate with its feasibility verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgedCandidate {
    pub file_path: String,
    pub function_name: String,
    pub start_line: u32,
    pub end_line: u32,
    pub similarity: f32,
    pub verdict: Verdict,
    pub body: String,
}

/// Run LLM feasibility reasoning on each sliced candidate.
pub async fn reason(
    candidates: &[SlicedCandidate],
    signature: &VulnSignature,
    llm: &dyn naptrace_llm::LlmClient,
    model_override: Option<&str>,
    raw_diff: &str,
) -> Result<Vec<JudgedCandidate>> {
    let prompt_template =
        load_prompt("reason_feasibility").context("failed to load reason_feasibility prompt")?;

    let model = model_override.unwrap_or(&prompt_template.meta.model);
    let mut results = Vec::with_capacity(candidates.len());

    for (i, sliced) in candidates.iter().enumerate() {
        let candidate = &sliced.candidate;

        info!(
            idx = i + 1,
            total = candidates.len(),
            function = %candidate.function_name,
            "reasoning about candidate"
        );

        let user_content = build_reason_input(signature, sliced, raw_diff);

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
                tracing::warn!(
                    function = %candidate.function_name,
                    error = %e,
                    "LLM call failed — marking as needs_runtime_check"
                );
                results.push(JudgedCandidate {
                    file_path: candidate.file_path.clone(),
                    function_name: candidate.function_name.clone(),
                    start_line: candidate.start_line,
                    end_line: candidate.end_line,
                    similarity: candidate.similarity,
                    body: candidate.body.clone(),
                    verdict: Verdict {
                        verdict: VerdictKind::NeedsRuntimeCheck,
                        justification: format!("LLM call failed: {e}"),
                        blocking_sanitizers: vec![],
                        reachable_inputs: vec![],
                        poc_sketch: None,
                        confidence: 0,
                    },
                });
                continue;
            }
        };

        let verdict = parse_verdict(&response.content).unwrap_or_else(|e| {
            tracing::warn!(
                function = %candidate.function_name,
                error = %e,
                "failed to parse verdict — marking as needs_runtime_check"
            );
            Verdict {
                verdict: VerdictKind::NeedsRuntimeCheck,
                justification: format!("Parse error: {e}"),
                blocking_sanitizers: vec![],
                reachable_inputs: vec![],
                poc_sketch: None,
                confidence: 0,
            }
        });

        results.push(JudgedCandidate {
            file_path: candidate.file_path.clone(),
            function_name: candidate.function_name.clone(),
            start_line: candidate.start_line,
            end_line: candidate.end_line,
            similarity: candidate.similarity,
            body: candidate.body.clone(),
            verdict,
        });
    }

    // Skeptical triage: review feasible verdicts with a follow-up challenge
    let mut triaged = Vec::new();
    for finding in results {
        if finding.verdict.verdict == VerdictKind::Feasible && finding.verdict.confidence < 10 {
            info!(
                function = %finding.function_name,
                "running skeptical triage on feasible verdict"
            );

            let triage_result = skeptical_triage(&finding, signature, llm, model, raw_diff).await;

            match triage_result {
                Ok(revised) => triaged.push(JudgedCandidate {
                    verdict: revised,
                    ..finding
                }),
                Err(_) => triaged.push(finding), // keep original on error
            }
        } else {
            triaged.push(finding);
        }
    }

    Ok(triaged)
}

/// Skeptical triage: challenge a feasible verdict by asking the LLM to find
/// evidence that the defense DOES exist. If it can cite a specific line, downgrade.
async fn skeptical_triage(
    finding: &JudgedCandidate,
    signature: &VulnSignature,
    llm: &dyn naptrace_llm::LlmClient,
    model: &str,
    _raw_diff: &str,
) -> Result<Verdict> {
    let challenge = format!(
        "A previous analysis found this function FEASIBLE for {}:\n\n\
         Function: {} at {}:{}-{}\n\
         Justification: {}\n\n\
         YOUR TASK: Try to DISPROVE this finding. Look for:\n\
         1. Does the function check for overflow/bounds BEFORE the arithmetic?\n\
         2. Is the function itself a SANITIZER (its purpose is to detect/prevent the bug)?\n\
         3. Are the types unsigned where modulo/division/bitwise ops are used (which cannot overflow)?\n\
         4. Is there a wrapper function call that handles the check?\n\n\
         Code:\n```\n{}\n```\n\n\
         If you find a defense, respond with verdict=infeasible and cite the exact line.\n\
         If you cannot find a defense, keep verdict=feasible.\n\
         Respond with the standard JSON verdict format.",
        signature.bug_class,
        finding.function_name,
        finding.file_path,
        finding.start_line,
        finding.end_line,
        finding.verdict.justification,
        finding.body,
    );

    let request = naptrace_llm::LlmRequest {
        model: model.to_string(),
        messages: vec![
            naptrace_llm::Message::system(
                "You are a skeptical security reviewer. Your job is to find reasons why a reported \
                 vulnerability might be a false positive. Be thorough but honest — if the bug is \
                 real, say so."
                    .to_string(),
            ),
            naptrace_llm::Message::user(challenge),
        ],
        temperature: 0.1,
        max_tokens: 1024,
    };

    let response = llm.complete(&request).await?;
    parse_verdict(&response.content)
}

/// Build the user message for the reasoning prompt.
fn build_reason_input(sig: &VulnSignature, sliced: &SlicedCandidate, raw_diff: &str) -> String {
    let candidate = &sliced.candidate;

    let mut input = format!(
        "## NL Brief\n{}\n\n\
         ## Original Patch Diff\n```diff\n{}\n```\n\n\
         ## Candidate Function\n\
         File: {}\n\
         Lines: {}-{}\n\
         ```\n{}\n```\n",
        sig.nl_brief,
        raw_diff,
        candidate.file_path,
        candidate.start_line,
        candidate.end_line,
        candidate.body,
    );

    // Add CPG path context if available
    if !sliced.cpg_paths.is_empty() {
        input.push_str("\n## CPG Path Slice\n");
        for path in &sliced.cpg_paths {
            input.push_str("Sources:\n");
            for src in &path.sources {
                input.push_str(&format!(
                    "  - {}:{} [{}] {}\n",
                    src.file, src.line, src.node_type, src.code
                ));
            }
            if !path.sanitizers.is_empty() {
                input.push_str("Sanitizers on path:\n");
                for san in &path.sanitizers {
                    input.push_str(&format!("  - {san}\n"));
                }
            }
        }
    } else if sliced.sliced {
        input.push_str(
            "\n## CPG Path Slice\nNo data-flow paths found by Joern for this candidate.\n",
        );
    } else {
        input
            .push_str("\n## CPG Path Slice\nCPG analysis was not performed (Joern unavailable).\n");
    }

    // Add sanitizer context from signature
    input.push_str("\n## Known Sanitizer Gaps from Original Vulnerability\n");
    for gap in &sig.sanitizer_gaps {
        input.push_str(&format!("- {gap}\n"));
    }

    input
}

/// Parse the LLM's JSON verdict response.
fn parse_verdict(content: &str) -> Result<Verdict> {
    let json_str = crate::signature::extract_json_block(content);

    // Try strict parsing first
    if let Ok(verdict) = serde_json::from_str::<Verdict>(json_str) {
        if verdict.confidence <= 10 {
            return Ok(verdict);
        }
    }

    // Fallback: try to extract fields from any JSON the LLM returned
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
        let verdict_kind = val
            .get("verdict")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "feasible" => VerdictKind::Feasible,
                "infeasible" => VerdictKind::Infeasible,
                _ => VerdictKind::NeedsRuntimeCheck,
            })
            .unwrap_or(VerdictKind::NeedsRuntimeCheck);

        let justification = val
            .get("justification")
            .or_else(|| val.get("reason"))
            .or_else(|| val.get("explanation"))
            .and_then(|v| v.as_str())
            .unwrap_or("LLM returned non-standard response format")
            .to_string();

        let confidence = val
            .get("confidence")
            .and_then(|v| v.as_u64())
            .map(|c| c.min(10) as u8)
            .unwrap_or(3);

        return Ok(Verdict {
            verdict: verdict_kind,
            justification,
            blocking_sanitizers: vec![],
            reachable_inputs: vec![],
            poc_sketch: None,
            confidence,
        });
    }

    // Last resort: treat the raw text as a justification
    Ok(Verdict {
        verdict: VerdictKind::NeedsRuntimeCheck,
        justification: format!(
            "Could not parse LLM response as structured JSON: {}",
            content.chars().take(200).collect::<String>()
        ),
        blocking_sanitizers: vec![],
        reachable_inputs: vec![],
        poc_sketch: None,
        confidence: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feasible_verdict() {
        let json = r#"{
            "verdict": "feasible",
            "justification": "Line 5 performs unchecked addition. No overflow check on path.",
            "blocking_sanitizers": [],
            "reachable_inputs": ["function parameter a", "function parameter b"],
            "poc_sketch": "Call unsafe_add(INT64_MAX, 1) to trigger overflow.",
            "confidence": 8
        }"#;
        let v = parse_verdict(json).unwrap();
        assert_eq!(v.verdict, VerdictKind::Feasible);
        assert_eq!(v.confidence, 8);
        assert!(v.poc_sketch.is_some());
    }

    #[test]
    fn parse_infeasible_verdict() {
        let json = r#"{
            "verdict": "infeasible",
            "justification": "Line 12 checks for overflow before addition.",
            "blocking_sanitizers": ["overflow check at line 12"],
            "reachable_inputs": [],
            "poc_sketch": null,
            "confidence": 9
        }"#;
        let v = parse_verdict(json).unwrap();
        assert_eq!(v.verdict, VerdictKind::Infeasible);
        assert!(v.poc_sketch.is_none());
    }

    #[test]
    fn parse_needs_check_verdict() {
        let json = r#"{
            "verdict": "needs_runtime_check",
            "justification": "Path depends on runtime value of config flag.",
            "blocking_sanitizers": [],
            "reachable_inputs": ["user input via argv"],
            "poc_sketch": null,
            "confidence": 4
        }"#;
        let v = parse_verdict(json).unwrap();
        assert_eq!(v.verdict, VerdictKind::NeedsRuntimeCheck);
    }
}
