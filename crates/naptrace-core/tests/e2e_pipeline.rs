use naptrace_core::ingest;
use naptrace_core::signature;
use naptrace_core::retrieve;
use naptrace_core::reason::{self, VerdictKind};
use naptrace_core::report;
use naptrace_core::slice;
use naptrace_llm::{LlmClient, LlmRequest, LlmResponse, Provider, Usage};

/// A mock LLM client that returns canned responses for testing.
struct MockLlmClient {
    distill_response: String,
    reason_response: String,
}

impl MockLlmClient {
    fn new() -> Self {
        Self {
            distill_response: serde_json::json!({
                "root_cause": "Integer overflow in unchecked arithmetic operation",
                "vulnerable_pattern": "(binary_expression left: (_) operator: \"+\" right: (_))",
                "required_preconditions": ["User-controlled integer operands"],
                "sanitizer_gaps": ["No overflow check before addition"],
                "nl_brief": "The function performs unchecked integer addition that can overflow with crafted inputs.",
                "bug_class": "INTEGER_OVERFLOW",
                "confidence": 8
            }).to_string(),
            reason_response: serde_json::json!({
                "verdict": "feasible",
                "justification": "Line 5 performs unchecked addition identical to the patched vulnerability.",
                "blocking_sanitizers": [],
                "reachable_inputs": ["function parameter a", "function parameter b"],
                "poc_sketch": "Call with INT64_MAX and 1 to trigger overflow.",
                "confidence": 8
            }).to_string(),
        }
    }
}

impl LlmClient for MockLlmClient {
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<LlmResponse>> + Send + '_>>
    {
        // Determine which response to return based on the system prompt
        let content = if request.messages.iter().any(|m| m.content.contains("Distillation")) {
            self.distill_response.clone()
        } else {
            self.reason_response.clone()
        };

        Box::pin(async move {
            Ok(LlmResponse {
                content,
                model: "mock-model".to_string(),
                usage: Some(Usage {
                    input_tokens: 100,
                    output_tokens: 50,
                }),
            })
        })
    }

    fn provider(&self) -> Provider {
        Provider::Ollama
    }
}

/// Mock embedder that returns fixed-dimension vectors.
struct MockEmbedder;

impl naptrace_embed::Embedder for MockEmbedder {
    fn embed(
        &self,
        texts: &[String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<Vec<f32>>>> + Send + '_>>
    {
        let count = texts.len();
        Box::pin(async move {
            // Return random-ish but deterministic embeddings
            Ok((0..count)
                .map(|i| {
                    (0..64)
                        .map(|j| ((i * 7 + j * 13) % 100) as f32 / 100.0)
                        .collect()
                })
                .collect())
        })
    }

    fn dimension(&self) -> usize {
        64
    }
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap()
}

fn create_test_target() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("src");
    std::fs::create_dir(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("math.c"),
        r#"#include <stdint.h>

int64_t unsafe_add(int64_t a, int64_t b) {
    int64_t result = a + b;
    return result;
}

int safe_add(int64_t *result, int64_t a, int64_t b) {
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) {
        return 1;
    }
    *result = a + b;
    return 0;
}

int64_t unsafe_multiply(int64_t a, int64_t b) {
    int64_t result = a * b;
    return result;
}
"#,
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn e2e_pipeline_with_mock_llm() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let target_dir = create_test_target();
    let mock_llm = MockLlmClient::new();
    let mock_embedder = MockEmbedder;

    // Stage 1: Ingest
    let seed = ingest::ingest(
        &format!("file:{}/tests/fixtures/sqlite_cve_2025_6965.patch", env!("CARGO_MANIFEST_DIR")),
        &target_dir.path().to_string_lossy(),
    )
    .await
    .expect("ingest should succeed");

    assert_eq!(seed.patched_files.len(), 1);
    assert_eq!(seed.language, naptrace_core::Language::C);

    // Stage 2: Distill
    let signature = signature::distill(&seed, &mock_llm, Some("mock-model"))
        .await
        .expect("distill should succeed");

    assert_eq!(signature.bug_class, "INTEGER_OVERFLOW");
    assert_eq!(signature.confidence, 8);

    // Stage 3: Retrieve
    let candidates = retrieve::retrieve(
        target_dir.path(),
        &signature,
        &mock_embedder,
        &[naptrace_core::Language::C],
        10,
    )
    .await
    .expect("retrieve should succeed");

    assert!(!candidates.is_empty(), "should find at least one candidate");

    // Stage 4: Slice (will skip since Joern may not be available in CI)
    let sliced = slice::slice_candidates(
        candidates,
        target_dir.path(),
        naptrace_core::Language::C,
    )
    .await
    .expect("slice should succeed even without Joern");

    assert!(!sliced.is_empty());

    // Stage 5: Reason
    let findings = reason::reason(
        &sliced,
        &signature,
        &mock_llm,
        Some("mock-model"),
        &diff,
    )
    .await
    .expect("reason should succeed");

    assert!(!findings.is_empty());
    // Mock always returns "feasible"
    assert!(
        findings.iter().all(|f| f.verdict.verdict == VerdictKind::Feasible),
        "mock LLM should return feasible for all candidates"
    );

    // Stage 6: Report
    let summary = report::summarize(&findings);
    assert!(summary.feasible > 0);
    assert_eq!(summary.total, findings.len());

    let sarif = report::generate_sarif(&findings, None);
    assert_eq!(sarif.version, "2.1.0");
    assert!(!sarif.runs[0].results.is_empty());

    // Verify SARIF serializes cleanly
    let json = serde_json::to_string_pretty(&sarif).unwrap();
    assert!(json.contains("naptrace"));
    assert!(json.contains("FEASIBLE"));
}
