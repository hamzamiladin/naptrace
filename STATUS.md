# Status

## v0.1.0 — Initial Release (2026-04-17)

### Complete

- **6-stage pipeline**: Ingest -> Distill -> Retrieve -> Slice -> Reason -> Report
- **4 LLM backends**: Ollama (local), Groq (free), Anthropic, OpenAI — all with rate limit retry
- **2 embedding backends**: Ollama (local), Voyage AI
- **8 languages**: C, C++, Java, Python, JavaScript, TypeScript, Go, Rust
- **tree-sitter function extraction** across all supported languages
- **Joern CPG analysis** with auto-download of Java + Joern
- **SARIF 2.1.0 output** for CI integration
- **6 rulepacks**: C memory safety, Java deserialization, Python injection, Go concurrency, Rust safety, ML framework security
- **15 real CVEs** in benchmark corpus across 8 vulnerability families
- **Embedding cache** — re-runs skip the embedding step entirely
- **NVD API caching** with rate limit retry
- **Custom benchmarks** via `--corpus` flag
- **44 tests** including E2E pipeline test with mock LLM
- **Published to crates.io** — `cargo install naptrace`
- **Animated CLI banner** (figlet slant font)
- **Cross-platform** — macOS, Linux, Windows (partial)

### Tested against

| Codebase | Language | Functions | Accuracy |
|----------|----------|-----------|----------|
| Redis (177K lines) | C | 5,335 | Found real potential overflow variant |
| Flask | Python | ~200 | 0 false positives |
| Gson | Java | ~300 | 0 false positives, identified anti-deser guards |

### What's next

- More benchmark corpus entries with verified ground truth
- Diff-only scanning mode (PR integration)
- Community rulepack contributions
- Performance optimization for large codebases
