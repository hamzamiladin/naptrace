# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project scaffolding: Cargo workspace with five crates (naptrace, naptrace-core, naptrace-joern, naptrace-embed, naptrace-llm)
- CLI skeleton with `hunt`, `explain`, `bench`, `doctor`, and `init-action` subcommands
- `naptrace doctor` — checks Joern, API keys, cache directory, and git availability
- Prompt templates for vulnerability signature distillation and feasibility reasoning
- CI workflow (fmt, clippy, test, deny)
- README with architecture overview and usage examples
- Stage 1 (Ingest): parse patches from `file:`, `cve:`, `repo@sha`, and `pr:` sources
- Unified diff parser with multi-file and multi-hunk support
- `naptrace hunt --explain-only` shows parsed patch structure without running stages 2-6
- 21 tests including insta snapshot tests against a fixed SQLite CVE patch
- Bumped `rust-version` to 1.85 (clap 4.6 requires Rust edition 2024)
- Stage 2 (Distill): LLM-powered vulnerability signature extraction with structured JSON output
- LLM client implementations for Anthropic, OpenAI, and Ollama (local)
- Prompt template loader with YAML frontmatter parsing and variable interpolation
- Smart model defaults per provider — `--reasoner ollama` just works without `--model`
- 28 tests total
- Stage 3 (Retrieve): tree-sitter function extraction + embedding-based candidate search
- Function extractor supporting C, C++, Python, Java, JavaScript, TypeScript, Go, Rust
- Ollama embedding backend using `nomic-embed-text` for fully local operation
- Voyage AI embedding backend for API users
- In-memory cosine similarity search with top-K ranking
- 37 tests total
- Stage 4 (Slice): Joern CPG building and path extraction for each candidate
- Auto-download of Joern CLI (v4.0.523) on first use
- Auto-install of Java 21 via Homebrew/apt/dnf when missing
- Graceful degradation — skips CPG slicing if Joern/Java unavailable
- Stage 5 (Reason): LLM feasibility verdict per candidate (feasible/infeasible/needs_runtime_check)
- Stage 6 (Report): SARIF 2.1.0 output + pretty terminal display with color-coded verdicts
- Exit codes per spec: 0 = no feasible findings, 1 = feasible found
- Complete 6-stage pipeline working end-to-end
- 43 tests total
- Benchmark corpus with ground truth (`benchmarks/ground_truth.yaml`) and `naptrace bench` harness
- C memory safety rulepack (`rulepacks/c_memory_safety.yaml`)
- `naptrace init-action` generates a starter GitHub Actions workflow
- Dockerfile for `docker run ghcr.io/hamzamiladin/naptrace`
- `install.sh` for `curl | sh` installation
- Multi-OS release workflow with cross-compilation and Docker image publishing
- Benchmark CI workflow (weekly)
- Homebrew formula template (`packaging/naptrace.rb`)
- Polished README with real pipeline output
