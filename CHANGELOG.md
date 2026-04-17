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
