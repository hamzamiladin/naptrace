# Status

## 2026-04-17 — Initial scaffolding

- Cargo workspace with 5 crates scaffolded per architecture spec.
- CLI skeleton with `doctor`, `hunt`, `explain`, `bench`, `init-action` subcommands.
- `naptrace doctor` implemented — checks Joern, API keys, cache dir, git.
- Prompt templates written for distill_signature and reason_feasibility.
- CI workflow (fmt/clippy/test/deny) in place.

## 2026-04-17 — Stage 1 (Ingest) complete

- Ingest pipeline parses `file:`, `cve:`, `repo@sha`, and `pr:` patch sources.
- Unified diff parser handles multi-file, multi-hunk patches correctly.
- `naptrace hunt --explain-only` works end-to-end with local diff files.
- 21 tests passing (13 unit + 8 integration with insta snapshots).
- Next: Stage 2 (Distill) — extract structural vulnerability signatures via LLM.

## 2026-04-17 — Stage 2 (Distill) complete

- LLM clients for Anthropic, OpenAI, and Ollama implemented and tested.
- Prompt template loader parses YAML frontmatter and interpolates variables.
- Stage 2 calls the LLM, parses structured JSON signature response.
- Verified end-to-end with Ollama (qwen2.5-coder:7b) on the SQLite fixture.
- Next: Stage 3 (Retrieve) — embed and search for candidate sites.

## 2026-04-17 — Stage 3 (Retrieve) complete

- Tree-sitter function extractor for 8 languages.
- Ollama + Voyage embedding backends.
- In-memory cosine similarity search, top-K ranking.
- Full 3-stage pipeline tested: Ingest -> Distill -> Retrieve.
- Next: Stage 4 (Slice) — Joern CPG paths for each candidate.
