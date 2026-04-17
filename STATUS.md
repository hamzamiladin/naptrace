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
