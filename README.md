# naptrace

```
$ naptrace hunt file:cve_2025_6965.patch ./target-project

naptrace hunt
────────────────────────────────────────────────────────────
  patch: file:cve_2025_6965.patch
  language: c
  diff: 1 file(s), 3 hunk(s)
────────────────────────────────────────────────────────────
  ~ src/vdbe.c [c]
    hunk 1: @@ -3837,10 +3837,12 @@  (4 removed, 6 added)
    hunk 2: @@ -3855,9 +3857,11 @@  (3 removed, 5 added)
    hunk 3: @@ -3872,9 +3876,11 @@  (3 removed, 5 added)

  [signature] distilled in 8.5s — INTEGER_OVERFLOW (10/10)
  [candidates] 5 candidates in 9.0s
  [cpg] 5 candidates sliced (19.0s)
  [reason] 5 findings (29.3s)

  >> FEASIBLE   src/math.c:4-7    [unsafe_add]
     Unchecked integer addition — same pattern as CVE-2025-6965.
     confidence: 8/10    similarity: 62%

  >> FEASIBLE   src/math.c:19-22  [unsafe_multiply]
     Unchecked integer multiplication without overflow guard.
     confidence: 7/10    similarity: 60%

  ?? NEEDS_CHECK src/math.c:10-16 [safe_add]
     Has overflow check but path feasibility uncertain.
     confidence: 4/10    similarity: 64%

  summary: 2 feasible, 1 needs_check, 2 infeasible
  total elapsed: 29.3s
```

## Install

```sh
cargo install naptrace
```
```sh
curl -sSL naptrace.dev/install.sh | sh
```
```sh
docker run ghcr.io/hamzamiladin/naptrace hunt file:patch.diff /src
```

## What it finds

Given the patch for CVE-2025-6965 (the SQLite integer overflow Google's Big Sleep found in July 2025):

```diff
--- a/src/vdbe.c
+++ b/src/vdbe.c
@@ -3837,7 +3837,9 @@ case OP_Add: {
-    iA = pIn1->u.i;
-    iB = pIn2->u.i;
-    iResult = iA + iB;
+    iA = pIn1->u.i;
+    iB = pIn2->u.i;
+    if( sqlite3AddInt64(&iResult, iA, iB) ){
+      goto fp_math;
+    }
```

Naptrace finds every function in your codebase with the same unchecked-arithmetic pattern, builds a code property graph, and uses an LLM to determine which candidates are actually reachable and exploitable.

## How it works

```
  naptrace hunt <patch> <target>
         │
  ┌──────┴──────┐
  │  1. Ingest  │  Parse patch from CVE ID, git commit, diff file, or PR URL
  └──────┬──────┘
  ┌──────┴──────┐
  │ 2. Distill  │  LLM extracts structural vulnerability signature
  └──────┬──────┘
  ┌──────┴──────┐
  │ 3. Retrieve │  tree-sitter + embeddings find top-K similar functions
  └──────┬──────┘
  ┌──────┴──────┐
  │  4. Slice   │  Joern CPG paths for each candidate (auto-installs)
  └──────┬──────┘
  ┌──────┴──────┐
  │  5. Reason  │  LLM verdict: feasible / infeasible / needs_check
  └──────┬──────┘
  ┌──────┴──────┐
  │  6. Report  │  SARIF 2.1.0 + terminal output
  └──────┴──────┘
```

## Usage

```sh
# Hunt from a CVE ID (fetches patch from NVD)
naptrace hunt cve:CVE-2025-6965 ./my-project

# Hunt from a git commit
naptrace hunt https://github.com/sqlite/sqlite@abc123f ./target

# Hunt from a local diff file
naptrace hunt file:patch.diff ./target

# Hunt from a pull request
naptrace hunt pr:https://github.com/user/repo/pull/42 .

# Fully offline with Ollama (zero API keys)
naptrace hunt --reasoner ollama cve:CVE-2025-6965 .

# SARIF output for CI
naptrace hunt cve:CVE-2025-6965 . --output sarif > findings.sarif

# Check your setup
naptrace doctor
```

## GitHub Action

Generate a starter workflow:

```sh
naptrace init-action
```

Or add manually:

```yaml
- uses: hamzamiladin/naptrace-action@v1
  with:
    patch: cve:CVE-2025-6965
    target: .
    reasoner: anthropic
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## LLM Backends

| Provider | Flag | Model | Requires |
|----------|------|-------|----------|
| Ollama (local) | `--reasoner ollama` | qwen2.5-coder:32b | Nothing (auto-downloads) |
| Anthropic | `--reasoner anthropic` | claude-opus-4-7 | `ANTHROPIC_API_KEY` |
| OpenAI | `--reasoner openai` | gpt-4o | `OPENAI_API_KEY` |

Local mode via Ollama is a first-class citizen. No signup, no API keys, no cloud.

## Benchmarks

| CVE | Bug class | Language | Status |
|-----|-----------|----------|--------|
| CVE-2025-6965 | INTEGER_OVERFLOW | C | Showcase |

Full harness: [`benchmarks/run.sh`](benchmarks/run.sh)

## Why this exists

Google's Big Sleep (Project Zero + DeepMind) proved that LLMs can perform **variant analysis** -- given a patched bug, find its structural twins across a codebase. Big Sleep found real CVEs in SQLite, Chrome, and WebKit that fuzzing missed.

The agent, prompts, and harness are all closed-source.

Naptrace is the open-source version.

## License

[Apache-2.0](LICENSE)
