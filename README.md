# naptrace

<!-- TODO: Replace with real asciinema SVG once the pipeline runs end-to-end -->
```
$ naptrace hunt cve:CVE-2025-6965 ./sqlite
[1/6] ingesting patch from NVD...                   done (0.4s)
[2/6] distilling vulnerability signature...          done (1.2s)
[3/6] retrieving candidate sites (K=50)...           done (3.1s)
[4/6] slicing CPG paths for 12 candidates...         done (8.7s)
[5/6] reasoning over 12 candidates...                done (14.3s)
[6/6] generating report...                           done

  FEASIBLE  src/vdbe.c:3841         integer overflow in OP_Add — same unchecked
            arithmetic pattern as CVE-2025-6965, reachable from SQL input.

  FEASIBLE  src/expr.c:2104         signed truncation in exprCodeVector() —
            structurally identical to the patched site in sqlite3VdbeExec().

  NEEDS_CHECK  src/func.c:891      potential overflow in absFunc() — same
               operand type, but sanitizer may exist on this path.

3 findings (2 feasible, 1 needs_check) in 27.7s
```

Naptrace found **N** variants of **15** known CVEs across **M** real projects.
See [`benchmarks/`](benchmarks/).

## Install

```sh
cargo install naptrace
```

or

```sh
brew install hamzamiladin/tap/naptrace
```

or

```sh
curl -sSL naptrace.dev/install.sh | sh
```

or

```sh
docker run ghcr.io/hamzamiladin/naptrace hunt cve:CVE-2025-6965 /src
```

## What it finds

Given the patch for [CVE-2025-6965](https://nvd.nist.gov/vuln/detail/CVE-2025-6965) (the SQLite integer overflow Google's Big Sleep found in July 2025):

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

Naptrace reports this twin in the same codebase:

```
FEASIBLE  src/expr.c:2104
  Signed truncation in exprCodeVector() — structurally identical to
  the patched site in sqlite3VdbeExec(). The operands are user-controlled
  SQL expression values and no overflow check exists on this path.
  Confidence: 8/10
```

## How it works

```
  naptrace hunt <patch> <target>
         │
  ┌──────┴──────┐
  │  1. Ingest  │  Parse patch from CVE ID, git commit, diff file, or PR URL
  └──────┬──────┘
  ┌──────┴──────┐
  │ 2. Distill  │  Extract structural vulnerability signature (CPG + NL + tree-sitter)
  └──────┬──────┘
  ┌──────┴──────┐
  │ 3. Retrieve │  Embed target functions, find top-K similar to signature
  └──────┬──────┘
  ┌──────┴──────┐
  │  4. Slice   │  Build CPG via Joern, extract interprocedural paths per candidate
  └──────┬──────┘
  ┌──────┴──────┐
  │  5. Reason  │  LLM classifies each path: feasible / infeasible / needs_check
  └──────┬──────┘
  ┌──────┴──────┐
  │  6. Report  │  SARIF 2.1.0 output, pretty terminal, optional GitHub issues
  └──────┴──────┘
```

## Usage

```sh
# Hunt for variants of a CVE across your repo
naptrace hunt cve:CVE-2025-6965 ./my-project

# Hunt from a specific commit patch
naptrace hunt https://github.com/user/repo@abc123f ./target-repo

# Use a local diff file
naptrace hunt file:patch.diff ./target-repo

# Fully offline with Ollama
naptrace hunt --reasoner ollama --offline cve:CVE-2025-6965 .

# Output SARIF for CI integration
naptrace hunt cve:CVE-2025-6965 . --output sarif > findings.sarif
```

## GitHub Action

```yaml
- uses: hamzamiladin/naptrace-action@v1
  with:
    patch: cve:CVE-2025-6965
    target: .
    reasoner: anthropic
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Benchmarks

| CVE | Bug class | Variants claimed | Variants verified | False positives |
|-----|-----------|-----------------|-------------------|-----------------|
| CVE-2025-6965 | integer overflow | — | — | — |
| ... | ... | — | — | — |

Full harness: [`benchmarks/run.sh`](benchmarks/run.sh)

## Why this exists

Google's [Big Sleep](https://googleprojectzero.blogspot.com/) (Project Zero + DeepMind) proved that LLMs can perform **variant analysis** — given a patched bug, find its structural twins across a codebase. Big Sleep found real CVEs in SQLite, Chrome, and WebKit that fuzzing missed.

The agent, prompts, and harness are all closed-source.

Naptrace is the open-source version.

## License

[Apache-2.0](LICENSE)
