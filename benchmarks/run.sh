#!/usr/bin/env bash
set -euo pipefail

# Naptrace Benchmark Harness
# Runs naptrace against each CVE in the ground truth corpus
# and produces a bench-results.json summary.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORPUS_DIR="$SCRIPT_DIR/corpus"
RESULTS_FILE="$SCRIPT_DIR/bench-results.json"
GROUND_TRUTH="$SCRIPT_DIR/ground_truth.yaml"

NAPTRACE="${NAPTRACE:-cargo run --release --}"

echo "========================================"
echo " naptrace benchmark harness"
echo "========================================"
echo ""
echo "corpus:       $CORPUS_DIR"
echo "ground truth: $GROUND_TRUTH"
echo "results:      $RESULTS_FILE"
echo ""

if [ ! -f "$GROUND_TRUTH" ]; then
    echo "ERROR: ground_truth.yaml not found"
    exit 1
fi

# Count entries
TOTAL=$(grep -c "^- cve:" "$GROUND_TRUTH" || echo 0)
echo "benchmarking $TOTAL CVE entries..."
echo ""

PASS=0
FAIL=0
SKIP=0

# For now, run the SQLite showcase if its corpus dir exists
if [ -d "$CORPUS_DIR/cve_2025_6965" ]; then
    echo "[1/$TOTAL] CVE-2025-6965 (SQLite integer overflow)"

    PATCH="$CORPUS_DIR/cve_2025_6965/patch.diff"
    TARGET="$CORPUS_DIR/cve_2025_6965/target"

    if [ -f "$PATCH" ] && [ -d "$TARGET" ]; then
        set +e
        OUTPUT=$($NAPTRACE hunt --output sarif "file:$PATCH" "$TARGET" 2>/dev/null)
        EXIT_CODE=$?
        set -e

        if [ $EXIT_CODE -eq 1 ]; then
            echo "  PASS: feasible variants found"
            PASS=$((PASS + 1))
        elif [ $EXIT_CODE -eq 0 ]; then
            echo "  FAIL: no feasible variants found (expected some)"
            FAIL=$((FAIL + 1))
        else
            echo "  ERROR: naptrace exited with code $EXIT_CODE"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  SKIP: corpus files not found"
        SKIP=$((SKIP + 1))
    fi
else
    echo "  SKIP: CVE-2025-6965 corpus not set up"
    SKIP=$((SKIP + 1))
fi

# Remaining entries are placeholders
REMAINING=$((TOTAL - 1))
SKIP=$((SKIP + REMAINING))
echo ""
echo "($REMAINING remaining entries are placeholders — skipped)"

echo ""
echo "========================================"
echo " results: $PASS pass, $FAIL fail, $SKIP skip / $TOTAL total"
echo "========================================"

# Write results JSON
cat > "$RESULTS_FILE" <<ENDJSON
{
  "version": "$(cargo metadata --format-version=1 --no-deps 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['packages'][0]['version'])" 2>/dev/null || echo "dev")",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total": $TOTAL,
  "pass": $PASS,
  "fail": $FAIL,
  "skip": $SKIP,
  "entries": []
}
ENDJSON

echo "results written to $RESULTS_FILE"
