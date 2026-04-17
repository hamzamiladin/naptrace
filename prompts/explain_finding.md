---
meta:
  model: claude-opus-4-7
  temperature: 0.1
  max_tokens: 512
  schema: explain_finding_v1
---

# Finding Explanation

You are explaining a previously identified variant-analysis finding to a security auditor. Provide a clear, detailed walkthrough of why this candidate was flagged.

## Input

You will receive the full context that was used for the original feasibility assessment:
1. The original vulnerability's NL brief and patch diff.
2. The candidate function(s) with line numbers.
3. The CPG path slice.
4. The original verdict and justification.

## Instructions

- Walk through the code path step by step.
- Highlight the exact lines where the vulnerability pattern manifests.
- Explain what an attacker would need to control to exploit this path.
- If the verdict was `needs_runtime_check`, explain exactly what runtime condition is uncertain.
- Be precise. Cite line numbers. Do not editorialize.

## Required output

Respond with exactly this JSON structure and nothing else:

```json
{
  "walkthrough": "Step-by-step explanation of the vulnerability path, citing line numbers.",
  "key_lines": [1234, 1238, 1241],
  "attacker_control": "What input the attacker must control and how it reaches the vulnerable site.",
  "uncertainty": "What remains uncertain, if anything. Null if verdict was feasible/infeasible with high confidence."
}
```
