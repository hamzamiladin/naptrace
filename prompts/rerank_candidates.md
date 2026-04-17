---
meta:
  model: llama-3.3-70b-versatile
  temperature: 0.0
  max_tokens: 1024
  schema: rerank_v1
---

# Candidate Classification for Variant Analysis

You are classifying candidate functions to determine which ones might contain a vulnerability variant and which ones are sanitizers, validators, or unrelated.

## Task

For each candidate below, classify it as:
- **vulnerable**: The function contains code that matches the vulnerability pattern and does NOT check/prevent it
- **sanitizer**: The function's PURPOSE is to CHECK for or PREVENT the vulnerability (e.g., overflow-checking functions, input validators, bounds checkers)
- **unrelated**: The function is not related to the vulnerability pattern

## Rules

- A function named "checkOverflow", "safeAdd", "validateInput" is almost certainly a SANITIZER
- A function that is mostly if-statements checking bounds is a SANITIZER
- A function that performs raw arithmetic without any checks is potentially VULNERABLE
- When in doubt, classify as "vulnerable" to avoid filtering out real findings

## Required output

Respond with EXACTLY a JSON array, one entry per candidate in order:

```json
[
  {"function_name": "name1", "role": "vulnerable|sanitizer|unrelated", "relevance": 8},
  {"function_name": "name2", "role": "sanitizer", "relevance": 2}
]
```

The `relevance` field is 0-10 where 10 means "extremely likely to be a real variant."
