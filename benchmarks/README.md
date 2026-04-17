# Naptrace Benchmark Corpus

This directory contains the ground truth for naptrace's benchmark suite.

## Running benchmarks

```sh
# Run the built-in benchmark corpus
naptrace bench

# Run with a custom corpus file
naptrace bench --corpus my_cves.yaml
```

## Adding your own CVEs

Create a YAML file following this schema:

```yaml
- cve: CVE-YYYY-NNNNN
  description: "Short description of the vulnerability"
  bug_class: INTEGER_OVERFLOW  # See bug classes below
  source_repo: https://github.com/org/repo
  patch_commit: abc123def456  # The commit SHA that fixed it
  language: c                 # c, cpp, java, python, go, rust, javascript, typescript
  family: my_family           # Group related CVEs
  variants:
    - file: path/to/file.c
      function: vulnerable_function
      is_feasible: true       # true = confirmed variant, false = patched/unreachable
      notes: "Why this is or isn't a variant"
    - file: path/to/other.c
      function: safe_function
      is_feasible: false
      notes: "Has overflow check at line 42"
```

### Bug classes

Use one of these values for `bug_class`:

- `INTEGER_OVERFLOW` / `INTEGER_UNDERFLOW`
- `OOB_READ` / `OOB_WRITE`
- `USE_AFTER_FREE` / `DOUBLE_FREE`
- `NULL_DEREF`
- `TYPE_CONFUSION`
- `INJECTION` (SQL, command, format string)
- `DESERIALIZATION`
- `AUTHZ_BYPASS`
- `PATH_TRAVERSAL`
- `RACE_CONDITION`
- `OTHER`

### Guidelines

- Use CVEs from **2024 or later** to avoid LLM training data leakage
- Always include the `patch_commit` SHA so the patch can be fetched
- Include both **feasible** (true positive) and **infeasible** (true negative) variants
- Document **why** each variant is feasible or not in the `notes` field
- Prefer CVEs where the variant relationship is documented (blog posts, advisories)

## Contributing

To contribute a CVE to the benchmark:

1. Fork the repo
2. Add your entry to `ground_truth.yaml` (or create a new file)
3. If possible, add the patch file to `corpus/<cve_id>/patch.diff`
4. Open a PR with a description of the variant relationship

We accept CVEs in any of the 8 supported languages.

## Current corpus

See [`ground_truth.yaml`](ground_truth.yaml) for the full list of 15 CVEs across 8 families.
