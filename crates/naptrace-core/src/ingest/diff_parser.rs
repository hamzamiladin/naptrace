use anyhow::Result;

use crate::{DiffHunk, Language, PatchedFile};

/// Parse a unified diff string into a list of PatchedFiles.
///
/// Handles standard unified diff format (`diff --git`, `---`, `+++`, `@@`).
/// Also handles `.patch` files from GitHub that include commit metadata.
pub fn parse_unified_diff(diff_text: &str) -> Result<Vec<PatchedFile>> {
    let mut files: Vec<PatchedFile> = Vec::new();
    let mut current_file: Option<PatchedFileBuilder> = None;
    let mut current_hunk: Option<HunkBuilder> = None;

    for line in diff_text.lines() {
        // New file header: `diff --git a/path b/path`
        if line.starts_with("diff --git ") {
            // Flush current hunk and file
            if let Some(hunk) = current_hunk.take() {
                if let Some(ref mut file) = current_file {
                    file.hunks.push(hunk.build());
                }
            }
            if let Some(file) = current_file.take() {
                files.push(file.build());
            }

            let path = parse_diff_header_path(line);
            current_file = Some(PatchedFileBuilder::new(path));
            continue;
        }

        // Old file path: `--- a/path`
        if line.starts_with("--- ") {
            // If we don't have a current file yet (non-git unified diff),
            // we'll create one when we see the +++ line
            continue;
        }

        // New file path: `+++ b/path`
        if line.starts_with("+++ ") {
            if current_file.is_none() {
                let path = line
                    .strip_prefix("+++ b/")
                    .or_else(|| line.strip_prefix("+++ "))
                    .unwrap_or("unknown")
                    .to_string();
                current_file = Some(PatchedFileBuilder::new(path));
            }
            continue;
        }

        // Hunk header: `@@ -old_start,old_lines +new_start,new_lines @@`
        if line.starts_with("@@ ") {
            // Flush previous hunk
            if let Some(hunk) = current_hunk.take() {
                if let Some(ref mut file) = current_file {
                    file.hunks.push(hunk.build());
                }
            }

            if let Some(hunk) = parse_hunk_header(line) {
                current_hunk = Some(hunk);
            }
            continue;
        }

        // Hunk content lines
        if let Some(ref mut hunk) = current_hunk {
            if line.starts_with('-') {
                hunk.removed_lines
                    .push(line.get(1..).unwrap_or("").to_string());
                hunk.content.push_str(line);
                hunk.content.push('\n');
            } else if line.starts_with('+') {
                hunk.added_lines
                    .push(line.get(1..).unwrap_or("").to_string());
                hunk.content.push_str(line);
                hunk.content.push('\n');
            } else if line.starts_with(' ') || line.is_empty() {
                // Context line
                hunk.content.push_str(line);
                hunk.content.push('\n');
            }
            // Skip `\ No newline at end of file` and other metadata
        }
    }

    // Flush final hunk and file
    if let Some(hunk) = current_hunk.take() {
        if let Some(ref mut file) = current_file {
            file.hunks.push(hunk.build());
        }
    }
    if let Some(file) = current_file.take() {
        files.push(file.build());
    }

    Ok(files)
}

/// Extract file path from `diff --git a/path b/path`.
fn parse_diff_header_path(line: &str) -> String {
    // Format: diff --git a/<path> b/<path>
    // Take the b/ path (post-patch)
    if let Some(rest) = line.strip_prefix("diff --git ") {
        if let Some((_, b_path)) = rest.split_once(" b/") {
            return b_path.to_string();
        }
        // Fallback: split on space and take second half
        if let Some((a, _)) = rest.split_once(' ') {
            return a.strip_prefix("a/").unwrap_or(a).to_string();
        }
    }
    "unknown".to_string()
}

/// Parse `@@ -old_start,old_lines +new_start,new_lines @@` into a HunkBuilder.
fn parse_hunk_header(line: &str) -> Option<HunkBuilder> {
    // Strip the @@ markers
    let inner = line
        .strip_prefix("@@ ")?
        .split(" @@")
        .next()?;

    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let (old_start, old_lines) = parse_range(parts[0].strip_prefix('-')?)?;
    let (new_start, new_lines) = parse_range(parts[1].strip_prefix('+')?)?;

    Some(HunkBuilder {
        old_start,
        old_lines,
        new_start,
        new_lines,
        content: String::new(),
        removed_lines: Vec::new(),
        added_lines: Vec::new(),
    })
}

/// Parse `start,lines` or just `start` (implying 1 line).
fn parse_range(s: &str) -> Option<(u32, u32)> {
    if let Some((start, lines)) = s.split_once(',') {
        Some((start.parse().ok()?, lines.parse().ok()?))
    } else {
        Some((s.parse().ok()?, 1))
    }
}

struct PatchedFileBuilder {
    path: String,
    hunks: Vec<DiffHunk>,
}

impl PatchedFileBuilder {
    fn new(path: String) -> Self {
        Self {
            path,
            hunks: Vec::new(),
        }
    }

    fn build(self) -> PatchedFile {
        let language = Language::from_path(&self.path);
        PatchedFile {
            path: self.path,
            pre_patch_source: None,
            post_patch_source: None,
            hunks: self.hunks,
            language,
        }
    }
}

struct HunkBuilder {
    old_start: u32,
    old_lines: u32,
    new_start: u32,
    new_lines: u32,
    content: String,
    removed_lines: Vec<String>,
    added_lines: Vec<String>,
}

impl HunkBuilder {
    fn build(self) -> DiffHunk {
        DiffHunk {
            old_start: self.old_start,
            old_lines: self.old_lines,
            new_start: self.new_start,
            new_lines: self.new_lines,
            content: self.content,
            removed_lines: self.removed_lines,
            added_lines: self.added_lines,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DIFF: &str = r#"diff --git a/src/vdbe.c b/src/vdbe.c
index abc1234..def5678 100644
--- a/src/vdbe.c
+++ b/src/vdbe.c
@@ -3837,7 +3837,9 @@ case OP_Add: {
     pIn1 = &aMem[pOp->p1];
     pIn2 = &aMem[pOp->p2];
-    iA = pIn1->u.i;
-    iB = pIn2->u.i;
-    iResult = iA + iB;
+    iA = pIn1->u.i;
+    iB = pIn2->u.i;
+    if( sqlite3AddInt64(&iResult, iA, iB) ){
+      goto fp_math;
+    }
     pOut = &aMem[pOp->p3];
"#;

    #[test]
    fn parse_simple_diff() {
        let files = parse_unified_diff(SAMPLE_DIFF).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/vdbe.c");
        assert_eq!(files[0].language, Some(Language::C));
        assert_eq!(files[0].hunks.len(), 1);

        let hunk = &files[0].hunks[0];
        assert_eq!(hunk.old_start, 3837);
        assert_eq!(hunk.old_lines, 7);
        assert_eq!(hunk.new_start, 3837);
        assert_eq!(hunk.new_lines, 9);
        assert_eq!(hunk.removed_lines.len(), 3);
        assert_eq!(hunk.added_lines.len(), 5);
    }

    #[test]
    fn parse_multi_file_diff() {
        let diff = r#"diff --git a/src/foo.c b/src/foo.c
--- a/src/foo.c
+++ b/src/foo.c
@@ -10,3 +10,4 @@ void foo() {
     int x = 1;
+    int y = 2;
     return;
diff --git a/src/bar.py b/src/bar.py
--- a/src/bar.py
+++ b/src/bar.py
@@ -5,2 +5,3 @@ def bar():
     x = 1
+    y = 2
"#;
        let files = parse_unified_diff(diff).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "src/foo.c");
        assert_eq!(files[0].language, Some(Language::C));
        assert_eq!(files[1].path, "src/bar.py");
        assert_eq!(files[1].language, Some(Language::Python));
    }

    #[test]
    fn parse_empty_diff() {
        let files = parse_unified_diff("").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn hunk_header_parsing() {
        let hunk = parse_hunk_header("@@ -10,5 +12,7 @@ function foo()").unwrap();
        assert_eq!(hunk.old_start, 10);
        assert_eq!(hunk.old_lines, 5);
        assert_eq!(hunk.new_start, 12);
        assert_eq!(hunk.new_lines, 7);
    }

    #[test]
    fn hunk_header_single_line() {
        let hunk = parse_hunk_header("@@ -10 +12,3 @@").unwrap();
        assert_eq!(hunk.old_start, 10);
        assert_eq!(hunk.old_lines, 1);
        assert_eq!(hunk.new_start, 12);
        assert_eq!(hunk.new_lines, 3);
    }
}
