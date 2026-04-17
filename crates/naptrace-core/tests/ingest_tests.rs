use naptrace_core::ingest::parse_unified_diff;
use naptrace_core::Language;

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"))
}

#[test]
fn ingest_sqlite_cve_patch_file_count() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();
    assert_eq!(files.len(), 1, "should parse exactly one file from patch");
    assert_eq!(files[0].path, "src/vdbe.c");
}

#[test]
fn ingest_sqlite_cve_patch_language() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();
    assert_eq!(files[0].language, Some(Language::C));
}

#[test]
fn ingest_sqlite_cve_patch_hunk_count() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();
    assert_eq!(files[0].hunks.len(), 3, "patch has 3 hunks (Add, Subtract, Multiply)");
}

#[test]
fn ingest_sqlite_cve_patch_hunk_ranges() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();

    // Hunk 1: OP_Add
    assert_eq!(files[0].hunks[0].old_start, 3837);
    assert_eq!(files[0].hunks[0].old_lines, 10);
    assert_eq!(files[0].hunks[0].new_start, 3837);
    assert_eq!(files[0].hunks[0].new_lines, 12);

    // Hunk 2: OP_Subtract
    assert_eq!(files[0].hunks[1].old_start, 3855);
    assert_eq!(files[0].hunks[1].new_start, 3857);

    // Hunk 3: OP_Multiply
    assert_eq!(files[0].hunks[2].old_start, 3872);
    assert_eq!(files[0].hunks[2].new_start, 3876);
}

#[test]
fn ingest_sqlite_cve_patch_removed_lines() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();

    let hunk = &files[0].hunks[0];
    // The vulnerable lines: raw arithmetic without overflow check
    assert!(
        hunk.removed_lines.iter().any(|l| l.contains("iResult = iA + iB")),
        "should find the removed iResult = iA + iB line"
    );
}

#[test]
fn ingest_sqlite_cve_patch_added_lines() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();

    let hunk = &files[0].hunks[0];
    // The fix: overflow-checked addition
    assert!(
        hunk.added_lines.iter().any(|l| l.contains("sqlite3AddInt64")),
        "should find the added sqlite3AddInt64 call"
    );
}

#[test]
fn ingest_snapshot_vuln_seed_structure() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();

    // Snapshot the parsed structure as JSON
    let json = serde_json::to_string_pretty(&files).unwrap();
    insta::assert_snapshot!("sqlite_cve_2025_6965_parsed", json);
}

#[test]
fn ingest_snapshot_hunk_content() {
    let diff = fixture("sqlite_cve_2025_6965.patch");
    let files = parse_unified_diff(&diff).unwrap();

    // Snapshot just the first hunk's content
    insta::assert_snapshot!(
        "sqlite_cve_2025_6965_hunk0_content",
        files[0].hunks[0].content
    );
}
