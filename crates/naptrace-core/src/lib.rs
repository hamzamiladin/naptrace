pub mod ingest;
pub mod prompt;
pub mod reason;
pub mod report;
pub mod retrieve;
pub mod signature;
pub mod slice;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// The canonical output of Stage 1 (Ingest).
/// Contains everything downstream stages need to know about the vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSeed {
    /// CVE identifier, if known.
    pub cve_id: Option<String>,
    /// Parsed diff hunks grouped by file.
    pub patched_files: Vec<PatchedFile>,
    /// Original commit message from the patch, if available.
    pub commit_msg: Option<String>,
    /// CVE metadata fetched from NVD, if available.
    pub cve_metadata: Option<CveMetadata>,
    /// Primary language detected from patched file extensions.
    pub language: Language,
    /// The raw unified diff text.
    pub raw_diff: String,
}

/// A single file modified by the patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchedFile {
    /// Path of the file relative to the repo root.
    pub path: String,
    /// The pre-patch (vulnerable) source of the file, if available.
    pub pre_patch_source: Option<String>,
    /// The post-patch (fixed) source of the file, if available.
    pub post_patch_source: Option<String>,
    /// Individual diff hunks within this file.
    pub hunks: Vec<DiffHunk>,
    /// Language detected from file extension.
    pub language: Option<Language>,
}

/// A single hunk from a unified diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    /// The raw hunk content including +/- lines.
    pub content: String,
    /// Lines removed (without the leading `-`).
    pub removed_lines: Vec<String>,
    /// Lines added (without the leading `+`).
    pub added_lines: Vec<String>,
}

/// Metadata from the NVD API for a CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMetadata {
    pub cve_id: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub references: Vec<String>,
    pub published_date: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    C,
    Cpp,
    Java,
    Python,
    Javascript,
    Typescript,
    Go,
    Rust,
}

impl Language {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "c" | "h" => Some(Self::C),
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(Self::Cpp),
            "java" => Some(Self::Java),
            "py" => Some(Self::Python),
            "js" | "mjs" | "cjs" => Some(Self::Javascript),
            "ts" | "tsx" => Some(Self::Typescript),
            "go" => Some(Self::Go),
            "rs" => Some(Self::Rust),
            _ => None,
        }
    }

    pub fn from_path(path: &str) -> Option<Self> {
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .and_then(Self::from_extension)
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::C => write!(f, "c"),
            Self::Cpp => write!(f, "cpp"),
            Self::Java => write!(f, "java"),
            Self::Python => write!(f, "python"),
            Self::Javascript => write!(f, "javascript"),
            Self::Typescript => write!(f, "typescript"),
            Self::Go => write!(f, "go"),
            Self::Rust => write!(f, "rust"),
        }
    }
}
