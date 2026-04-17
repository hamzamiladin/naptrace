pub mod cpg;
pub mod download;

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

pub const JOERN_VERSION: &str = "4.0.523";

pub fn joern_cache_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "naptrace", "naptrace")
        .context("could not determine platform cache directory")?;
    let path = dirs.cache_dir().join("joern");
    Ok(path)
}

pub fn joern_bin_path() -> Result<PathBuf> {
    let cache = joern_cache_dir()?;
    Ok(cache.join("joern-cli").join("joern"))
}

pub fn joern_parse_bin_path() -> Result<PathBuf> {
    let cache = joern_cache_dir()?;
    Ok(cache.join("joern-cli").join("joern-parse"))
}

pub fn is_joern_installed() -> bool {
    joern_bin_path().map(|p| p.exists()).unwrap_or(false)
}

pub fn cpg_cache_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "naptrace", "naptrace")
        .context("could not determine platform cache directory")?;
    Ok(dirs.cache_dir().join("cpgs"))
}

pub fn cpg_path_for_commit(commit_sha: &str) -> Result<PathBuf> {
    let dir = cpg_cache_dir()?;
    Ok(dir.join(format!("{commit_sha}.bin")))
}
