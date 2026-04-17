use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Get the embedding cache directory.
fn cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "naptrace", "naptrace")
        .map(|d| d.cache_dir().join("embeddings"))
}

/// Generate a cache key from the target directory contents.
/// Uses a hash of all file paths + sizes for fast invalidation.
fn cache_key(target_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    let canonical = target_dir
        .canonicalize()
        .unwrap_or_else(|_| target_dir.to_path_buf());
    hasher.update(canonical.to_string_lossy().as_bytes());

    // Hash file metadata for invalidation
    if let Ok(entries) = walkdir::WalkDir::new(target_dir)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    {
        for entry in entries {
            if entry.file_type().is_file() {
                hasher.update(entry.path().to_string_lossy().as_bytes());
                if let Ok(meta) = entry.metadata() {
                    hasher.update(meta.len().to_le_bytes());
                }
            }
        }
    }

    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// Try to load cached embeddings for a target directory.
pub fn load_cached(target_dir: &Path) -> Option<Vec<Vec<f32>>> {
    let dir = cache_dir()?;
    let key = cache_key(target_dir);
    let path = dir.join(format!("{key}.bin"));

    if !path.exists() {
        return None;
    }

    let data = std::fs::read(&path).ok()?;
    let embeddings: Vec<Vec<f32>> = bincode_decode(&data)?;

    info!(
        count = embeddings.len(),
        "loaded cached embeddings for {}",
        target_dir.display()
    );

    Some(embeddings)
}

/// Save embeddings to the cache.
pub fn save_cache(target_dir: &Path, embeddings: &[Vec<f32>]) {
    if let Some(dir) = cache_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let key = cache_key(target_dir);
        let path = dir.join(format!("{key}.bin"));

        if let Some(data) = bincode_encode(embeddings) {
            let _ = std::fs::write(&path, data);
            debug!(
                count = embeddings.len(),
                path = %path.display(),
                "saved embeddings to cache"
            );
        }
    }
}

/// Simple binary encoding for Vec<Vec<f32>>.
fn bincode_encode(embeddings: &[Vec<f32>]) -> Option<Vec<u8>> {
    let mut buf = Vec::new();

    // Write count of embeddings
    let count = embeddings.len() as u64;
    buf.extend_from_slice(&count.to_le_bytes());

    for emb in embeddings {
        // Write dimension
        let dim = emb.len() as u64;
        buf.extend_from_slice(&dim.to_le_bytes());

        // Write floats
        for &val in emb {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }

    Some(buf)
}

/// Simple binary decoding for Vec<Vec<f32>>.
fn bincode_decode(data: &[u8]) -> Option<Vec<Vec<f32>>> {
    let mut pos = 0;

    if data.len() < 8 {
        return None;
    }

    let count = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?) as usize;
    pos += 8;

    let mut embeddings = Vec::with_capacity(count);

    for _ in 0..count {
        if pos + 8 > data.len() {
            return None;
        }
        let dim = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?) as usize;
        pos += 8;

        let bytes_needed = dim * 4;
        if pos + bytes_needed > data.len() {
            return None;
        }

        let mut emb = Vec::with_capacity(dim);
        for _ in 0..dim {
            let val = f32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
            pos += 4;
            emb.push(val);
        }
        embeddings.push(emb);
    }

    Some(embeddings)
}
