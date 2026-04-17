pub mod local;
pub mod ollama;
pub mod voyage;

use anyhow::Result;

/// Boxed future type alias to avoid clippy::type_complexity.
pub type EmbedFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Vec<f32>>>> + Send + 'a>>;

/// Trait for embedding backends.
pub trait Embedder: Send + Sync {
    fn embed(&self, texts: &[String]) -> EmbedFuture<'_>;

    fn dimension(&self) -> usize;
}

pub fn has_voyage_key() -> bool {
    std::env::var("VOYAGE_API_KEY").is_ok()
}

/// Create the best available embedder.
/// Prefers Voyage if VOYAGE_API_KEY is set, otherwise uses Ollama.
pub fn create_embedder() -> Box<dyn Embedder> {
    if has_voyage_key() {
        Box::new(voyage::VoyageEmbedder::from_env())
    } else {
        Box::new(ollama::OllamaEmbedder::from_env())
    }
}

/// Cosine similarity between two vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identical() {
        let v = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = vec![1.0, 2.0];
        let b = vec![0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }
}
