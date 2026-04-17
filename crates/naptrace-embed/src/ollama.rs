use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::Embedder;

const DEFAULT_MODEL: &str = "nomic-embed-text";

pub struct OllamaEmbedder {
    client: Client,
    base_url: String,
    model: String,
    dim: usize,
}

#[derive(Serialize)]
struct EmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

impl OllamaEmbedder {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            model,
            dim: 768, // nomic-embed-text default
        }
    }

    pub fn from_env() -> Self {
        let base_url =
            std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".into());
        let model = std::env::var("NAPTRACE_EMBED_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());
        Self::new(base_url, model)
    }
}

impl Embedder for OllamaEmbedder {
    fn embed(&self, texts: &[String]) -> crate::EmbedFuture<'_> {
        let texts = texts.to_vec();
        Box::pin(async move {
            if texts.is_empty() {
                return Ok(Vec::new());
            }

            // Ollama's /api/embed supports batch input
            let body = EmbedRequest {
                model: self.model.clone(),
                input: texts.clone(),
            };

            let url = format!("{}/api/embed", self.base_url);
            debug!(url, model = %self.model, count = texts.len(), "embedding via Ollama");

            let resp = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .context("failed to send embed request to Ollama")?;

            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!(
                    "Ollama embed returned {status}: {text}\n\
                     hint: run `ollama pull {model}` to download the embedding model",
                    model = self.model
                );
            }

            let embed_resp: EmbedResponse = resp
                .json()
                .await
                .context("failed to parse Ollama embed response")?;

            Ok(embed_resp.embeddings)
        })
    }

    fn dimension(&self) -> usize {
        self.dim
    }
}
