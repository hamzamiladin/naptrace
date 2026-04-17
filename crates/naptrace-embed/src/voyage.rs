use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::Embedder;

const API_URL: &str = "https://api.voyageai.com/v1/embeddings";
const MODEL: &str = "voyage-code-3";

pub struct VoyageEmbedder {
    client: Client,
    api_key: String,
}

#[derive(Serialize)]
struct EmbedRequest {
    model: String,
    input: Vec<String>,
    input_type: String,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedData>,
}

#[derive(Deserialize)]
struct EmbedData {
    embedding: Vec<f32>,
}

impl VoyageEmbedder {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub fn from_env() -> Self {
        let key = std::env::var("VOYAGE_API_KEY").unwrap_or_default();
        Self::new(key)
    }
}

impl Embedder for VoyageEmbedder {
    fn embed(
        &self,
        texts: &[String],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Vec<f32>>>> + Send + '_>>
    {
        let texts = texts.to_vec();
        Box::pin(async move {
            if texts.is_empty() {
                return Ok(Vec::new());
            }

            let body = EmbedRequest {
                model: MODEL.to_string(),
                input: texts.clone(),
                input_type: "document".to_string(),
            };

            debug!(count = texts.len(), "embedding via Voyage API");

            let resp = self
                .client
                .post(API_URL)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .context("failed to send embed request to Voyage")?;

            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Voyage API returned {status}: {text}");
            }

            let embed_resp: EmbedResponse = resp
                .json()
                .await
                .context("failed to parse Voyage embed response")?;

            Ok(embed_resp.data.into_iter().map(|d| d.embedding).collect())
        })
    }

    fn dimension(&self) -> usize {
        1024 // voyage-code-3 with Matryoshka truncation
    }
}
