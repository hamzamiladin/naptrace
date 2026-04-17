use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{LlmClient, LlmRequest, LlmResponse, Provider};

pub struct OllamaClient {
    client: Client,
    base_url: String,
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    messages: Vec<ApiMessage>,
    stream: bool,
    options: ApiOptions,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ApiOptions {
    temperature: f32,
    num_predict: u32,
}

#[derive(Deserialize)]
struct ApiResponse {
    message: ResponseMessage,
    model: String,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

impl OllamaClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    pub fn from_env() -> Self {
        let base_url =
            std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".into());
        Self::new(base_url)
    }
}

impl LlmClient for OllamaClient {
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LlmResponse>> + Send + '_>> {
        let request = request.clone();
        Box::pin(async move {
            let messages: Vec<ApiMessage> = request
                .messages
                .iter()
                .map(|m| ApiMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                })
                .collect();

            let body = ApiRequest {
                model: request.model.clone(),
                messages,
                stream: false,
                options: ApiOptions {
                    temperature: request.temperature,
                    num_predict: request.max_tokens,
                },
            };

            let url = format!("{}/api/chat", self.base_url);

            let resp = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .context("failed to send request to Ollama")?;

            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Ollama returned {status}: {text}");
            }

            let api_resp: ApiResponse = resp
                .json()
                .await
                .context("failed to parse Ollama response")?;

            Ok(LlmResponse {
                content: api_resp.message.content,
                model: api_resp.model,
                usage: None,
            })
        })
    }

    fn provider(&self) -> Provider {
        Provider::Ollama
    }
}
