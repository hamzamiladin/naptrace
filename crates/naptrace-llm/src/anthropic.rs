use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{LlmClient, LlmRequest, LlmResponse, Provider, Usage};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

pub struct AnthropicClient {
    client: Client,
    api_key: String,
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<ApiMessage>,
    temperature: f32,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
    model: String,
    usage: ApiUsage,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Deserialize)]
struct ApiUsage {
    input_tokens: u32,
    output_tokens: u32,
}

impl AnthropicClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub fn from_env() -> Result<Self> {
        let key = std::env::var("ANTHROPIC_API_KEY")
            .context("ANTHROPIC_API_KEY not set")?;
        Ok(Self::new(key))
    }
}

impl LlmClient for AnthropicClient {
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LlmResponse>> + Send + '_>> {
        let request = request.clone();
        Box::pin(async move {
            // Anthropic uses a top-level `system` field, not a system message
            let mut system = None;
            let mut messages = Vec::new();

            for msg in &request.messages {
                if msg.role == "system" {
                    system = Some(msg.content.clone());
                } else {
                    messages.push(ApiMessage {
                        role: msg.role.clone(),
                        content: msg.content.clone(),
                    });
                }
            }

            let body = ApiRequest {
                model: request.model.clone(),
                max_tokens: request.max_tokens,
                system,
                messages,
                temperature: request.temperature,
            };

            let resp = self
                .client
                .post(API_URL)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", API_VERSION)
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .context("failed to send request to Anthropic API")?;

            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("Anthropic API returned {status}: {text}");
            }

            let api_resp: ApiResponse = resp
                .json()
                .await
                .context("failed to parse Anthropic response")?;

            let content = api_resp
                .content
                .into_iter()
                .map(|b| b.text)
                .collect::<Vec<_>>()
                .join("");

            Ok(LlmResponse {
                content,
                model: api_resp.model,
                usage: Some(Usage {
                    input_tokens: api_resp.usage.input_tokens,
                    output_tokens: api_resp.usage.output_tokens,
                }),
            })
        })
    }

    fn provider(&self) -> Provider {
        Provider::Anthropic
    }
}
