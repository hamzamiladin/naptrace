use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{LlmClient, LlmRequest, LlmResponse, Provider, Usage};

const API_URL: &str = "https://api.groq.com/openai/v1/chat/completions";

pub struct GroqClient {
    client: Client,
    api_key: String,
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    messages: Vec<ApiMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    choices: Vec<Choice>,
    model: String,
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
struct ApiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

impl GroqClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub fn from_env() -> Result<Self> {
        let key = std::env::var("GROQ_API_KEY").context("GROQ_API_KEY not set")?;
        Ok(Self::new(key))
    }
}

impl LlmClient for GroqClient {
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
                temperature: request.temperature,
                max_tokens: request.max_tokens,
            };

            // Retry loop for rate limiting (Groq free tier: 12K TPM)
            let mut last_error = String::new();
            let mut resp_body = None;

            for attempt in 0..4 {
                let resp = self
                    .client
                    .post(API_URL)
                    .header("Authorization", format!("Bearer {}", self.api_key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .context("failed to send request to Groq API")?;

                let status = resp.status();
                if status.as_u16() == 429 {
                    // Rate limited — wait and retry
                    let wait = match attempt {
                        0 => 5,
                        1 => 15,
                        2 => 30,
                        _ => 60,
                    };
                    tracing::debug!(
                        "Groq rate limited, waiting {wait}s (attempt {}/4)",
                        attempt + 1
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    last_error = resp.text().await.unwrap_or_default();
                    continue;
                }

                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    anyhow::bail!("Groq API returned {status}: {text}");
                }

                resp_body = Some(resp);
                break;
            }

            let resp = resp_body.ok_or_else(|| {
                anyhow::anyhow!("Groq rate limit exceeded after 4 retries: {last_error}")
            })?;

            let api_resp: ApiResponse =
                resp.json().await.context("failed to parse Groq response")?;

            let content = api_resp
                .choices
                .first()
                .and_then(|c| c.message.content.clone())
                .unwrap_or_default();

            Ok(LlmResponse {
                content,
                model: api_resp.model,
                usage: api_resp.usage.map(|u| Usage {
                    input_tokens: u.prompt_tokens,
                    output_tokens: u.completion_tokens,
                }),
            })
        })
    }

    fn provider(&self) -> Provider {
        Provider::Groq
    }
}
