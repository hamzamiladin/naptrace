use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{LlmClient, LlmRequest, LlmResponse, Provider, Usage};

const API_URL: &str = "https://api.openai.com/v1/chat/completions";

pub struct OpenAiClient {
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

#[derive(Serialize, Clone)]
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

impl OpenAiClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    pub fn from_env() -> Result<Self> {
        let key = std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not set")?;
        Ok(Self::new(key))
    }
}

impl LlmClient for OpenAiClient {
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

            let api_key = self.api_key.clone();
            let client = &self.client;

            let resp = crate::retry::send_with_retry(
                client,
                || {
                    client
                        .post(API_URL)
                        .header("Authorization", format!("Bearer {api_key}"))
                        .header("Content-Type", "application/json")
                        .json(&body)
                },
                "OpenAI",
            )
            .await?;

            let api_resp: ApiResponse = resp
                .json()
                .await
                .context("failed to parse OpenAI response")?;

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
        Provider::OpenAi
    }
}
