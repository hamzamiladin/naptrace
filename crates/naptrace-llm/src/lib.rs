pub mod anthropic;
pub mod groq;
pub mod ollama;
pub mod openai;
pub mod retry;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: f32,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".into(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAi,
    Ollama,
    Groq,
}

impl std::str::FromStr for Provider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" => Ok(Self::Anthropic),
            "openai" | "gpt" => Ok(Self::OpenAi),
            "ollama" | "local" => Ok(Self::Ollama),
            "groq" => Ok(Self::Groq),
            _ => bail!("unknown LLM provider: {s} (expected: anthropic, openai, ollama, groq)"),
        }
    }
}

impl Provider {
    pub fn default_model(&self) -> &'static str {
        match self {
            Self::Anthropic => "claude-opus-4-7",
            Self::OpenAi => "gpt-4o",
            Self::Ollama => "qwen2.5-coder:32b",
            Self::Groq => "llama-3.3-70b-versatile",
        }
    }
}

/// Create an LLM client for the given provider.
pub async fn create_client(provider: Provider) -> Result<Box<dyn LlmClient>> {
    match provider {
        Provider::Anthropic => {
            let client = anthropic::AnthropicClient::from_env()?;
            Ok(Box::new(client))
        }
        Provider::OpenAi => {
            let client = openai::OpenAiClient::from_env()?;
            Ok(Box::new(client))
        }
        Provider::Ollama => {
            let client = ollama::OllamaClient::from_env();
            Ok(Box::new(client))
        }
        Provider::Groq => {
            let client = groq::GroqClient::from_env()?;
            Ok(Box::new(client))
        }
    }
}

/// Trait for LLM completion backends.
pub trait LlmClient: Send + Sync {
    fn complete(
        &self,
        request: &LlmRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LlmResponse>> + Send + '_>>;

    fn provider(&self) -> Provider;
}
