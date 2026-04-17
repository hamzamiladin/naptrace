use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response};

const MAX_RETRIES: u32 = 4;
const BACKOFF_SECS: [u64; 4] = [5, 15, 30, 60];

/// Send an HTTP request with retry on rate limiting (429) and server errors (5xx).
/// Returns the successful response body.
pub async fn send_with_retry(
    _client: &Client,
    build_request: impl Fn() -> RequestBuilder,
    provider_name: &str,
) -> Result<Response> {
    let mut last_error = String::new();

    for attempt in 0..MAX_RETRIES {
        let resp = build_request()
            .send()
            .await
            .with_context(|| format!("failed to send request to {provider_name}"))?;

        let status = resp.status();

        // Rate limited or server error — retry with backoff
        if status.as_u16() == 429 || status.is_server_error() {
            let wait = BACKOFF_SECS[attempt as usize];
            last_error = resp.text().await.unwrap_or_default();
            tracing::warn!(
                provider = provider_name,
                status = status.as_u16(),
                attempt = attempt + 1,
                wait_secs = wait,
                "rate limited, retrying..."
            );
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            continue;
        }

        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("{provider_name} returned {status}: {text}");
        }

        return Ok(resp);
    }

    anyhow::bail!("{provider_name} failed after {MAX_RETRIES} retries. Last error: {last_error}")
}
