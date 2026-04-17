use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// Parsed representation of a patch source.
#[derive(Debug)]
pub enum PatchSource {
    /// A raw diff file on disk: `file:path.diff`
    File(String),
    /// A CVE identifier: `cve:CVE-2025-6965`
    Cve(String),
    /// A git repo + commit SHA: `https://github.com/user/repo@abc123`
    GitCommit { repo_url: String, commit_sha: String },
    /// A pull request URL: `pr:https://github.com/user/repo/pull/123`
    PullRequest(String),
}

impl PatchSource {
    /// Parse a patch source string from the CLI.
    pub fn parse(input: &str) -> Result<Self> {
        if let Some(path) = input.strip_prefix("file:") {
            return Ok(Self::File(path.to_string()));
        }

        if let Some(cve) = input.strip_prefix("cve:") {
            let cve = cve.to_uppercase();
            if !cve.starts_with("CVE-") {
                bail!("invalid CVE ID format: expected CVE-YYYY-NNNNN, got {cve}");
            }
            return Ok(Self::Cve(cve));
        }

        if let Some(url) = input.strip_prefix("pr:") {
            return Ok(Self::PullRequest(url.to_string()));
        }

        // Try repo@sha format
        if let Some((repo, sha)) = input.rsplit_once('@') {
            if sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(Self::GitCommit {
                    repo_url: repo.to_string(),
                    commit_sha: sha.to_string(),
                });
            }
        }

        // If it looks like a file path (contains . or /), treat as file
        if input.contains('.') || input.contains('/') {
            if std::path::Path::new(input).exists() {
                return Ok(Self::File(input.to_string()));
            }
        }

        bail!(
            "could not parse patch source: {input}\n\
             expected one of:\n  \
             file:path.diff\n  \
             cve:CVE-YYYY-NNNNN\n  \
             <repo-url>@<commit-sha>\n  \
             pr:<pull-request-url>"
        );
    }

    /// Fetch the diff content, commit message, and optional CVE ID.
    pub async fn fetch(&self) -> Result<(String, Option<String>, Option<String>)> {
        match self {
            Self::File(path) => {
                info!(path, "reading diff from file");
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read diff file: {path}"))?;
                Ok((content, None, None))
            }

            Self::Cve(cve_id) => {
                info!(cve_id, "fetching patch for CVE");
                let diff = fetch_cve_patch(cve_id).await?;
                Ok((diff, None, Some(cve_id.clone())))
            }

            Self::GitCommit {
                repo_url,
                commit_sha,
            } => {
                info!(repo_url, commit_sha, "fetching commit diff");
                let (diff, msg) = fetch_git_commit_diff(repo_url, commit_sha).await?;
                Ok((diff, Some(msg), None))
            }

            Self::PullRequest(url) => {
                info!(url, "fetching PR diff");
                let diff = fetch_pr_diff(url).await?;
                Ok((diff, None, None))
            }
        }
    }
}

/// Fetch a commit's diff from GitHub's API.
/// Accepts URLs like `https://github.com/user/repo` or `user/repo`.
async fn fetch_git_commit_diff(
    repo_url: &str,
    commit_sha: &str,
) -> Result<(String, String)> {
    let (owner, repo) = parse_github_repo(repo_url)?;

    let api_url = format!(
        "https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
    );
    debug!(api_url, "fetching commit from GitHub API");

    let client = reqwest::Client::new();
    let resp = client
        .get(&api_url)
        .header("Accept", "application/vnd.github.v3.diff")
        .header("User-Agent", "naptrace")
        .send()
        .await
        .context("failed to fetch commit from GitHub")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("GitHub API returned {status}: {body}");
    }

    let diff = resp.text().await.context("failed to read diff body")?;

    // Fetch commit message separately (the diff endpoint doesn't include it)
    let msg_resp = client
        .get(&format!(
            "https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
        ))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "naptrace")
        .send()
        .await
        .context("failed to fetch commit metadata")?;

    let commit_msg = if msg_resp.status().is_success() {
        let json: serde_json::Value = msg_resp.json().await.unwrap_or_default();
        json["commit"]["message"]
            .as_str()
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };

    Ok((diff, commit_msg))
}

/// Get the NVD cache directory.
fn nvd_cache_dir() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("dev", "naptrace", "naptrace")
        .map(|d| d.cache_dir().join("nvd"))
}

/// Check the NVD cache for a previously fetched CVE response.
fn nvd_cache_get(cve_id: &str) -> Option<serde_json::Value> {
    let dir = nvd_cache_dir()?;
    let path = dir.join(format!("{cve_id}.json"));
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Store an NVD response in the cache.
fn nvd_cache_put(cve_id: &str, json: &serde_json::Value) {
    if let Some(dir) = nvd_cache_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{cve_id}.json"));
        let _ = std::fs::write(&path, serde_json::to_string(json).unwrap_or_default());
    }
}

/// Fetch a CVE's patch from GitHub advisories or NVD references.
/// Caches NVD responses to disk. Rate-limits to 5 requests per 30 seconds.
async fn fetch_cve_patch(cve_id: &str) -> Result<String> {
    // Check cache first
    let json = if let Some(cached) = nvd_cache_get(cve_id) {
        debug!(cve_id, "using cached NVD response");
        cached
    } else {
        let api_url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        );
        debug!(api_url, "fetching CVE from NVD");

        let client = reqwest::Client::new();
        let resp = client
            .get(&api_url)
            .header("User-Agent", "naptrace")
            .send()
            .await
            .context("failed to fetch CVE from NVD")?;

        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // NVD rate limit: wait and retry once
            debug!("NVD rate limited — waiting 6 seconds");
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let resp = client
                .get(&api_url)
                .header("User-Agent", "naptrace")
                .send()
                .await
                .context("failed to retry NVD fetch")?;
            if !resp.status().is_success() {
                bail!("NVD API returned {} for {cve_id} (after retry)", resp.status());
            }
            let json: serde_json::Value = resp.json().await.context("failed to parse NVD response")?;
            nvd_cache_put(cve_id, &json);
            json
        } else if !resp.status().is_success() {
            let status = resp.status();
            bail!("NVD API returned {status} for {cve_id}");
        } else {
            let json: serde_json::Value = resp.json().await.context("failed to parse NVD response")?;
            nvd_cache_put(cve_id, &json);
            json
        }
    };

    // Extract reference URLs and find a GitHub commit
    let references = json["vulnerabilities"][0]["cve"]["references"]
        .as_array()
        .context("no references found for this CVE")?;

    for reference in references {
        let url = reference["url"].as_str().unwrap_or("");
        debug!(url, "checking reference URL");

        // Look for GitHub commit URLs
        if let Some(diff) = try_github_commit_url(url).await? {
            return Ok(diff);
        }
    }

    bail!(
        "could not find a GitHub commit patch for {cve_id}. \
         Try providing the patch directly: naptrace hunt file:patch.diff"
    );
}

/// Try to extract a diff from a GitHub commit URL.
/// Handles URLs like:
///   https://github.com/user/repo/commit/abc123
///   https://github.com/user/repo/commit/abc123.patch
async fn try_github_commit_url(url: &str) -> Result<Option<String>> {
    // Match github.com/<owner>/<repo>/commit/<sha>
    let parts: Vec<&str> = url.split('/').collect();
    let is_github_commit = parts.len() >= 7
        && parts[2] == "github.com"
        && parts[5] == "commit";

    if !is_github_commit {
        return Ok(None);
    }

    let owner = parts[3];
    let repo = parts[4];
    let sha = parts[6].trim_end_matches(".patch");

    debug!(owner, repo, sha, "found GitHub commit reference");

    let diff_url = format!("https://github.com/{owner}/{repo}/commit/{sha}.patch");

    let client = reqwest::Client::new();
    let resp = client
        .get(&diff_url)
        .header("User-Agent", "naptrace")
        .send()
        .await
        .context("failed to fetch patch from GitHub")?;

    if resp.status().is_success() {
        let diff = resp.text().await.context("failed to read patch body")?;
        Ok(Some(diff))
    } else {
        Ok(None)
    }
}

/// Fetch a PR's diff from GitHub.
async fn fetch_pr_diff(url: &str) -> Result<String> {
    // Parse PR URL: https://github.com/user/repo/pull/123
    let parts: Vec<&str> = url.split('/').collect();
    if parts.len() < 7 || parts[5] != "pull" {
        bail!(
            "invalid PR URL: {url}\n\
             expected: https://github.com/<owner>/<repo>/pull/<number>"
        );
    }

    let owner = parts[3];
    let repo = parts[4];
    let number = parts[6];

    let api_url = format!(
        "https://api.github.com/repos/{owner}/{repo}/pulls/{number}"
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&api_url)
        .header("Accept", "application/vnd.github.v3.diff")
        .header("User-Agent", "naptrace")
        .send()
        .await
        .context("failed to fetch PR diff from GitHub")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("GitHub API returned {status} for PR: {body}");
    }

    resp.text().await.context("failed to read PR diff body")
}

/// Parse a GitHub repo identifier from a URL or `owner/repo` string.
fn parse_github_repo(input: &str) -> Result<(String, String)> {
    // Handle full URLs
    if input.contains("github.com") {
        let parts: Vec<&str> = input.split('/').collect();
        if parts.len() >= 5 {
            let owner = parts[3].to_string();
            let repo = parts[4].trim_end_matches(".git").to_string();
            return Ok((owner, repo));
        }
    }

    // Handle owner/repo format
    if let Some((owner, repo)) = input.split_once('/') {
        if !owner.is_empty() && !repo.is_empty() {
            return Ok((owner.to_string(), repo.to_string()));
        }
    }

    bail!(
        "could not parse GitHub repo from: {input}\n\
         expected: https://github.com/owner/repo or owner/repo"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_source() {
        let source = PatchSource::parse("file:test.diff").unwrap();
        assert!(matches!(source, PatchSource::File(p) if p == "test.diff"));
    }

    #[test]
    fn parse_cve_source() {
        let source = PatchSource::parse("cve:CVE-2025-6965").unwrap();
        assert!(matches!(source, PatchSource::Cve(id) if id == "CVE-2025-6965"));
    }

    #[test]
    fn parse_cve_lowercase() {
        let source = PatchSource::parse("cve:cve-2025-6965").unwrap();
        assert!(matches!(source, PatchSource::Cve(id) if id == "CVE-2025-6965"));
    }

    #[test]
    fn parse_git_commit() {
        let source =
            PatchSource::parse("https://github.com/user/repo@abc1234").unwrap();
        assert!(matches!(
            source,
            PatchSource::GitCommit { repo_url, commit_sha }
            if repo_url == "https://github.com/user/repo" && commit_sha == "abc1234"
        ));
    }

    #[test]
    fn parse_pr_source() {
        let source =
            PatchSource::parse("pr:https://github.com/user/repo/pull/42").unwrap();
        assert!(matches!(source, PatchSource::PullRequest(url) if url.contains("42")));
    }

    #[test]
    fn parse_github_repo_full_url() {
        let (owner, repo) =
            parse_github_repo("https://github.com/sqlite/sqlite").unwrap();
        assert_eq!(owner, "sqlite");
        assert_eq!(repo, "sqlite");
    }

    #[test]
    fn parse_github_repo_short() {
        let (owner, repo) = parse_github_repo("sqlite/sqlite").unwrap();
        assert_eq!(owner, "sqlite");
        assert_eq!(repo, "sqlite");
    }

    #[test]
    fn parse_invalid_source() {
        assert!(PatchSource::parse("nonsense").is_err());
    }
}
