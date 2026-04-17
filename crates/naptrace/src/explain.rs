use anyhow::{Context, Result};
use colored::Colorize;

/// Run the explain command — re-runs the full pipeline for a specific finding
/// and shows the complete LLM trace.
pub async fn run(finding_id: &str, reasoner: &str, model: Option<&str>) -> Result<()> {
    // Finding IDs are formatted as "file:line" (e.g. "src/math.c:4")
    // For now, explain re-runs the hunt with --explain-only style detail

    let parts: Vec<&str> = finding_id.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "invalid finding ID: {finding_id}\n\
             expected format: <file>:<line> (e.g. src/math.c:4)"
        );
    }

    let file = parts[0];
    let line: u32 = parts[1]
        .parse()
        .context("invalid line number in finding ID")?;

    println!("\n{}", "naptrace explain".bold());
    println!("{}", "─".repeat(60).dimmed());
    println!("  {} {}:{}", "finding:".dimmed(), file, line);
    println!("  {} {}", "reasoner:".dimmed(), reasoner);
    if let Some(m) = model {
        println!("  {} {}", "model:".dimmed(), m);
    }
    println!("{}", "─".repeat(60).dimmed());

    // Load the explain prompt
    let prompt_template = naptrace_core::prompt::load_prompt("explain_finding")
        .context("failed to load explain_finding prompt")?;

    let provider = naptrace_llm::Provider::from_str(reasoner)?;
    let llm = naptrace_llm::create_client(provider).await?;

    let llm_model = model
        .unwrap_or_else(|| {
            if provider != naptrace_llm::Provider::Anthropic {
                provider.default_model()
            } else {
                &prompt_template.meta.model
            }
        });

    println!(
        "\n  {} sending to {} ({})...\n",
        "[explain]".cyan(),
        reasoner,
        llm_model,
    );

    // Build a minimal request asking the LLM to explain the finding location
    let user_content = format!(
        "Please explain the potential vulnerability at {file}:{line}.\n\n\
         This finding was identified during variant analysis. Walk through\n\
         the code path step by step, highlight the exact lines where the\n\
         vulnerability pattern manifests, and explain what an attacker\n\
         would need to control to exploit this path.\n\n\
         File: {file}\n\
         Line: {line}\n\n\
         Respond with the JSON schema specified in your instructions."
    );

    let request = naptrace_llm::LlmRequest {
        model: llm_model.to_string(),
        messages: vec![
            naptrace_llm::Message::system(prompt_template.body.clone()),
            naptrace_llm::Message::user(user_content),
        ],
        temperature: prompt_template.meta.temperature,
        max_tokens: prompt_template.meta.max_tokens,
    };

    // Show what we're sending
    println!("  {}", "prompt (system):".dimmed());
    let system_preview: String = prompt_template.body.lines().take(3).collect::<Vec<_>>().join("\n");
    println!("    {}...", system_preview);
    println!();

    let response = llm
        .complete(&request)
        .await
        .context("LLM explain call failed")?;

    if let Some(ref usage) = response.usage {
        println!(
            "  {} input={} output={}",
            "tokens:".dimmed(),
            usage.input_tokens,
            usage.output_tokens,
        );
    }

    println!("\n  {}", "response:".dimmed());
    println!("{}", "─".repeat(60).dimmed());

    // Try to parse as structured JSON, fall back to raw output
    let content = response.content.trim();
    let json_str = naptrace_core::signature::extract_json_block(content);

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(walkthrough) = parsed.get("walkthrough").and_then(|v| v.as_str()) {
            println!("\n  {}", "walkthrough:".bold());
            for line in walkthrough.lines() {
                println!("    {line}");
            }
        }

        if let Some(lines) = parsed.get("key_lines").and_then(|v| v.as_array()) {
            let line_strs: Vec<String> = lines
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n.to_string()))
                .collect();
            if !line_strs.is_empty() {
                println!("\n  {} {}", "key lines:".bold(), line_strs.join(", "));
            }
        }

        if let Some(control) = parsed.get("attacker_control").and_then(|v| v.as_str()) {
            println!("\n  {}", "attacker control:".bold());
            println!("    {control}");
        }

        if let Some(uncertainty) = parsed.get("uncertainty").and_then(|v| v.as_str()) {
            println!("\n  {}", "uncertainty:".bold());
            println!("    {uncertainty}");
        }
    } else {
        // Raw output
        println!("{content}");
    }

    println!("\n{}", "─".repeat(60).dimmed());
    println!();

    Ok(())
}
