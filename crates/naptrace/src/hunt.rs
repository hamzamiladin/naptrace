use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Instant;

pub struct HuntOptions {
    pub patch_source: String,
    pub target: String,
    pub explain_only: bool,
    pub reasoner: String,
    pub model: Option<String>,
    pub top_k: usize,
    pub languages: Vec<naptrace_core::Language>,
}

pub async fn run(opts: HuntOptions) -> Result<()> {
    let start = Instant::now();

    let pb = ProgressBar::new(6);
    pb.set_style(
        ProgressStyle::with_template("  [{pos}/{len}] {msg:.cyan}").unwrap(),
    );

    // Stage 1: Ingest
    pb.set_position(1);
    pb.set_message("ingesting patch...");

    let seed =
        naptrace_core::ingest::ingest(&opts.patch_source, &opts.target).await?;

    let ingest_elapsed = start.elapsed();
    pb.set_message(format!("ingesting patch... done ({:.1}s)", ingest_elapsed.as_secs_f64()));

    // Print ingest summary
    pb.finish_and_clear();
    println!("\n{}", "naptrace hunt".bold());
    println!("{}", "─".repeat(60).dimmed());

    println!("  {} {}", "patch:".dimmed(), opts.patch_source);
    if let Some(ref cve) = seed.cve_id {
        println!("  {} {}", "cve:".dimmed(), cve);
    }
    println!("  {} {}", "language:".dimmed(), seed.language);
    println!(
        "  {} {} file(s), {} hunk(s)",
        "diff:".dimmed(),
        seed.patched_files.len(),
        seed.patched_files.iter().map(|f| f.hunks.len()).sum::<usize>()
    );
    if let Some(ref msg) = seed.commit_msg {
        let first_line = msg.lines().next().unwrap_or(msg);
        println!("  {} {}", "commit:".dimmed(), first_line);
    }

    println!("{}", "─".repeat(60).dimmed());

    for file in &seed.patched_files {
        let lang = file.language.map(|l| format!("[{l}]")).unwrap_or_default();
        println!("  {} {} {}", "~".yellow(), file.path, lang.dimmed());

        for (i, hunk) in file.hunks.iter().enumerate() {
            println!(
                "    hunk {}: @@ -{},{} +{},{} @@  ({} removed, {} added)",
                i + 1,
                hunk.old_start, hunk.old_lines,
                hunk.new_start, hunk.new_lines,
                hunk.removed_lines.len().to_string().red(),
                hunk.added_lines.len().to_string().green(),
            );
        }
    }

    println!("{}", "─".repeat(60).dimmed());

    if opts.explain_only {
        println!(
            "\n  {} ingested in {:.1}s — stopping before LLM calls.",
            "[explain-only]".yellow(),
            ingest_elapsed.as_secs_f64(),
        );
        println!();
        return Ok(());
    }

    // Stage 2: Distill signature
    let pb2 = ProgressBar::new_spinner();
    pb2.set_style(ProgressStyle::with_template("  [2/6] {msg:.cyan}").unwrap());
    pb2.set_message("distilling vulnerability signature...");
    pb2.enable_steady_tick(std::time::Duration::from_millis(100));

    let provider = naptrace_llm::Provider::from_str(&opts.reasoner)?;
    let llm = naptrace_llm::create_client(provider).await?;

    // Use explicit --model, or fall back to the provider's default
    // (don't use the prompt template's model for non-Anthropic providers)
    let model_override = opts
        .model
        .as_deref()
        .or_else(|| {
            if provider != naptrace_llm::Provider::Anthropic {
                Some(provider.default_model())
            } else {
                None // let the prompt template decide
            }
        });
    let signature = naptrace_core::signature::distill(&seed, llm.as_ref(), model_override).await?;

    let distill_elapsed = start.elapsed();
    pb2.finish_and_clear();

    println!("\n  {} distilled in {:.1}s", "[signature]".green(), distill_elapsed.as_secs_f64());
    println!("{}", "─".repeat(60).dimmed());
    println!("  {} {}", "bug class:".dimmed(), signature.bug_class.yellow());
    println!("  {} {}/10", "confidence:".dimmed(), signature.confidence);
    println!("  {} {}", "root cause:".dimmed(), signature.root_cause);
    println!();
    println!("  {}", "pattern:".dimmed());
    println!("    {}", signature.vulnerable_pattern);
    println!();
    println!("  {}", "brief:".dimmed());
    for line in textwrap(&signature.nl_brief, 70) {
        println!("    {line}");
    }

    if !signature.sanitizer_gaps.is_empty() {
        println!();
        println!("  {}", "sanitizer gaps:".dimmed());
        for gap in &signature.sanitizer_gaps {
            println!("    - {gap}");
        }
    }

    if !signature.required_preconditions.is_empty() {
        println!();
        println!("  {}", "preconditions:".dimmed());
        for pre in &signature.required_preconditions {
            println!("    - {pre}");
        }
    }

    println!("{}", "─".repeat(60).dimmed());

    // Stage 3: Retrieve candidate sites
    let pb3 = ProgressBar::new_spinner();
    pb3.set_style(ProgressStyle::with_template("  [3/6] {msg:.cyan}").unwrap());
    pb3.set_message(format!("retrieving candidate sites (K={})...", opts.top_k));
    pb3.enable_steady_tick(std::time::Duration::from_millis(100));

    let embedder = naptrace_embed::create_embedder();
    let target_path = std::path::Path::new(&opts.target);

    let candidates = naptrace_core::retrieve::retrieve(
        target_path,
        &signature,
        embedder.as_ref(),
        &opts.languages,
        opts.top_k,
    )
    .await?;

    let retrieve_elapsed = start.elapsed();
    pb3.finish_and_clear();

    println!(
        "\n  {} {} candidates in {:.1}s",
        "[candidates]".green(),
        candidates.len(),
        retrieve_elapsed.as_secs_f64(),
    );
    println!("{}", "─".repeat(60).dimmed());

    if candidates.is_empty() {
        println!("  no candidate sites found.");
    } else {
        for (i, c) in candidates.iter().enumerate() {
            let sim_pct = (c.similarity * 100.0) as u32;
            println!(
                "  {}. {} {}:{}-{}  {} ({}% similar)",
                i + 1,
                c.function_name.bold(),
                c.file_path,
                c.start_line,
                c.end_line,
                format!("[{}]", c.language).dimmed(),
                sim_pct,
            );
        }
    }

    println!("{}", "─".repeat(60).dimmed());

    // Stage 4: Slice CPG paths
    let pb4 = ProgressBar::new_spinner();
    pb4.set_style(ProgressStyle::with_template("  [4/6] {msg:.cyan}").unwrap());
    pb4.set_message(format!("slicing CPG paths for {} candidates...", candidates.len()));
    pb4.enable_steady_tick(std::time::Duration::from_millis(100));

    let sliced = naptrace_core::slice::slice_candidates(
        candidates,
        target_path,
        seed.language,
    )
    .await?;

    let slice_elapsed = start.elapsed();
    pb4.finish_and_clear();

    let sliced_count = sliced.iter().filter(|s| s.sliced).count();
    let paths_count: usize = sliced.iter().map(|s| s.cpg_paths.len()).sum();

    if sliced_count > 0 {
        println!(
            "\n  {} {} candidates sliced, {} paths found ({:.1}s)",
            "[cpg]".green(),
            sliced_count,
            paths_count,
            slice_elapsed.as_secs_f64(),
        );
    } else {
        println!(
            "\n  {} CPG slicing skipped (Joern/Java not available) ({:.1}s)",
            "[cpg]".yellow(),
            slice_elapsed.as_secs_f64(),
        );
        println!(
            "  {}",
            "candidates will be sent to the reasoner without path context.".dimmed()
        );
    }

    println!("{}", "─".repeat(60).dimmed());

    // Stages 5-6 not yet implemented
    println!(
        "\n  {} stages 5-6 (reason, report) not yet implemented.",
        "[todo]".yellow(),
    );
    println!(
        "  total elapsed: {:.1}s",
        start.elapsed().as_secs_f64(),
    );
    println!();

    Ok(())
}

/// Simple word-wrapping at the given width.
fn textwrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
