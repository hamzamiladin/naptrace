use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Instant;

pub struct HuntOptions {
    pub patch_source: String,
    pub target: String,
    pub explain_only: bool,
}

pub async fn run(opts: HuntOptions) -> Result<()> {
    let start = Instant::now();

    let pb = ProgressBar::new(6);
    pb.set_style(
        ProgressStyle::with_template(
            "  [{pos}/{len}] {msg:.cyan}",
        )
        .unwrap(),
    );

    // Stage 1: Ingest
    pb.set_position(1);
    pb.set_message("ingesting patch...");

    let seed = naptrace_core::ingest::ingest(&opts.patch_source, &opts.target).await?;

    pb.set_message("ingesting patch... done");

    pb.finish_and_clear();

    let elapsed = start.elapsed();

    // Print summary
    println!(
        "\n{}",
        "naptrace hunt".bold()
    );
    println!("{}", "─".repeat(60).dimmed());

    println!(
        "  {} {}",
        "patch:".dimmed(),
        opts.patch_source
    );

    if let Some(ref cve) = seed.cve_id {
        println!("  {} {}", "cve:".dimmed(), cve);
    }

    println!(
        "  {} {}",
        "language:".dimmed(),
        seed.language
    );

    println!(
        "  {} {} file(s), {} hunk(s)",
        "diff:".dimmed(),
        seed.patched_files.len(),
        seed.patched_files.iter().map(|f| f.hunks.len()).sum::<usize>()
    );

    if let Some(ref msg) = seed.commit_msg {
        let first_line = msg.lines().next().unwrap_or(msg);
        println!(
            "  {} {}",
            "commit:".dimmed(),
            first_line
        );
    }

    println!("{}", "─".repeat(60).dimmed());

    // Print patched files
    for file in &seed.patched_files {
        let lang = file
            .language
            .map(|l| format!("[{l}]"))
            .unwrap_or_default();

        println!(
            "  {} {} {}",
            "~".yellow(),
            file.path,
            lang.dimmed()
        );

        for (i, hunk) in file.hunks.iter().enumerate() {
            println!(
                "    hunk {}: @@ -{},{} +{},{} @@  ({} removed, {} added)",
                i + 1,
                hunk.old_start,
                hunk.old_lines,
                hunk.new_start,
                hunk.new_lines,
                hunk.removed_lines.len().to_string().red(),
                hunk.added_lines.len().to_string().green(),
            );
        }
    }

    println!("{}", "─".repeat(60).dimmed());

    if opts.explain_only {
        println!(
            "\n  {} ingested in {:.1}s — {} mode, stopping here.",
            "[explain-only]".yellow(),
            elapsed.as_secs_f64(),
            "--explain-only".dimmed(),
        );

        // Print what would be sent to Stage 2
        println!(
            "\n  {} the distilled signature for this patch would be computed next.",
            "next:".dimmed(),
        );
        println!(
            "  {} stages 2-6 require a target repo and configured LLM.",
            "note:".dimmed(),
        );
    } else {
        println!(
            "\n  {} stages 2-6 are not yet implemented.",
            "[todo]".yellow(),
        );
        println!(
            "  ingested in {:.1}s. run with {} to see parsed output.",
            elapsed.as_secs_f64(),
            "--explain-only".dimmed(),
        );
    }

    println!();
    Ok(())
}
