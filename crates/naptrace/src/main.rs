mod doctor;
mod hunt;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "naptrace",
    about = "Variant analysis, open-sourced. Feed a CVE patch, find its structural twins.",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check that all dependencies (Joern, models, API keys) are available
    Doctor,

    /// Hunt for variants of a known vulnerability
    Hunt {
        /// Patch source: <repo>@<sha>, cve:CVE-XXXX-XXXXX, file:patch.diff, or pr:<url>
        patch_source: String,

        /// Target repository path or git URL (default: current directory)
        #[arg(default_value = ".")]
        target: String,

        /// Languages to scan (auto-detect if omitted)
        #[arg(long, value_delimiter = ',')]
        languages: Option<Vec<String>>,

        /// LLM provider for reasoning
        #[arg(long, default_value = "anthropic")]
        reasoner: String,

        /// Override default model for the chosen reasoner
        #[arg(long)]
        model: Option<String>,

        /// Embedding provider
        #[arg(long, default_value = "auto")]
        embedder: String,

        /// Number of top candidates to retrieve
        #[arg(long, default_value_t = 50)]
        top_k: usize,

        /// Minimum severity to report
        #[arg(long, default_value = "medium")]
        severity_floor: String,

        /// Output format
        #[arg(long, default_value = "auto")]
        output: String,

        /// Open GitHub issues for feasible findings
        #[arg(long)]
        file_issues: bool,

        /// Cache directory
        #[arg(long)]
        cache_dir: Option<String>,

        /// Force local models, fail if network needed
        #[arg(long)]
        offline: bool,

        /// Skip reasoning, only show what would be sent to the LLM
        #[arg(long)]
        explain_only: bool,
    },

    /// Replay the LLM call for a finding with full trace
    Explain {
        /// Finding ID to explain
        finding_id: String,
    },

    /// Run the public benchmark against this build
    Bench,

    /// Emit a starter .github/workflows/naptrace.yml
    InitAction,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => doctor::run().await,
        Commands::Hunt {
            patch_source,
            target,
            explain_only,
            reasoner,
            model,
            top_k,
            languages,
            ..
        } => {
            let langs: Vec<naptrace_core::Language> = languages
                .unwrap_or_default()
                .iter()
                .filter_map(|s| naptrace_core::Language::from_extension(s))
                .collect();

            hunt::run(hunt::HuntOptions {
                patch_source,
                target,
                explain_only,
                reasoner,
                model,
                top_k,
                languages: langs,
            })
            .await
        }
        Commands::Explain { .. } => {
            eprintln!("explain is not yet implemented");
            std::process::exit(2);
        }
        Commands::Bench => {
            eprintln!("bench is not yet implemented");
            std::process::exit(2);
        }
        Commands::InitAction => {
            eprintln!("init-action is not yet implemented");
            std::process::exit(2);
        }
    }
}
