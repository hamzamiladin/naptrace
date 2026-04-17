use anyhow::Result;
use colored::Colorize;
use directories::ProjectDirs;
use std::path::PathBuf;

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

enum Status {
    Ok,
    Missing,
    Warning,
}

pub async fn run() -> Result<()> {
    println!("\n{}", "naptrace doctor".bold());
    println!(
        "{}\n",
        "checking dependencies and configuration...".dimmed()
    );

    let checks = vec![
        check_joern(),
        check_cache_dir(),
        check_anthropic_key(),
        check_openai_key(),
        check_voyage_key(),
        check_ollama(),
        check_git(),
    ];

    let mut has_missing = false;

    for check in &checks {
        let (icon, label) = match check.status {
            Status::Ok => ("[ok]".green(), check.name.normal()),
            Status::Missing => {
                has_missing = true;
                ("[missing]".red(), check.name.normal())
            }
            Status::Warning => ("[warn]".yellow(), check.name.normal()),
        };
        println!("  {:<12} {:<30} {}", icon, label, check.detail.dimmed());
    }

    println!();

    if has_missing {
        println!(
            "{}",
            "some dependencies are missing — naptrace may not work fully.".yellow()
        );
        println!("{}", "run with RUST_LOG=debug for more details.\n".dimmed());
    } else {
        println!("{}", "all checks passed.\n".green());
    }

    Ok(())
}

fn check_joern() -> Check {
    let installed = naptrace_joern::is_joern_installed();
    if installed {
        let path = naptrace_joern::joern_bin_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        Check {
            name: "joern",
            status: Status::Ok,
            detail: path,
        }
    } else {
        // Also check if joern is on PATH
        let on_path = which("joern");
        if let Some(path) = on_path {
            Check {
                name: "joern",
                status: Status::Ok,
                detail: format!("{} (system)", path),
            }
        } else {
            Check {
                name: "joern",
                status: Status::Missing,
                detail: "will be auto-downloaded on first `hunt`".into(),
            }
        }
    }
}

fn check_cache_dir() -> Check {
    let dir = cache_dir();
    match dir {
        Some(path) => {
            let exists = path.exists();
            if exists {
                let writable = std::fs::metadata(&path)
                    .map(|m| !m.permissions().readonly())
                    .unwrap_or(false);
                if writable {
                    Check {
                        name: "cache dir",
                        status: Status::Ok,
                        detail: path.display().to_string(),
                    }
                } else {
                    Check {
                        name: "cache dir",
                        status: Status::Missing,
                        detail: format!("{} (not writable)", path.display()),
                    }
                }
            } else {
                // Try to create it
                match std::fs::create_dir_all(&path) {
                    Ok(_) => Check {
                        name: "cache dir",
                        status: Status::Ok,
                        detail: format!("{} (created)", path.display()),
                    },
                    Err(e) => Check {
                        name: "cache dir",
                        status: Status::Missing,
                        detail: format!("{} ({})", path.display(), e),
                    },
                }
            }
        }
        None => Check {
            name: "cache dir",
            status: Status::Missing,
            detail: "could not determine platform cache directory".into(),
        },
    }
}

fn check_anthropic_key() -> Check {
    match std::env::var("ANTHROPIC_API_KEY") {
        Ok(key) if !key.is_empty() => Check {
            name: "anthropic api",
            status: Status::Ok,
            detail: format!("ANTHROPIC_API_KEY set ({}...)", &key[..8.min(key.len())]),
        },
        _ => Check {
            name: "anthropic api",
            status: Status::Warning,
            detail: "ANTHROPIC_API_KEY not set (optional, needed for --reasoner anthropic)".into(),
        },
    }
}

fn check_openai_key() -> Check {
    match std::env::var("OPENAI_API_KEY") {
        Ok(key) if !key.is_empty() => Check {
            name: "openai api",
            status: Status::Ok,
            detail: format!("OPENAI_API_KEY set ({}...)", &key[..8.min(key.len())]),
        },
        _ => Check {
            name: "openai api",
            status: Status::Warning,
            detail: "OPENAI_API_KEY not set (optional, needed for --reasoner openai)".into(),
        },
    }
}

fn check_voyage_key() -> Check {
    if naptrace_embed::has_voyage_key() {
        Check {
            name: "voyage embed",
            status: Status::Ok,
            detail: "VOYAGE_API_KEY set".into(),
        }
    } else {
        Check {
            name: "voyage embed",
            status: Status::Warning,
            detail: "VOYAGE_API_KEY not set (will use local ONNX embeddings)".into(),
        }
    }
}

fn check_ollama() -> Check {
    let host = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".into());

    // Just check if the env is set or default is reachable — don't block on network
    if std::env::var("OLLAMA_HOST").is_ok() {
        Check {
            name: "ollama",
            status: Status::Ok,
            detail: format!("OLLAMA_HOST={host}"),
        }
    } else {
        Check {
            name: "ollama",
            status: Status::Warning,
            detail: "OLLAMA_HOST not set (optional, needed for --reasoner ollama)".into(),
        }
    }
}

fn check_git() -> Check {
    match which("git") {
        Some(path) => Check {
            name: "git",
            status: Status::Ok,
            detail: path,
        },
        None => Check {
            name: "git",
            status: Status::Missing,
            detail: "git not found on PATH".into(),
        },
    }
}

fn which(binary: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
}

fn cache_dir() -> Option<PathBuf> {
    ProjectDirs::from("dev", "naptrace", "naptrace").map(|d| d.cache_dir().to_path_buf())
}
