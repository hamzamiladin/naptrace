use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::info;

use crate::{joern_cache_dir, JOERN_VERSION};

/// URL pattern for Joern releases.
fn joern_download_url() -> String {
    format!(
        "https://github.com/joernio/joern/releases/download/v{ver}/joern-cli.zip",
        ver = JOERN_VERSION
    )
}

/// Known Homebrew Java paths to check on macOS.
const HOMEBREW_JAVA_PATHS: &[&str] = &[
    "/opt/homebrew/opt/openjdk@21/bin",
    "/opt/homebrew/opt/openjdk/bin",
    "/usr/local/opt/openjdk@21/bin",
    "/usr/local/opt/openjdk/bin",
];

/// Check if Java is available on the system.
/// Also checks common Homebrew locations on macOS.
pub fn java_available() -> bool {
    // Check PATH first
    if std::process::Command::new("java")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }

    // Check Homebrew locations
    for brew_path in HOMEBREW_JAVA_PATHS {
        let java = format!("{brew_path}/java");
        if std::path::Path::new(&java).exists() {
            // Add to PATH for this process
            add_to_path(brew_path);
            return true;
        }
    }

    false
}

/// Add a directory to the current process's PATH.
fn add_to_path(dir: &str) {
    if let Ok(current) = std::env::var("PATH") {
        std::env::set_var("PATH", format!("{dir}:{current}"));
    } else {
        std::env::set_var("PATH", dir);
    }
}

/// Attempt to auto-install Java via the platform package manager.
pub fn auto_install_java() -> Result<()> {
    if java_available() {
        return Ok(());
    }

    info!("Java not found — attempting auto-install...");

    #[cfg(target_os = "macos")]
    {
        // Try Homebrew first
        if which_exists("brew") {
            info!("installing Java via Homebrew...");
            let status = std::process::Command::new("brew")
                .args(["install", "openjdk@21"])
                .status()
                .context("failed to run brew install")?;

            if status.success() {
                // Add Homebrew Java to PATH for this process
                for brew_path in HOMEBREW_JAVA_PATHS {
                    let java = format!("{brew_path}/java");
                    if std::path::Path::new(&java).exists() {
                        add_to_path(brew_path);
                        break;
                    }
                }
                info!("Java 21 installed via Homebrew");
                return Ok(());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Try apt
        if which_exists("apt-get") {
            info!("installing Java via apt...");
            let status = std::process::Command::new("sudo")
                .args(["apt-get", "install", "-y", "openjdk-21-jre-headless"])
                .status()
                .context("failed to run apt-get install")?;
            if status.success() {
                info!("Java 21 installed via apt");
                return Ok(());
            }
        }

        // Try dnf/yum
        if which_exists("dnf") {
            info!("installing Java via dnf...");
            let status = std::process::Command::new("sudo")
                .args(["dnf", "install", "-y", "java-21-openjdk-headless"])
                .status()
                .context("failed to run dnf install")?;
            if status.success() {
                info!("Java 21 installed via dnf");
                return Ok(());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Try winget (Windows 10+)
        if which_exists("winget") {
            info!("installing Java via winget...");
            let status = std::process::Command::new("winget")
                .args([
                    "install",
                    "--id",
                    "EclipseAdoptium.Temurin.21.JRE",
                    "-e",
                    "--silent",
                ])
                .status()
                .context("failed to run winget install")?;
            if status.success() {
                info!("Java 21 installed via winget");
                return Ok(());
            }
        }

        // Try chocolatey
        if which_exists("choco") {
            info!("installing Java via chocolatey...");
            let status = std::process::Command::new("choco")
                .args(["install", "temurin21jre", "-y"])
                .status()
                .context("failed to run choco install")?;
            if status.success() {
                info!("Java 21 installed via chocolatey");
                return Ok(());
            }
        }
    }

    anyhow::bail!(
        "could not auto-install Java.\n\
         please install Java 11+ manually:\n  \
         macOS:   brew install openjdk@21\n  \
         Ubuntu:  sudo apt install openjdk-21-jre-headless\n  \
         Fedora:  sudo dnf install java-21-openjdk-headless\n  \
         Windows: winget install EclipseAdoptium.Temurin.21.JRE"
    )
}

fn which_exists(binary: &str) -> bool {
    let cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    std::process::Command::new(cmd)
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Download and extract Joern CLI if not already present.
/// Also installs Java if missing.
pub async fn ensure_joern() -> Result<PathBuf> {
    if !java_available() {
        auto_install_java().context("Java auto-install failed")?;

        if !java_available() {
            anyhow::bail!("Java installation succeeded but `java` is still not on PATH");
        }
    }

    let cache = joern_cache_dir()?;
    let install_dir = cache.join("joern-cli");
    let marker = cache.join(".naptrace-joern-installed");

    if marker.exists() && install_dir.exists() {
        info!(
            "Joern {} already installed at {}",
            JOERN_VERSION,
            install_dir.display()
        );
        return Ok(install_dir);
    }

    info!("downloading Joern {}...", JOERN_VERSION);

    std::fs::create_dir_all(&cache)
        .with_context(|| format!("failed to create cache dir: {}", cache.display()))?;

    let url = joern_download_url();
    let zip_path = cache.join("joern-cli.zip");

    // Download
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;
    let resp = client
        .get(&url)
        .header("User-Agent", "naptrace")
        .send()
        .await
        .with_context(|| format!("failed to download Joern from {url}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("Joern download returned {}: {url}", resp.status());
    }

    let bytes = resp
        .bytes()
        .await
        .context("failed to read Joern download")?;

    std::fs::write(&zip_path, &bytes)
        .with_context(|| format!("failed to write zip to {}", zip_path.display()))?;

    info!(
        size_mb = bytes.len() / (1024 * 1024),
        "downloaded Joern zip"
    );

    // Extract zip (cross-platform)
    let status = if cfg!(target_os = "windows") {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Force -Path '{}' -DestinationPath '{}'",
                    zip_path.display(),
                    cache.display()
                ),
            ])
            .status()
            .context("failed to extract Joern zip with PowerShell")?
    } else {
        std::process::Command::new("unzip")
            .args(["-o", "-q", &zip_path.to_string_lossy()])
            .current_dir(&cache)
            .status()
            .context("failed to extract Joern zip")?
    };

    if !status.success() {
        anyhow::bail!("zip extraction failed with status {status}");
    }

    // Clean up zip
    let _ = std::fs::remove_file(&zip_path);

    // Write marker
    std::fs::write(&marker, JOERN_VERSION).context("failed to write install marker")?;

    info!(
        "Joern {} installed to {}",
        JOERN_VERSION,
        install_dir.display()
    );
    Ok(install_dir)
}

/// Check if Joern is available (either our managed install or system-wide).
pub fn joern_status() -> JoernStatus {
    if crate::is_joern_installed() {
        return JoernStatus::Managed(
            crate::joern_bin_path()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        );
    }

    // Check system PATH
    if let Ok(output) = std::process::Command::new("which").arg("joern").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return JoernStatus::System(path);
        }
    }

    if !java_available() {
        return JoernStatus::MissingJava;
    }

    JoernStatus::NotInstalled
}

#[derive(Debug)]
pub enum JoernStatus {
    /// Managed by naptrace in the cache dir.
    Managed(String),
    /// Found on system PATH.
    System(String),
    /// Not installed but Java is available — can auto-download.
    NotInstalled,
    /// Java is not available — cannot use Joern at all.
    MissingJava,
}

impl std::fmt::Display for JoernStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Managed(path) => write!(f, "managed install at {path}"),
            Self::System(path) => write!(f, "system install at {path}"),
            Self::NotInstalled => write!(f, "not installed (will auto-download on first use)"),
            Self::MissingJava => write!(f, "unavailable (Java not found)"),
        }
    }
}
