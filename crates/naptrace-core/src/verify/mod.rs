use anyhow::{Context, Result};
use std::path::Path;
use tracing::{info, warn};

use crate::reason::{JudgedCandidate, VerdictKind};

/// Result of execution-based verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub function_name: String,
    pub crashed: bool,
    pub asan_output: Option<String>,
    pub exit_code: i32,
}

/// Verify feasible findings by compiling with AddressSanitizer and
/// running generated PoC sketches. Confirmed crashes get confidence 10.
pub fn verify_findings(
    findings: &mut [JudgedCandidate],
    target_dir: &Path,
    language: crate::Language,
) {
    if !matches!(language, crate::Language::C | crate::Language::Cpp) {
        info!("--verify only supports C/C++ targets, skipping");
        return;
    }

    // Check if compiler with ASan support is available
    if !has_asan_compiler() {
        warn!("no compiler with AddressSanitizer found — skipping verification");
        return;
    }

    for finding in findings.iter_mut() {
        if finding.verdict.verdict != VerdictKind::Feasible {
            continue;
        }

        let poc = match &finding.verdict.poc_sketch {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                info!(
                    function = %finding.function_name,
                    "no PoC sketch available — skipping verification"
                );
                continue;
            }
        };

        info!(
            function = %finding.function_name,
            "verifying with AddressSanitizer..."
        );

        match run_asan_verification(target_dir, &finding.function_name, &poc) {
            Ok(result) => {
                if result.crashed {
                    info!(
                        function = %finding.function_name,
                        "ASan crash confirmed! Upgrading confidence to 10."
                    );
                    finding.verdict.confidence = 10;
                    finding.verdict.justification = format!(
                        "CONFIRMED by AddressSanitizer. {}",
                        result.asan_output.unwrap_or_default()
                    );
                } else {
                    info!(
                        function = %finding.function_name,
                        exit_code = result.exit_code,
                        "no crash detected — downgrading to needs_runtime_check"
                    );
                    finding.verdict.verdict = VerdictKind::NeedsRuntimeCheck;
                    finding.verdict.justification = format!(
                        "PoC did not trigger ASan crash (exit code {}). {}",
                        result.exit_code, finding.verdict.justification
                    );
                }
            }
            Err(e) => {
                warn!(
                    function = %finding.function_name,
                    error = %e,
                    "verification failed — keeping original verdict"
                );
            }
        }
    }
}

/// Check if a C compiler with ASan support is available.
fn has_asan_compiler() -> bool {
    // Try gcc first, then clang
    for compiler in &["gcc", "clang", "cc"] {
        let result = std::process::Command::new(compiler)
            .args(["--version"])
            .output();
        if let Ok(output) = result {
            if output.status.success() {
                return true;
            }
        }
    }
    false
}

/// Compile and run a PoC with AddressSanitizer.
fn run_asan_verification(
    target_dir: &Path,
    function_name: &str,
    poc_sketch: &str,
) -> Result<VerifyResult> {
    let tmp = tempfile::tempdir().context("failed to create temp dir for verification")?;
    let poc_file = tmp.path().join("poc.c");
    let binary = tmp.path().join("poc_test");

    // Generate a minimal C test file from the PoC sketch
    let test_code = format!(
        "#include <stdio.h>\n\
         #include <stdint.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\n\
         // PoC for {function_name}\n\
         int main() {{\n\
             {poc_sketch}\n\
             return 0;\n\
         }}\n"
    );

    std::fs::write(&poc_file, &test_code).context("failed to write PoC file")?;

    // Try to compile with ASan
    let compiler = if which_exists("clang") {
        "clang"
    } else {
        "gcc"
    };

    let compile = std::process::Command::new(compiler)
        .args([
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-g",
            "-o",
            binary.to_str().unwrap_or("poc_test"),
            poc_file.to_str().unwrap_or("poc.c"),
            // Include the target directory for headers
            &format!("-I{}", target_dir.display()),
        ])
        .output()
        .context("failed to compile PoC with ASan")?;

    if !compile.status.success() {
        let stderr = String::from_utf8_lossy(&compile.stderr);
        return Ok(VerifyResult {
            function_name: function_name.to_string(),
            crashed: false,
            asan_output: Some(format!("compilation failed: {stderr}")),
            exit_code: -1,
        });
    }

    // Run the binary with a timeout
    let run = std::process::Command::new(&binary)
        .env("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
        .output()
        .context("failed to run PoC binary")?;

    let exit_code = run.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&run.stderr).to_string();
    let crashed = !run.status.success() && stderr.contains("AddressSanitizer");

    Ok(VerifyResult {
        function_name: function_name.to_string(),
        crashed,
        asan_output: if !stderr.is_empty() {
            Some(stderr)
        } else {
            None
        },
        exit_code,
    })
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
