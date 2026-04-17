use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use crate::{cpg_cache_dir, joern_bin_path, joern_parse_bin_path};

/// A data-flow path extracted from the CPG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpgPath {
    /// Source nodes where data enters (function params, external calls, etc.)
    pub sources: Vec<CpgNode>,
    /// The sink node (the candidate site).
    pub sink: CpgNode,
    /// Intermediate nodes on the path.
    pub path_nodes: Vec<CpgNode>,
    /// Sanitizers/checks found along the path.
    pub sanitizers: Vec<String>,
    /// Symbolic constraints collected on the path.
    pub constraints: Vec<String>,
}

/// A node in the CPG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpgNode {
    pub file: String,
    pub line: u32,
    pub code: String,
    pub node_type: String,
}

/// Build a CPG for the given source directory.
/// Returns the path to the generated CPG file.
pub fn build_cpg(source_dir: &Path, language: &str) -> Result<PathBuf> {
    let joern_parse = joern_parse_bin_path()?;

    if !joern_parse.exists() {
        anyhow::bail!(
            "joern-parse not found at {}. Run `naptrace doctor` to check.",
            joern_parse.display()
        );
    }

    let cache = cpg_cache_dir()?;
    std::fs::create_dir_all(&cache)
        .with_context(|| format!("failed to create CPG cache dir: {}", cache.display()))?;

    // Use a hash of the source dir path as the CPG filename
    let dir_hash = hash_path(source_dir);
    let cpg_path = cache.join(format!("{dir_hash}.cpg"));

    if cpg_path.exists() {
        info!(cpg = %cpg_path.display(), "using cached CPG");
        return Ok(cpg_path);
    }

    info!(
        source = %source_dir.display(),
        language,
        "building CPG with joern-parse"
    );

    let status = std::process::Command::new(&joern_parse)
        .arg(source_dir.to_str().unwrap_or("."))
        .args(["--output", cpg_path.to_str().unwrap_or("out.cpg")])
        .args(["--language", language])
        .status()
        .with_context(|| format!("failed to run joern-parse at {}", joern_parse.display()))?;

    if !status.success() {
        anyhow::bail!("joern-parse failed with status {status}");
    }

    info!(cpg = %cpg_path.display(), "CPG built");
    Ok(cpg_path)
}

/// Query the CPG to extract data-flow paths reaching a specific function.
pub fn query_paths(
    cpg_path: &Path,
    function_name: &str,
    file_path: &str,
    start_line: u32,
) -> Result<Vec<CpgPath>> {
    let joern = joern_bin_path()?;

    if !joern.exists() {
        anyhow::bail!(
            "joern not found at {}. Run `naptrace doctor` to check.",
            joern.display()
        );
    }

    // Build a Joern script that:
    // 1. Loads the CPG
    // 2. Finds the target function
    // 3. Extracts data-flow paths reaching it
    // 4. Outputs JSON
    let script = build_query_script(cpg_path, function_name, file_path, start_line);

    let temp_script =
        tempfile::NamedTempFile::new().context("failed to create temp script file")?;
    std::fs::write(temp_script.path(), &script).context("failed to write Joern query script")?;

    debug!(
        function = function_name,
        file = file_path,
        "querying CPG for data-flow paths"
    );

    let output = std::process::Command::new(&joern)
        .args(["--script", temp_script.path().to_str().unwrap_or("")])
        .output()
        .with_context(|| format!("failed to run joern at {}", joern.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!(stderr = %stderr, "joern query failed");
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_query_output(&stdout)
}

/// Build a Joern Scala script to extract dataflow paths for a function.
fn build_query_script(
    cpg_path: &Path,
    function_name: &str,
    file_path: &str,
    start_line: u32,
) -> String {
    let cpg_escaped = cpg_path.display().to_string().replace('\\', "\\\\");
    format!(
        r#"
import io.shiftleft.semanticcpg.language._

// Load CPG and apply dataflow overlay
importCpg("{cpg_escaped}")

try {{
  run.ossdataflow
}} catch {{
  case _: Throwable => // dataflow overlay may already be applied
}}

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.{{EngineContext, EngineConfig}}
implicit val engineContext: EngineContext = EngineContext(EngineConfig(maxCallDepth = 4))

// Find the target method
val targetMethods = cpg.method.nameExact("{function_name}")
  .where(_.filename(".*{file_path}.*"))
  .l

val results = targetMethods.flatMap {{ method =>
  // --- Dataflow analysis ---
  val sources = method.parameter
  val sinks = method.call.argument

  val flows = try {{
    sinks.reachableByFlows(sources).l
  }} catch {{
    case _: Throwable => List()
  }}

  val flowNodes = flows.flatMap {{ flow =>
    flow.elements.l.map {{ elem =>
      s"""{{"file":"${{elem.file.name.headOption.getOrElse("")}}","line":${{elem.lineNumber.getOrElse(0)}},"code":"${{elem.code.take(100).replace("\"", "\\\"").replace("\n", " ")}}","node_type":"dataflow"}}"""
    }}
  }}.distinct

  // --- Structural fallback ---
  val params = method.parameter.l.map {{ p =>
    s"""{{"file":"${{p.filename}}","line":${{p.lineNumber.getOrElse(0)}},"code":"${{p.code.replace("\"", "\\\"")}}","node_type":"parameter"}}"""
  }}

  val callers = method.callIn.l.take(5).map {{ c =>
    s"""{{"file":"${{c.filename}}","line":${{c.lineNumber.getOrElse(0)}},"code":"${{c.code.take(100).replace("\"", "\\\"")}}","node_type":"call_site"}}"""
  }}

  // Sanitizer detection
  val conditions = method.ifBlock.condition.l.map(_.code.take(100))
  val sanitizers = conditions.filter(c =>
    c.contains(">=") || c.contains("<=") || c.contains("NULL") ||
    c.contains("overflow") || c.contains("check") || c.contains("MAX") ||
    c.contains("MIN") || c.contains("bound") || c.contains("assert")
  )

  // Type constraints
  val constraints = method.parameter.l.flatMap {{ p =>
    p.typeFullName.headOption.map(t => s"param ${{p.name}} : $t")
  }} ++ conditions.map(c => s"branch: $c")

  val allConstraints = constraints.map(c =>
    s"\"${{c.take(120).replace("\"", "\\\"").replace("\n", " ")}}\""
  )

  val pathNodes = if (flowNodes.nonEmpty) flowNodes else (callers ++ params)

  List(s"""{{
    "sources": [${{params.mkString(",")}}],
    "sink": {{"file":"${{method.filename}}","line":{start_line},"code":"${{method.name}}","node_type":"function"}},
    "path_nodes": [${{pathNodes.mkString(",")}}],
    "sanitizers": [${{sanitizers.map(s => s"\"${{s.replace("\"", "\\\"")}}\"").mkString(",")}}],
    "constraints": [${{allConstraints.mkString(",")}}]
  }}"#,
        cpg_escaped = cpg_escaped,
        function_name = function_name.replace('"', r#"\""#),
        file_path = file_path.replace('"', r#"\""#),
        start_line = start_line,
    ) + r#"
  )
}}

println("[" + results.mkString(",") + "]")
"#
}

/// Parse the JSON output from a Joern query.
fn parse_query_output(output: &str) -> Result<Vec<CpgPath>> {
    // Find the JSON array in the output (skip Joern startup messages)
    let json_start = output.find('[');
    let json_end = output.rfind(']');

    match (json_start, json_end) {
        (Some(start), Some(end)) if end > start => {
            let json = &output[start..=end];
            let paths: Vec<CpgPath> = serde_json::from_str(json).unwrap_or_default();
            Ok(paths)
        }
        _ => {
            debug!(output_len = output.len(), "no JSON found in Joern output");
            Ok(Vec::new())
        }
    }
}

fn hash_path(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}
