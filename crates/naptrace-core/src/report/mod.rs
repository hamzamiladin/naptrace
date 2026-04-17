use serde::{Deserialize, Serialize};

use crate::reason::{JudgedCandidate, VerdictKind};

/// SARIF 2.1.0 output for CI integration.
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub properties: SarifProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "endLine")]
    pub end_line: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifProperties {
    pub verdict: String,
    pub confidence: u8,
    pub similarity: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc_sketch: Option<String>,
}

/// Generate a SARIF 2.1.0 report from judged candidates.
pub fn generate_sarif(findings: &[JudgedCandidate], cve_id: Option<&str>) -> SarifReport {
    let results: Vec<SarifResult> = findings
        .iter()
        .filter(|f| f.verdict.verdict != VerdictKind::Infeasible)
        .map(|f| {
            let rule_id = cve_id
                .map(|c| format!("naptrace/variant/{c}"))
                .unwrap_or_else(|| "naptrace/variant".to_string());

            let level = match f.verdict.verdict {
                VerdictKind::Feasible => "error",
                VerdictKind::NeedsRuntimeCheck => "warning",
                VerdictKind::Infeasible => "note",
            };

            SarifResult {
                rule_id,
                level: level.to_string(),
                message: SarifMessage {
                    text: format!(
                        "{} in {}() at {}:{} — {}",
                        f.verdict.verdict,
                        f.function_name,
                        f.file_path,
                        f.start_line,
                        f.verdict.justification,
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.file_path.clone(),
                        },
                        region: SarifRegion {
                            start_line: f.start_line,
                            end_line: f.end_line,
                        },
                    },
                }],
                properties: SarifProperties {
                    verdict: f.verdict.verdict.to_string(),
                    confidence: f.verdict.confidence,
                    similarity: f.similarity,
                    poc_sketch: f.verdict.poc_sketch.clone(),
                },
            }
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "naptrace".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/hamzamiladin/naptrace".to_string(),
                },
            },
            results,
        }],
    }
}

/// Summary stats for terminal output.
pub struct ReportSummary {
    pub feasible: usize,
    pub needs_check: usize,
    pub infeasible: usize,
    pub total: usize,
}

pub fn summarize(findings: &[JudgedCandidate]) -> ReportSummary {
    let mut s = ReportSummary {
        feasible: 0,
        needs_check: 0,
        infeasible: 0,
        total: findings.len(),
    };
    for f in findings {
        match f.verdict.verdict {
            VerdictKind::Feasible => s.feasible += 1,
            VerdictKind::NeedsRuntimeCheck => s.needs_check += 1,
            VerdictKind::Infeasible => s.infeasible += 1,
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::Verdict;

    fn make_finding(verdict: VerdictKind, confidence: u8) -> JudgedCandidate {
        JudgedCandidate {
            file_path: "src/test.c".to_string(),
            function_name: "test_func".to_string(),
            start_line: 10,
            end_line: 20,
            similarity: 0.85,
            body: "int test_func() { return 0; }".to_string(),
            verdict: Verdict {
                verdict,
                justification: "test justification".to_string(),
                blocking_sanitizers: vec![],
                reachable_inputs: vec![],
                poc_sketch: None,
                confidence,
            },
        }
    }

    #[test]
    fn sarif_excludes_infeasible() {
        let findings = vec![
            make_finding(VerdictKind::Feasible, 8),
            make_finding(VerdictKind::Infeasible, 9),
            make_finding(VerdictKind::NeedsRuntimeCheck, 5),
        ];
        let report = generate_sarif(&findings, Some("CVE-2025-6965"));
        assert_eq!(report.runs[0].results.len(), 2);
    }

    #[test]
    fn sarif_levels() {
        let findings = vec![
            make_finding(VerdictKind::Feasible, 8),
            make_finding(VerdictKind::NeedsRuntimeCheck, 5),
        ];
        let report = generate_sarif(&findings, None);
        assert_eq!(report.runs[0].results[0].level, "error");
        assert_eq!(report.runs[0].results[1].level, "warning");
    }

    #[test]
    fn summary_counts() {
        let findings = vec![
            make_finding(VerdictKind::Feasible, 8),
            make_finding(VerdictKind::Feasible, 7),
            make_finding(VerdictKind::Infeasible, 9),
            make_finding(VerdictKind::NeedsRuntimeCheck, 4),
        ];
        let s = summarize(&findings);
        assert_eq!(s.feasible, 2);
        assert_eq!(s.infeasible, 1);
        assert_eq!(s.needs_check, 1);
        assert_eq!(s.total, 4);
    }
}
