use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Metadata from the YAML frontmatter of a prompt template.
#[derive(Debug, Clone, Deserialize)]
pub struct PromptMeta {
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub schema: String,
}

/// A loaded prompt template with metadata and body.
#[derive(Debug, Clone)]
pub struct PromptTemplate {
    pub meta: PromptMeta,
    pub body: String,
}

impl PromptTemplate {
    /// Load a prompt template from a file.
    /// The file must have YAML frontmatter delimited by `---`.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read prompt template: {}", path.display()))?;
        Self::parse(&content)
    }

    /// Parse a prompt template from a string.
    pub fn parse(content: &str) -> Result<Self> {
        let content = content.trim();

        // Strip leading `---` and find the closing `---`
        let without_leading = content
            .strip_prefix("---")
            .context("prompt template must start with ---")?;

        let (yaml_str, body) = without_leading
            .split_once("---")
            .context("prompt template must have closing --- after frontmatter")?;

        // Parse the frontmatter — it's wrapped in a `meta:` key
        let wrapper: FrontmatterWrapper = serde_yaml::from_str(yaml_str.trim())
            .context("failed to parse prompt frontmatter")?;

        Ok(Self {
            meta: wrapper.meta,
            body: body.trim().to_string(),
        })
    }

    /// Build the final prompt by appending context variables.
    pub fn render(&self, variables: &[(&str, &str)]) -> String {
        let mut result = self.body.clone();
        for (key, value) in variables {
            let placeholder = format!("{{{{{key}}}}}");
            result = result.replace(&placeholder, value);
        }
        result
    }
}

#[derive(Deserialize)]
struct FrontmatterWrapper {
    meta: PromptMeta,
}

/// Find the prompts directory relative to the workspace root.
/// Searches upward from the current directory for a `prompts/` folder.
pub fn find_prompts_dir() -> Result<std::path::PathBuf> {
    let mut dir = std::env::current_dir().context("failed to get current directory")?;

    loop {
        let prompts = dir.join("prompts");
        if prompts.is_dir() {
            return Ok(prompts);
        }

        if !dir.pop() {
            break;
        }
    }

    // Fallback: check next to the binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let prompts = parent.join("prompts");
            if prompts.is_dir() {
                return Ok(prompts);
            }
        }
    }

    anyhow::bail!("could not find prompts/ directory — run from the naptrace workspace root")
}

/// Load a specific prompt template by name (without extension).
pub fn load_prompt(name: &str) -> Result<PromptTemplate> {
    let dir = find_prompts_dir()?;
    let path = dir.join(format!("{name}.md"));
    PromptTemplate::load(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TEMPLATE: &str = r#"---
meta:
  model: claude-opus-4-7
  temperature: 0.3
  max_tokens: 1024
  schema: test_v1
---

# Test Prompt

You are a test assistant.

Input: {{input}}
Output: JSON
"#;

    #[test]
    fn parse_template() {
        let tmpl = PromptTemplate::parse(SAMPLE_TEMPLATE).unwrap();
        assert_eq!(tmpl.meta.model, "claude-opus-4-7");
        assert_eq!(tmpl.meta.temperature, 0.3);
        assert_eq!(tmpl.meta.max_tokens, 1024);
        assert_eq!(tmpl.meta.schema, "test_v1");
        assert!(tmpl.body.contains("# Test Prompt"));
    }

    #[test]
    fn render_variables() {
        let tmpl = PromptTemplate::parse(SAMPLE_TEMPLATE).unwrap();
        let rendered = tmpl.render(&[("input", "hello world")]);
        assert!(rendered.contains("Input: hello world"));
        assert!(!rendered.contains("{{input}}"));
    }

    #[test]
    fn load_real_distill_template() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("prompts");

        let path = dir.join("distill_signature.md");
        if path.exists() {
            let tmpl = PromptTemplate::load(&path).unwrap();
            assert_eq!(tmpl.meta.model, "claude-opus-4-7");
            assert!(tmpl.body.contains("Vulnerability Signature Distillation"));
        }
    }
}
