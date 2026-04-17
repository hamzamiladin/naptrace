use anyhow::{Context, Result};
use std::path::Path;
use tracing::debug;
use walkdir::WalkDir;

use crate::Language;

/// A function extracted from a source file.
#[derive(Debug, Clone)]
pub struct ExtractedFunction {
    /// File path relative to the target root.
    pub file_path: String,
    /// Function name.
    pub name: String,
    /// Full function body (including signature).
    pub body: String,
    /// Start line (1-indexed).
    pub start_line: u32,
    /// End line (1-indexed).
    pub end_line: u32,
    /// Language of the source file.
    pub language: Language,
}

/// Extract all functions from a target directory for the given languages.
pub fn extract_functions(
    target_dir: &Path,
    languages: &[Language],
) -> Result<Vec<ExtractedFunction>> {
    let mut functions = Vec::new();

    for entry in WalkDir::new(target_dir)
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| !is_hidden_or_vendor(e))
    {
        let entry = entry.context("failed to read directory entry")?;
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let lang = match Language::from_path(&path.to_string_lossy()) {
            Some(l) if languages.is_empty() || languages.contains(&l) => l,
            _ => continue,
        };

        let relative = path
            .strip_prefix(target_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        match extract_from_file(path, &relative, lang) {
            Ok(fns) => {
                debug!(file = %relative, count = fns.len(), "extracted functions");
                functions.extend(fns);
            }
            Err(e) => {
                debug!(file = %relative, error = %e, "skipping file");
            }
        }
    }

    Ok(functions)
}

/// Extract functions from a single source file using tree-sitter.
fn extract_from_file(
    path: &Path,
    relative_path: &str,
    lang: Language,
) -> Result<Vec<ExtractedFunction>> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut parser = tree_sitter::Parser::new();
    let ts_lang = get_tree_sitter_language(lang)?;
    parser
        .set_language(&ts_lang)
        .context("failed to set tree-sitter language")?;

    let tree = parser
        .parse(&source, None)
        .context("tree-sitter parse failed")?;

    let function_kinds = function_node_kinds(lang);
    let mut functions = Vec::new();

    collect_functions(
        tree.root_node(),
        &source,
        relative_path,
        lang,
        &function_kinds,
        &mut functions,
    );

    Ok(functions)
}

/// Recursively collect function nodes from the AST.
fn collect_functions(
    node: tree_sitter::Node,
    source: &str,
    file_path: &str,
    lang: Language,
    function_kinds: &[&str],
    out: &mut Vec<ExtractedFunction>,
) {
    if function_kinds.contains(&node.kind()) {
        if let Some(func) = node_to_function(node, source, file_path, lang) {
            out.push(func);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, file_path, lang, function_kinds, out);
    }
}

/// Convert a tree-sitter function node to an ExtractedFunction.
fn node_to_function(
    node: tree_sitter::Node,
    source: &str,
    file_path: &str,
    lang: Language,
) -> Option<ExtractedFunction> {
    let body = node.utf8_text(source.as_bytes()).ok()?.to_string();

    // Skip very small functions (one-liners, empty stubs)
    if body.lines().count() < 3 {
        return None;
    }

    let name =
        extract_function_name(node, source, lang).unwrap_or_else(|| "<anonymous>".to_string());

    let start_line = node.start_position().row as u32 + 1;
    let end_line = node.end_position().row as u32 + 1;

    Some(ExtractedFunction {
        file_path: file_path.to_string(),
        name,
        body,
        start_line,
        end_line,
        language: lang,
    })
}

/// Extract the function name from a tree-sitter node.
fn extract_function_name(node: tree_sitter::Node, source: &str, lang: Language) -> Option<String> {
    let name_field = match lang {
        Language::C | Language::Cpp => "declarator",
        Language::Python => "name",
        Language::Java => "name",
        Language::Javascript | Language::Typescript => "name",
        Language::Go => "name",
        Language::Rust => "name",
    };

    let child = node.child_by_field_name(name_field)?;

    // For C/C++, the declarator may be nested (e.g., pointer_declarator -> function_declarator)
    let name_node = find_identifier(child);
    name_node
        .utf8_text(source.as_bytes())
        .ok()
        .map(|s| s.to_string())
}

/// Find the deepest identifier node in a declarator chain.
fn find_identifier(node: tree_sitter::Node) -> tree_sitter::Node {
    if node.kind() == "identifier" || node.kind() == "field_identifier" {
        return node;
    }

    // Check named children for identifier
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "field_identifier" {
            return child;
        }
    }

    // Recurse into declarator children
    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if child.kind().contains("declarator") || child.kind() == "name" {
            return find_identifier(child);
        }
    }

    node
}

/// Get the tree-sitter node kinds that represent function definitions.
fn function_node_kinds(lang: Language) -> Vec<&'static str> {
    match lang {
        Language::C => vec!["function_definition"],
        Language::Cpp => vec!["function_definition"],
        Language::Python => vec!["function_definition"],
        Language::Java => vec!["method_declaration", "constructor_declaration"],
        Language::Javascript => vec![
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        Language::Typescript => vec![
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        Language::Go => vec!["function_declaration", "method_declaration"],
        Language::Rust => vec!["function_item"],
    }
}

/// Get the tree-sitter Language for a given language.
fn get_tree_sitter_language(lang: Language) -> Result<tree_sitter::Language> {
    let ts_lang = match lang {
        Language::C => tree_sitter_c::LANGUAGE,
        Language::Cpp => tree_sitter_cpp::LANGUAGE,
        Language::Python => tree_sitter_python::LANGUAGE,
        Language::Java => tree_sitter_java::LANGUAGE,
        Language::Javascript => tree_sitter_javascript::LANGUAGE,
        Language::Typescript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        Language::Go => tree_sitter_go::LANGUAGE,
        Language::Rust => tree_sitter_rust::LANGUAGE,
    };
    Ok(ts_lang.into())
}

/// Check if a directory entry is hidden or a common vendor/build directory.
/// Skips the check for depth 0 (the root dir itself).
fn is_hidden_or_vendor(entry: &walkdir::DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    name.starts_with('.')
        || name == "node_modules"
        || name == "vendor"
        || name == "target"
        || name == "build"
        || name == "dist"
        || name == "__pycache__"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_c_functions_direct() {
        let source = r#"#include <stdio.h>

int add(int a, int b) {
    int result = a + b;
    return result;
}

void greet(const char *name) {
    printf("Hello, %s\n", name);
    return;
}

int main() {
    greet("world");
    return add(1, 2);
}
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.c");
        std::fs::write(&file, source).unwrap();

        // Test direct file extraction
        let funcs = extract_from_file(&file, "test.c", Language::C).unwrap();
        assert_eq!(funcs.len(), 3);

        // Then test directory walk
        let functions = extract_functions(dir.path(), &[Language::C]).unwrap();
        assert!(
            functions.len() >= 2,
            "directory walk should find at least 2 functions, got {}",
            functions.len()
        );
    }

    #[test]
    fn extract_python_functions() {
        let source = r#"
def hello(name):
    print(f"Hello, {name}")
    return name

def add(a, b):
    result = a + b
    return result
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.py");
        std::fs::write(&file, source).unwrap();

        let functions = extract_functions(dir.path(), &[Language::Python]).unwrap();
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn skips_hidden_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join(".hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(
            hidden.join("test.c"),
            "int foo() { return 1; \n return 2; \n return 3; }",
        )
        .unwrap();

        let functions = extract_functions(dir.path(), &[]).unwrap();
        assert_eq!(functions.len(), 0);
    }
}
