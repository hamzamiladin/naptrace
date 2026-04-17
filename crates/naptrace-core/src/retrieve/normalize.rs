use crate::Language;

/// Normalize a function body for cross-project comparison.
///
/// Replaces local variable names with generic identifiers (VAR0, VAR1, ...)
/// while preserving function call names, type names, numeric literals,
/// and structural keywords. This makes embeddings naming-independent
/// so the same vulnerability pattern in different projects scores high.
pub fn normalize_function(body: &str, lang: Language) -> String {
    let mut result = String::with_capacity(body.len());
    let mut var_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut var_counter = 0;

    // Keywords and type names to preserve (not rename)
    let preserve_words = get_preserved_words(lang);

    for line in body.lines() {
        let mut normalized_line = String::new();
        let mut chars = line.chars().peekable();

        while let Some(&ch) = chars.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                // Collect the full identifier/number
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        word.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }

                // Decide whether to preserve or normalize
                if word
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    // Numeric literal — preserve
                    normalized_line.push_str(&word);
                } else if preserve_words.contains(&word.as_str())
                    || is_type_name(&word)
                    || is_likely_function_call(&word, &mut chars)
                {
                    // Keyword, type, or function call — preserve
                    normalized_line.push_str(&word);
                } else {
                    // Local variable — normalize
                    let normalized = var_map
                        .entry(word)
                        .or_insert_with(|| {
                            let name = format!("VAR{var_counter}");
                            var_counter += 1;
                            name
                        })
                        .clone();
                    normalized_line.push_str(&normalized);
                }
            } else if ch == '/' && chars.clone().nth(1) == Some('/') {
                // Line comment — skip rest of line
                break;
            } else if ch == '/' && chars.clone().nth(1) == Some('*') {
                // Block comment — skip until */
                chars.next(); // /
                chars.next(); // *
                while let Some(c) = chars.next() {
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                }
            } else {
                normalized_line.push(ch);
                chars.next();
            }
        }

        let trimmed = normalized_line.trim();
        if !trimmed.is_empty() {
            result.push_str(trimmed);
            result.push('\n');
        }
    }

    result
}

fn get_preserved_words(lang: Language) -> Vec<&'static str> {
    match lang {
        Language::C | Language::Cpp => vec![
            "if",
            "else",
            "for",
            "while",
            "do",
            "return",
            "break",
            "continue",
            "switch",
            "case",
            "default",
            "goto",
            "sizeof",
            "typedef",
            "struct",
            "union",
            "enum",
            "const",
            "volatile",
            "static",
            "extern",
            "void",
            "NULL",
            "true",
            "false",
            "inline",
            // Overflow-related — important to preserve
            "INT_MAX",
            "INT_MIN",
            "UINT_MAX",
            "INT64_MAX",
            "INT64_MIN",
            "UINT64_MAX",
            "SIZE_MAX",
            "LONG_MAX",
            "LONG_MIN",
        ],
        Language::Python => vec![
            "if",
            "else",
            "elif",
            "for",
            "while",
            "return",
            "break",
            "continue",
            "def",
            "class",
            "import",
            "from",
            "try",
            "except",
            "finally",
            "raise",
            "with",
            "as",
            "None",
            "True",
            "False",
            "self",
            "pickle",
            "eval",
            "exec",
            "os",
            "subprocess",
        ],
        Language::Java => vec![
            "if",
            "else",
            "for",
            "while",
            "return",
            "break",
            "continue",
            "switch",
            "case",
            "new",
            "this",
            "super",
            "class",
            "interface",
            "extends",
            "implements",
            "null",
            "true",
            "false",
            "void",
            "static",
            "final",
            "try",
            "catch",
            "throw",
            "throws",
            "ObjectInputStream",
            "readObject",
            "Runtime",
            "exec",
            "forName",
        ],
        Language::Go => vec![
            "if", "else", "for", "return", "break", "continue", "switch", "case", "func", "go",
            "defer", "select", "chan", "nil", "true", "false", "range", "make", "len", "cap",
            "append", "panic", "recover",
        ],
        Language::Rust => vec![
            "if", "else", "for", "while", "loop", "return", "break", "continue", "match", "fn",
            "let", "mut", "self", "Self", "impl", "struct", "enum", "trait", "unsafe", "Some",
            "None", "Ok", "Err", "true", "false", "pub", "use",
        ],
        _ => vec![
            "if",
            "else",
            "for",
            "while",
            "return",
            "break",
            "continue",
            "function",
            "var",
            "let",
            "const",
            "null",
            "undefined",
            "true",
            "false",
            "this",
            "new",
        ],
    }
}

fn is_type_name(word: &str) -> bool {
    // Common C/C++ types and type-like identifiers
    word.starts_with("int")
        || word.starts_with("uint")
        || word.starts_with("size_t")
        || word.starts_with("ssize_t")
        || word.starts_with("char")
        || word.starts_with("bool")
        || word.starts_with("float")
        || word.starts_with("double")
        || word.starts_with("long")
        || word.starts_with("short")
        || word.starts_with("unsigned")
        || word.starts_with("signed")
        || word.ends_with("_t")
        || word == "String"
        || word == "str"
}

fn is_likely_function_call(_word: &str, chars: &mut std::iter::Peekable<std::str::Chars>) -> bool {
    // If the next non-space char is '(', it's likely a function call — preserve it
    let mut lookahead = chars.clone();
    while let Some(&c) = lookahead.peek() {
        if c == ' ' || c == '\t' {
            lookahead.next();
        } else {
            return c == '(';
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_c_function() {
        let body = r#"int64_t unsafe_add(int64_t a, int64_t b) {
    int64_t result = a + b;
    return result;
}"#;
        let normalized = normalize_function(body, Language::C);
        // Function name and type names should be preserved
        assert!(normalized.contains("int64_t"));
        // Local variables should be normalized
        assert!(normalized.contains("VAR"));
        // Operators should be preserved
        assert!(normalized.contains("+"));
    }

    #[test]
    fn preserve_function_calls() {
        let body = r#"void foo() {
    malloc(size);
    free(ptr);
}"#;
        let normalized = normalize_function(body, Language::C);
        assert!(normalized.contains("malloc"));
        assert!(normalized.contains("free"));
    }

    #[test]
    fn strip_comments() {
        let body = r#"int x = 1; // this is a comment
/* block comment */
int y = 2;"#;
        let normalized = normalize_function(body, Language::C);
        assert!(!normalized.contains("comment"));
        assert!(!normalized.contains("block"));
    }
}
