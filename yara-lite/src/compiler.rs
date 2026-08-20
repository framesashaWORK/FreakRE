//! Compiler: transforms parsed AST into a scannable form.
//!
//! For text patterns we build an Aho-Corasick automaton for fast multi-pattern
//! matching. Hex patterns with wildcards are compiled into a custom matcher
//! since AC doesn't support wildcards.

use crate::ast::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use std::collections::HashMap;

/// A compiled rule ready for scanning.
#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub tags: Vec<String>,
    pub condition: Condition,
    /// Text patterns indexed by string identifier.
    pub text_patterns: HashMap<String, CompiledTextPattern>,
    /// Hex patterns indexed by string identifier.
    pub hex_patterns: HashMap<String, CompiledHexPattern>,
    /// Regex patterns indexed by string identifier.
    pub regex_patterns: HashMap<String, CompiledRegexPattern>,
}

#[derive(Debug)]
pub struct CompiledTextPattern {
    pub identifier: String,
    pub modifiers: Modifiers,
    /// The byte sequences to search for (expanded for nocase/wide).
    pub variants: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct CompiledHexPattern {
    pub identifier: String,
    pub tokens: Vec<HexToken>,
    /// Minimum literal prefix length for quick rejection.
    pub min_literal_len: usize,
}

#[derive(Debug)]
pub struct CompiledRegexPattern {
    pub identifier: String,
    pub modifiers: Modifiers,
    pub regex: Regex,
}

/// Errors during compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid regex for '{0}': {1}")]
    InvalidRegex(String, String),
    #[error("no patterns defined in rule '{0}'")]
    NoPatterns(String),
}

/// Compile a single parsed rule.
pub fn compile_rule(rule: &Rule) -> Result<CompiledRule, CompileError> {
    let mut text_patterns = HashMap::new();
    let mut hex_patterns = HashMap::new();
    let mut regex_patterns = HashMap::new();

    for sdef in &rule.strings {
        match &sdef.pattern {
            Pattern::Text(tp) if tp.is_regex => {
                let flags = if sdef.modifiers.nocase { "(?i)" } else { "" };
                let pattern_str = format!("(?-u){}{}", flags, tp.value);
                let regex = Regex::new(&pattern_str).map_err(|e| {
                    CompileError::InvalidRegex(sdef.identifier.clone(), e.to_string())
                })?;
                regex_patterns.insert(
                    sdef.identifier.clone(),
                    CompiledRegexPattern {
                        identifier: sdef.identifier.clone(),
                        modifiers: sdef.modifiers.clone(),
                        regex,
                    },
                );
            }
            Pattern::Text(tp) => {
                let variants = expand_text_variants(&tp.value, &sdef.modifiers);
                text_patterns.insert(
                    sdef.identifier.clone(),
                    CompiledTextPattern {
                        identifier: sdef.identifier.clone(),
                        modifiers: sdef.modifiers.clone(),
                        variants,
                    },
                );
            }
            Pattern::Hex(hp) => {
                let min_literal_len = hp
                    .tokens
                    .iter()
                    .take_while(|t| matches!(t, HexToken::Literal(_)))
                    .count();
                hex_patterns.insert(
                    sdef.identifier.clone(),
                    CompiledHexPattern {
                        identifier: sdef.identifier.clone(),
                        tokens: hp.tokens.clone(),
                        min_literal_len,
                    },
                );
            }
        }
    }

    Ok(CompiledRule {
        name: rule.name.clone(),
        tags: rule.tags.clone(),
        condition: rule.condition.clone(),
        text_patterns,
        hex_patterns,
        regex_patterns,
    })
}

/// Expand a text pattern into byte-sequence variants based on modifiers.
fn expand_text_variants(text: &str, mods: &Modifiers) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();

    if mods.ascii || (!mods.wide && !mods.ascii) {
        if mods.nocase {
            // For nocase ASCII, we generate lowercase variant and rely on
            // case-insensitive scanning at match time. Store lowercase.
            variants.push(text.to_ascii_lowercase().into_bytes());
        } else {
            variants.push(text.as_bytes().to_vec());
        }
    }

    if mods.wide {
        let wide: Vec<u8> = if mods.nocase {
            text.to_ascii_lowercase()
                .chars()
                .flat_map(|c| {
                    let b = c as u16;
                    [(b & 0xFF) as u8, ((b >> 8) & 0xFF) as u8]
                })
                .collect()
        } else {
            text.chars()
                .flat_map(|c| {
                    let b = c as u16;
                    [(b & 0xFF) as u8, ((b >> 8) & 0xFF) as u8]
                })
                .collect()
        };
        variants.push(wide);
    }

    variants
}

/// Build an Aho-Corasick automaton from all text patterns across multiple rules.
/// Returns the AC automaton and a mapping from pattern index → (rule_name, string_id).
pub fn build_ac_automaton(
    rules: &[CompiledRule],
) -> (AhoCorasick, Vec<(String, String)>) {
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut index_map: Vec<(String, String)> = Vec::new();

    for rule in rules {
        for (id, tp) in &rule.text_patterns {
            for variant in &tp.variants {
                patterns.push(variant.clone());
                index_map.push((rule.name.clone(), id.clone()));
            }
        }
    }

    // Handle empty pattern set gracefully (rules with only hex/regex patterns)
    if patterns.is_empty() {
        // Build a dummy AC that matches nothing
        let ac = AhoCorasickBuilder::new()
            .build(&[b"__IMPOSSIBLE_PATTERN_NEVER_MATCH__"])
            .expect("failed to build dummy Aho-Corasick automaton");
        return (ac, index_map);
    }

    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(false) // We handle case ourselves via variants
        .build(&patterns)
        .expect("failed to build Aho-Corasick automaton");

    (ac, index_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn test_compile_simple_rule() {
        let input = r#"
        rule test {
            strings:
                $s = "hello" ascii
                $h = { 4D 5A ?? 90 }
            condition:
                all of them
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.text_patterns.len(), 1);
        assert_eq!(compiled.hex_patterns.len(), 1);
        assert_eq!(compiled.hex_patterns["$h"].min_literal_len, 2);
    }

    #[test]
    fn test_expand_nocase_variants() {
        let mods = Modifiers {
            nocase: true,
            ascii: true,
            ..Default::default()
        };
        let vars = expand_text_variants("Hello", &mods);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], b"hello");
    }

    #[test]
    fn test_expand_wide_variants() {
        let mods = Modifiers {
            wide: true,
            ascii: false,
            ..Default::default()
        };
        let vars = expand_text_variants("AB", &mods);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], vec![0x41, 0x00, 0x42, 0x00]);
    }
}
