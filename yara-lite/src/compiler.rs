//! Compiler: transforms parsed AST into a scannable form.
//!
//! For text patterns we build an Aho-Corasick automaton for fast multi-pattern
//! matching. Hex patterns with wildcards are compiled into a custom matcher
//! since AC doesn't support wildcards.

use crate::ast::*;
use freakre_patterns::{SafeRegex, AcSearcher};
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
    pub regex: SafeRegex,
}

/// Errors during compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid regex for '{0}': {1}")]
    InvalidRegex(String, String),
    #[error("no patterns defined in rule '{0}'")]
    NoPatterns(String),
    #[error("empty string pattern '{0}'")]
    EmptyPattern(String),
    #[error("empty hex pattern '{0}'")]
    EmptyHexPattern(String),
    #[error("unresolved string reference '{0}' in rule '{1}'")]
    UndefinedString(String, String),
}

/// Compile a single parsed rule.
pub fn compile_rule(rule: &Rule) -> Result<CompiledRule, CompileError> {
    let mut text_patterns = HashMap::new();
    let mut hex_patterns = HashMap::new();
    let mut regex_patterns = HashMap::new();

    // Every string identifier defined in this rule; used to reject
    // condition references to strings that were never declared (real YARA
    // fails compilation with "unresolved reference" instead of silently
    // evaluating them as false).
    let defined: std::collections::HashSet<&str> = rule
        .strings
        .iter()
        .map(|s| s.identifier.as_str())
        .collect();
    for id in rule.condition.referenced_strings() {
        if !defined.contains(id) {
            return Err(CompileError::UndefinedString(
                id.to_string(),
                rule.name.clone(),
            ));
        }
    }

    for sdef in &rule.strings {
        match &sdef.pattern {
            Pattern::Text(tp) if tp.is_regex => {
                if tp.value.is_empty() {
                    return Err(CompileError::InvalidRegex(
                        sdef.identifier.clone(),
                        "empty pattern".into(),
                    ));
                }
                let flags = if sdef.modifiers.nocase { "(?i)" } else { "" };
                // Regex values come verbatim from the rule source, so they are
                // always valid UTF-8.
                let pattern_str =
                    format!("(?-u){}{}", flags, String::from_utf8_lossy(&tp.value));
                let regex = SafeRegex::new(&pattern_str).map_err(|e| {
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
                if tp.value.is_empty() {
                    return Err(CompileError::EmptyPattern(sdef.identifier.clone()));
                }
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
                // An empty hex pattern `{}` would match nothing; real YARA
                // rejects it at compile time.
                if hp.tokens.is_empty() {
                    return Err(CompileError::EmptyHexPattern(sdef.identifier.clone()));
                }
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
fn expand_text_variants(text: &[u8], mods: &Modifiers) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();

    if mods.ascii || (!mods.wide && !mods.ascii) {
        variants.push(text.to_vec());
    }

    if mods.wide {
        // Wide = insert a NUL after every pattern byte (raw bytes included).
        let wide: Vec<u8> = text
            .iter()
            .flat_map(|&b| {
                let b = if mods.nocase { b.to_ascii_lowercase() } else { b };
                [b, 0]
            })
            .collect();
        variants.push(wide);
    }

    variants
}

/// Build an Aho-Corasick automaton from text patterns across multiple rules.
///
/// `nocase` selects which patterns are included: when `true`, only `nocase`
/// text patterns are added (with lowercased variants, matched against a
/// lowercased haystack); when `false`, only case-sensitive text patterns are
/// added (original-case variants, matched against the raw haystack).
/// Returns the AC searcher and a mapping from pattern index → (rule_name, string_id).
pub fn build_ac_automaton(
    rules: &[CompiledRule],
    nocase: bool,
) -> Result<(AcSearcher, Vec<(String, String)>), CompileError> {
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut index_map: Vec<(String, String)> = Vec::new();

    for rule in rules {
        for (id, tp) in &rule.text_patterns {
            if tp.modifiers.nocase != nocase {
                continue;
            }
            for variant in &tp.variants {
                if variant.is_empty() {
                    return Err(CompileError::EmptyPattern(format!("{}:{}", rule.name, id)));
                }
                let v = if nocase {
                    variant.iter().map(|b| b.to_ascii_lowercase()).collect()
                } else {
                    variant.clone()
                };
                patterns.push(v);
                index_map.push((rule.name.clone(), id.clone()));
            }
        }
    }

    // Handle empty pattern set gracefully (rules with only hex/regex patterns)
    if patterns.is_empty() {
        let ac = AcSearcher::new(&[b"__IMPOSSIBLE_PATTERN_NEVER_MATCH__".to_vec()])
            .map_err(|e| CompileError::InvalidRegex("<ac>".into(), e.to_string()))?;
        return Ok((ac, index_map));
    }

    let ac = AcSearcher::new(&patterns)
        .map_err(|e| CompileError::InvalidRegex("<ac>".into(), e.to_string()))?;
    Ok((ac, index_map))
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
        // Case folding is now deferred to scan time (lowercased haystack),
        // so the stored variant keeps its original case.
        let vars = expand_text_variants(b"Hello", &mods);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], b"Hello");
    }

    #[test]
    fn test_expand_wide_variants() {
        let mods = Modifiers {
            wide: true,
            ascii: false,
            ..Default::default()
        };
        let vars = expand_text_variants(b"AB", &mods);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_compile_and_scan_regex_rule_end_to_end() {
        let input = r#"
        rule regex_hello {
            strings:
                $r = /hello/
            condition:
                $r
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.regex_patterns.len(), 1);

        let scanner = crate::scanner::Scanner::new(vec![compiled]).unwrap();
        let hit = scanner.scan(b"some data with hello inside");
        assert!(hit.matched_rules.contains(&"regex_hello".to_string()));

        let miss = scanner.scan(b"some data without the word");
        assert!(miss.matched_rules.is_empty());
    }

    #[test]
    fn test_empty_text_pattern_rejected() {
        let input = r#"
        rule empty_str {
            strings:
                $s = ""
            condition:
                any of them
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        assert!(matches!(
            compile_rule(&rule),
            Err(CompileError::EmptyPattern(_))
        ));
    }

    #[test]
    fn test_empty_hex_pattern_rejected() {
        let input = r#"
        rule empty_hex {
            strings:
                $h = { }
            condition:
                $h
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        assert!(matches!(
            compile_rule(&rule),
            Err(CompileError::EmptyHexPattern(id)) if id == "$h"
        ));
    }

    #[test]
    fn test_undefined_string_reference_rejected() {
        let input = r#"
        rule dangling_ref {
            strings:
                $a = "x"
            condition:
                $a and $missing
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        assert!(matches!(
            compile_rule(&rule),
            Err(CompileError::UndefinedString(id, _)) if id == "$missing"
        ));
    }

    #[test]
    fn test_of_set_with_nonexistent_id_rejected() {
        let input = r#"
        rule bad_of_set {
            strings:
                $a = "x"
            condition:
                all of ($a, $nope)
        }
        "#;
        let rule = parser::parse_rule(input).unwrap();
        assert!(matches!(
            compile_rule(&rule),
            Err(CompileError::UndefinedString(id, _)) if id == "$nope"
        ));

        // The well-formed variant still compiles.
        let ok = r#"
        rule good_of_set {
            strings:
                $a = "x"
                $b = "y"
            condition:
                all of ($a, $b)
        }
        "#;
        let rule = parser::parse_rule(ok).unwrap();
        assert!(compile_rule(&rule).is_ok());
    }
}
