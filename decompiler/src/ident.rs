//! Identifier sanitation for emitted C pseudocode.
//!
//! Names recovered from binaries (symbols, imports, register aliases) are not
//! guaranteed to be valid C identifiers: they may contain `@`, `.`, `-`,
//! non-ASCII bytes, start with a digit, be empty, or collide with C keywords.
//! Emission-time sanitation guarantees the listing is always valid C.
//! The mapping is a pure function of the raw name, and [`IdentMap`] keeps it
//! collision-free and deterministic within one function (first-seen name keeps
//! the base form; later collisions get `_1`, `_2`, ... suffixes).

use std::collections::{HashMap, HashSet};

/// C keywords that cannot be used as identifiers (C23 + common extensions).
const C_KEYWORDS: &[&str] = &[
    "auto", "bool", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "false", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "true", "union", "unsigned", "void", "volatile", "while", "_Alignas", "_Alignof",
    "_Atomic", "_BitInt", "_Bool", "_Complex", "_Decimal32", "_Decimal64", "_Decimal128",
    "_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local", "asm", "fortran",
];

/// Sanitize a single identifier: illegal characters become `_`, a leading
/// digit is prefixed with `_`, empty input becomes `_`, and C keywords get a
/// trailing `_`. Pure function of the input.
pub fn sanitize_ident(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if s.is_empty() {
        return "_".to_string();
    }
    if s.as_bytes()[0].is_ascii_digit() {
        s.insert(0, '_');
    }
    if C_KEYWORDS.contains(&s.as_str()) {
        s.push('_');
    }
    s
}

/// Deterministic per-function rename map: raw identifier -> valid C identifier.
///
/// Insertion order drives collision numbering, and emission order is fixed,
/// so the mapping is stable across runs of the same input.
#[derive(Debug, Default)]
pub struct IdentMap {
    map: HashMap<String, String>,
    used: HashSet<String>,
    next_suffix: HashMap<String, usize>,
}

impl IdentMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the sanitized form of `raw`, registering it on first use.
    pub fn get_or_insert(&mut self, raw: &str) -> String {
        if let Some(known) = self.map.get(raw) {
            return known.clone();
        }
        let mut candidate = sanitize_ident(raw);
        if self.used.contains(&candidate) {
            let base = candidate.clone();
            loop {
                let n = self.next_suffix.entry(base.clone()).or_insert(0);
                *n += 1;
                candidate = format!("{base}_{}", n);
                if !self.used.contains(&candidate) {
                    break;
                }
            }
        }
        self.used.insert(candidate.clone());
        self.map.insert(raw.to_string(), candidate.clone());
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_get_suffix() {
        assert_eq!(sanitize_ident("int"), "int_");
        assert_eq!(sanitize_ident("switch"), "switch_");
        assert_eq!(sanitize_ident("_Bool"), "_Bool_");
    }

    #[test]
    fn leading_digit_and_empty() {
        assert_eq!(sanitize_ident("0abc"), "_0abc");
        assert_eq!(sanitize_ident(""), "_");
        assert_eq!(sanitize_ident("7"), "_7");
    }

    #[test]
    fn illegal_characters_become_underscores() {
        assert_eq!(sanitize_ident("a-b.c@d"), "a_b_c_d");
        assert_eq!(sanitize_ident("_foo@8"), "_foo_8");
        assert_eq!(sanitize_ident("mangled??name"), "mangled__name");
        // Non-ASCII is not a valid identifier char in the emitted listing.
        assert_eq!(sanitize_ident("функция"), "_______");
    }

    #[test]
    fn valid_names_pass_through() {
        assert_eq!(sanitize_ident("v12"), "v12");
        assert_eq!(sanitize_ident("_rax"), "_rax");
        assert_eq!(sanitize_ident("sub_401000"), "sub_401000");
    }

    #[test]
    fn collisions_get_deterministic_suffixes() {
        let mut m = IdentMap::new();
        assert_eq!(m.get_or_insert("a-b"), "a_b");
        assert_eq!(m.get_or_insert("a_b"), "a_b_1");
        // Stable across repeats and reinsertion.
        assert_eq!(m.get_or_insert("a-b"), "a_b");
        assert_eq!(m.get_or_insert("a-b"), "a_b");
        let mut m2 = IdentMap::new();
        assert_eq!(m2.get_or_insert("a-b"), "a_b");
        assert_eq!(m2.get_or_insert("a_b"), "a_b_1");
    }

    #[test]
    fn suffix_chain_skips_existing_names() {
        let mut m = IdentMap::new();
        assert_eq!(m.get_or_insert("x"), "x");
        assert_eq!(m.get_or_insert("x_1"), "x_1");
        assert_eq!(m.get_or_insert("y"), "y");
        assert_eq!(m.get_or_insert("y_1"), "y_1");
        // "x-" sanitizes to "x_" which is unused, so it keeps that form.
        assert_eq!(m.get_or_insert("x-"), "x_");
        // The next one that also sanitizes to "x_" must get a suffix.
        assert_eq!(m.get_or_insert("x."), "x__1");
    }
}
