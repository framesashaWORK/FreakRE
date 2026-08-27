//! Mandatory-literal prefilter extraction for safe regex patterns.
//!
//! For every top-level alternation branch of a pattern we extract the
//! *mandatory leading literal*: the maximal run of literal bytes that every
//! match produced by that branch must start with. A pattern is
//! **prefilterable** only when *every* top-level branch yields a non-empty
//! mandatory prefix; those prefixes feed one combined Aho-Corasick automaton
//! whose hits mark the only start positions where the full regex needs to be
//! simulated.
//!
//! # Soundness contract
//!
//! The prefilter may only *reduce* the set of inspected start positions. It is
//! sound iff: for every match starting at `s`, at least one registered literal
//! occurs inside the match at a known offset bound (`max_lead` above its
//! extracted position). We guarantee this conservatively:
//!
//! * Only bytes parsed as exact literals by [`crate::regex`] are collected
//!   (escaped metacharacters resolve to their literal byte; `\n`/`\t`/`\r`
//!   resolve to their control bytes).
//! * The first wildcard (`.`, `[...]`), escape class (`\d`, `\w`, `\s`),
//!   group `(` or quantified atom ends the run; anything before it is truly
//!   mandatory.
//! * A quantifier after an atom removes that atom's byte from the guaranteed
//!   prefix (it may repeat or vanish).
//! * Patterns with inline `(?i)` are rejected outright: a case-folded literal
//!   matches several byte values and cannot be keyed in a plain byte-level AC.
//! * Branches without a guaranteed non-empty literal (escape classes, leading
//!   groups, empty branches such as `a|`) make the whole pattern fall back to
//!   the original brute-force scan.
//!
//! With these rules every match must begin with one of the registered
//! literals at offset `0..=max_lead` (here always `0`), so verifying only at
//! candidate positions derived from AC hits preserves match results exactly.

/// A mandatory literal prefix of one top-level alternation branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltPrefix {
    /// Bytes every match of this branch must contain, starting at some
    /// offset `<= max_lead` into the match.
    pub literal: Vec<u8>,
    /// Upper bound of the distance between match start and literal start.
    /// Extraction currently only guarantees fixed-offset prefixes, so this is
    /// always `0`; kept explicit because candidate verification uses it as the
    /// bounded window `[lit_start - max_lead, lit_start]`.
    pub max_lead: usize,
}

/// Result of static analysis of one regex source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefilterPlan {
    /// One entry per usable top-level alternation branch.
    pub alts: Vec<AltPrefix>,
    /// `false` ⇒ the pattern must use the brute-force scan (see module docs).
    pub usable: bool,
}

impl PrefilterPlan {
    fn fallback() -> Self {
        Self { alts: Vec::new(), usable: false }
    }
}

/// Analyze a pattern source and produce its prefilter plan.
pub fn plan_for(source: &str) -> PrefilterPlan {
    let b = source.as_bytes();

    // Inline flags: mirror `NfaBuilder::has_inline_flags` placement rules.
    if let Some((flags_end, body)) = inline_flag_body(b) {
        // Case folding turns literals into multi-value ranges, which a
        // byte-exact AC cannot key. Conservative: any `i` ⇒ no prefilter.
        if body.contains(&b'i') {
            return PrefilterPlan::fallback();
        }
        return plan_from(&b[flags_end..]);
    }
    plan_from(b)
}

fn plan_from(b: &[u8]) -> PrefilterPlan {
    if b.is_empty() {
        return PrefilterPlan::fallback();
    }
    let mut alts = Vec::new();
    for part in top_level_split(b) {
        match leading_literal(part) {
            Some(lit) if !lit.is_empty() => {
                alts.push(AltPrefix { literal: lit, max_lead: 0 });
            }
            // Empty / unguaranteed branch: a match may start anywhere,
            // so no candidate set can be complete. Fall back.
            _ => return PrefilterPlan::fallback(),
        }
    }
    PrefilterPlan { alts, usable: true }
}

/// Split on top-level `|`, mirroring `parse_alternation`'s notion of depth.
/// Skips escapes and `[...]` classes so their contents never split.
fn top_level_split(b: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2; // escaped byte: never structural
                continue;
            }
            b'[' => {
                i = skip_class(b, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
            }
            b'|' if depth == 0 => {
                parts.push(&b[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&b[start..]);
    parts
}

/// `b[i] == b'['`: return index just past the closing `]`.
/// Mirrors the engine: the FIRST `]` closes the class (no escapes inside).
fn skip_class(b: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < b.len() {
        if b[i] == b']' {
            return i + 1;
        }
        i += 1;
    }
    b.len()
}

/// Extract the mandatory leading literal of one alternation branch.
/// `Some(vec![])` means "the run ended immediately" (branch unusable);
/// `None` means malformed input (the engine will reject it anyway).
#[allow(unused_assignments)]
fn leading_literal(alt: &[u8]) -> Option<Vec<u8>> {
    let mut lit = Vec::new();
    let mut p = 0usize;
    let mut after_atom = false;
    while p < alt.len() {
        let c = alt[p];
        if after_atom && matches!(c, b'*' | b'+' | b'?' | b'{') {
            // Quantifier binds to the previous atom: that atom is repeated
            // or optional, so its byte is no longer guaranteed.
            lit.pop();
            return Some(lit);
        }
        after_atom = false;
        match c {
            b'\\' => {
                let e = *alt.get(p + 1)?;
                p += 2;
                match e {
                    // Escape classes end the guaranteed run.
                    b'd' | b'D' | b'w' | b'W' | b's' | b'S' | b'b' | b'B' => return Some(lit),
                    // Resolved-control escapes behave like literal bytes.
                    b'n' => lit.push(0x0A),
                    b't' => lit.push(0x09),
                    b'r' => lit.push(0x0D),
                    other => lit.push(other),
                }
                after_atom = true;
            }
            // Wildcard, class or group: stop, keeping what we have.
            b'.' | b'[' | b'(' => return Some(lit),
            // Everything else (including `*+?{` in atom-start position,
            // exactly like the engine's default branch) is a literal byte.
            _ => {
                lit.push(c);
                p += 1;
                after_atom = true;
            }
        }
    }
    Some(lit)
}

/// If `b` starts with an inline flag group `(?...)`, return `(end, body)`
/// where `body` is the text between `(?` and `)`. Mirrors the engine's
/// acceptance rule (only alphabetic/- inside, non-empty, closed).
fn inline_flag_body(b: &[u8]) -> Option<(usize, &[u8])> {
    if b.len() < 3 || b[0] != b'(' || b[1] != b'?' {
        return None;
    }
    let body = &b[2..];
    let close = body.iter().position(|&c| c == b')')?;
    if close == 0 {
        return None;
    }
    if !body[..close].iter().all(|&c| c.is_ascii_alphabetic() || c == b'-') {
        return None;
    }
    Some((2 + close + 1, &body[..close]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lits(src: &str) -> Vec<Vec<u8>> {
        let p = plan_for(src);
        assert!(p.usable, "{src} should be prefilterable");
        p.alts.into_iter().map(|a| a.literal).collect()
    }

    #[test]
    fn pure_literal() {
        assert_eq!(lits("hello"), vec![b"hello".to_vec()]);
    }

    #[test]
    fn alternation_takes_each_branch_prefix() {
        assert_eq!(lits("cat|dog"), vec![b"cat".to_vec(), b"dog".to_vec()]);
    }

    #[test]
    fn quantifier_drops_quantified_byte() {
        assert_eq!(lits("ab*c"), vec![b"a".to_vec()]);
        assert_eq!(lits("ab?c"), vec![b"a".to_vec()]);
        assert_eq!(lits("ab+c"), vec![b"a".to_vec()]);
        assert_eq!(lits("ab{2,3}c"), vec![b"a".to_vec()]);
    }

    #[test]
    fn wildcard_ends_run() {
        assert_eq!(lits("a.b"), vec![b"a".to_vec()]);
        assert_eq!(lits("a[0-9]b"), vec![b"a".to_vec()]);
    }

    #[test]
    fn escaped_metacharacters_are_literal_bytes() {
        assert_eq!(lits(r"a\*b"), vec![b"a*b".to_vec()]);
        assert_eq!(lits(r"\(a\)"), vec![b"(a)".to_vec()]);
        assert_eq!(lits(r"\nAB"), vec![vec![0x0A, b'A', b'B']]);
    }

    #[test]
    fn escape_class_makes_it_unusable() {
        assert!(!plan_for(r"\dabc").usable);
        assert!(!plan_for(r"\w+x").usable);
    }

    #[test]
    fn case_insensitive_is_unusable() {
        assert!(!plan_for("(?i)hello").usable);
        assert!(!plan_for("(?is-u)ABC").usable);
        // Non-insensitive flags stay usable.
        assert!(plan_for("(?-u)ABC").usable);
    }

    #[test]
    fn groups_and_empty_branches_are_unusable() {
        assert!(!plan_for("(cat|dog)x").usable);
        assert!(!plan_for("a|").usable);
        assert!(!plan_for("").usable);
        assert!(!plan_for("[a-z]ail").usable);
    }

    #[test]
    fn classes_do_not_confuse_splitting() {
        // '|' inside a class must not split alternatives.
        assert_eq!(lits("[a|b]c"), vec![b"c".to_vec()]);
        assert_eq!(lits("x[()]y"), vec![b"x".to_vec()]);
    }

    #[test]
    fn leading_quantifier_chars_are_literals_like_the_engine() {
        // Engine parses a leading '*' as a literal byte.
        assert_eq!(lits("*a"), vec![b"*a".to_vec()]);
    }
}
