//! Mandatory-literal prefilter extraction for safe regex patterns.
//!
//! For every top-level alternation branch of a pattern we extract the
//! *mandatory leading literal(s)*: literal bytes that every match produced
//! by that branch must start with (or contain within a bounded lead). A
//! pattern is **prefilterable** only when *every* top-level branch yields a
//! non-empty mandatory prefix; those prefixes feed one combined Aho-Corasick
//! automaton whose hits mark the only start positions where the full regex
//! needs to be simulated.
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
//! * A leading `(a|b|...)` group fans out: each alternative's leading
//!   literals are registered (they all sit at match offset 0). This applies
//!   only when the group itself is mandatory (not quantified) and the
//!   remainder of the branch after the group is nullable-or-empty —
//!   otherwise we fall back (e.g. `(cat|dog)x`, `(cat)x`).
//! * A leading `[...]` class containing `|` is skipped, counting one byte of
//!   lead (classes match exactly one byte in this engine); a following
//!   literal is then registered with `max_lead` covering the skipped bytes
//!   (e.g. `[a|b]c` registers `c` with lead 1). Plain leading classes without
//!   `|` end the run instead (conservative fallback, e.g. `[a-z]ail`).
//! * Any other leading wildcard (`.`), escape class (`\d`, `\w`, `\s`) or
//!   group ends the run; anything before it is truly mandatory.
//! * A quantifier after an atom removes that atom's byte from the guaranteed
//!   prefix (it may repeat or vanish).
//! * Patterns with inline `(?i)` are rejected outright: a case-folded literal
//!   matches several byte values and cannot be keyed in a plain byte-level AC.
//! * Branches without a guaranteed non-empty literal make the whole pattern
//!   fall back to the original brute-force scan.
//!
//! With these rules every match must begin with one of the registered
//! literals at offset `0..=max_lead`, so verifying only at candidate
//! positions derived from AC hits preserves match results exactly.

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
        Self {
            alts: Vec::new(),
            usable: false,
        }
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
        let prefixes = branch_prefixes(part);
        if prefixes.is_empty() {
            // Unguaranteed branch: a match may start anywhere,
            // so no candidate set can be complete. Fall back.
            return PrefilterPlan::fallback();
        }
        for (literal, max_lead) in prefixes {
            alts.push(AltPrefix { literal, max_lead });
        }
    }
    PrefilterPlan { alts, usable: true }
}

/// Mandatory leading literals of one alternation branch.
///
/// Returns one `(literal, max_lead)` per alternative (usually exactly one;
/// a leading group fans out into several). An empty return means "no
/// guaranteed literal" and forces fallback for the whole pattern.
fn branch_prefixes(alt: &[u8]) -> Vec<(Vec<u8>, usize)> {
    // Leading group: fan out over its alternatives. Sound only when the
    // group itself is mandatory (no trailing quantifier here — that is
    // checked via the remainder) — every alternative sits at offset 0.
    if alt.first() == Some(&b'(') {
        let Some(close) = match_paren(alt, 0) else {
            return Vec::new();
        };
        let rest = &alt[close + 1..];
        // A quantifier on the group (`(a|b)+x`) or a non-nullable
        // remainder (`(cat|dog)x`) voids the guarantee: fall back.
        if rest
            .first()
            .is_some_and(|&c| matches!(c, b'*' | b'+' | b'?' | b'{'))
            || !rest_nullable(rest)
        {
            return Vec::new();
        }
        let inner = &alt[1..close];
        let mut out = Vec::new();
        for sub in top_level_split(inner) {
            let mut sub_ps = branch_prefixes(sub);
            if sub_ps.iter().any(|(l, _)| l.is_empty()) || sub_ps.is_empty() {
                return Vec::new();
            }
            out.append(&mut sub_ps);
        }
        if out.is_empty() {
            return Vec::new(); // e.g. empty group `()`
        }
        return out;
    }
    // Ordinary leading run (with bar-class skipping).
    match leading_literal(alt) {
        Some((lit, lead)) if !lit.is_empty() => vec![(lit, lead)],
        _ => Vec::new(),
    }
}

/// `true` iff `rest` can match the empty string: a (possibly empty) sequence
/// of atoms each suffixed with `?`, `*` or `{0,...}`. Conservative: anything
/// unrecognized (including malformed input, which the engine rejects anyway)
/// returns `false`, forcing fallback — always sound.
fn rest_nullable(rest: &[u8]) -> bool {
    let mut p = 0usize;
    while p < rest.len() {
        // Skip one atom.
        let mut end = match rest[p] {
            b'\\' => {
                if p + 1 >= rest.len() {
                    return false;
                }
                p + 2
            }
            b'[' => {
                let mut q = p + 1;
                while q < rest.len() && rest[q] != b']' {
                    q += 1;
                }
                if q >= rest.len() {
                    return false;
                }
                q + 1
            }
            b'(' => match match_paren(rest, p) {
                Some(c) => c + 1,
                None => return false,
            },
            // Zero-width atoms never consume input.
            b'^' | b'$' => p + 1,
            _ => p + 1,
        };
        // The atom must be optional.
        if end < rest.len() && matches!(rest[end], b'?' | b'*') {
            end += 1;
        } else if end < rest.len() && rest[end] == b'{' {
            // `{0}`, `{0,n}` — nullable; anything else is not.
            if end + 1 < rest.len() && rest[end + 1] == b'0' {
                let Some(close) = rest[end..].iter().position(|&c| c == b'}') else {
                    return false;
                };
                end += close + 1;
            } else {
                return false;
            }
        } else {
            return false;
        }
        p = end;
    }
    true
}

/// Index of the `)` matching the `(` at `open`, respecting nesting,
/// escapes and `[...]` classes. `None` when unbalanced.
fn match_paren(b: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(b.get(open), Some(&b'('));
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => {
                i = skip_class(b, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
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

/// Like [`skip_class`] but also reports whether the class closed and whether
/// its body contains a `|` (which the prefilter treats as skippable).
/// Returns `(end, has_bar)`; `None` when the class is unterminated.
fn skip_closed_class(b: &[u8], i: usize) -> Option<(usize, bool)> {
    let mut j = i + 1;
    let mut has_bar = false;
    while j < b.len() {
        match b[j] {
            b']' => return Some((j + 1, has_bar)),
            b'|' => {
                has_bar = true;
                j += 1;
            }
            _ => j += 1,
        }
    }
    None
}

/// Extract the mandatory leading literal of one alternation branch, without
/// a leading group (groups are fanned out by [`branch_prefixes`]).
///
/// Returns `(literal, lead)` where `lead` counts bytes skipped over leading
/// `|`-classes (each matches exactly one byte in this engine). An empty
/// literal means "the run ended immediately" (branch unusable); `None`
/// means malformed input (the engine will reject it anyway).
#[allow(unused_assignments)]
fn leading_literal(alt: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut lit = Vec::new();
    let mut lead = 0usize;
    let mut p = 0usize;
    let mut after_atom = false;
    // True when the previous atom was a skipped `|`-class (no byte pushed).
    // A quantifier here would give it unbounded width, voiding the lead —
    // but the literal collected so far stays valid, so return it as-is.
    let mut after_skip = false;
    while p < alt.len() {
        let c = alt[p];
        if matches!(c, b'*' | b'+' | b'?' | b'{') {
            if after_atom {
                // Quantifier binds to the previous atom: that atom is
                // repeated or optional, so its byte is no longer guaranteed.
                lit.pop();
                return Some((lit, lead));
            }
            if after_skip {
                return Some((lit, lead));
            }
            // Leading quantifier char: literal, like the engine.
        }
        after_atom = false;
        after_skip = false;
        match c {
            b'\\' => {
                let e = *alt.get(p + 1)?;
                p += 2;
                match e {
                    // Escape classes end the guaranteed run.
                    b'd' | b'D' | b'w' | b'W' | b's' | b'S' | b'b' | b'B' => {
                        return Some((lit, lead))
                    }
                    // Resolved-control escapes behave like literal bytes.
                    b'n' => lit.push(0x0A),
                    b't' => lit.push(0x09),
                    b'r' => lit.push(0x0D),
                    other => lit.push(other),
                }
                after_atom = true;
            }
            // A *closed* class containing `|` is skipped, counting one byte
            // of lead: it matches exactly one byte, so a following literal
            // is still guaranteed (e.g. `[a|b]c` always contains `c` at
            // offset 1). Any other leading class ends the run (conservative
            // fallback). An unterminated class is malformed (the engine
            // rejects it); treat as run end.
            b'[' => match skip_closed_class(alt, p) {
                Some((end, true)) => {
                    lead += 1;
                    p = end;
                    after_skip = true;
                    continue;
                }
                _ => return Some((lit, lead)),
            },
            // Wildcard or group: stop, keeping what we have.
            b'.' | b'(' => return Some((lit, lead)),
            // Everything else (including `*+?{` in atom-start position,
            // exactly like the engine's default branch) is a literal byte.
            _ => {
                lit.push(c);
                p += 1;
                after_atom = true;
            }
        }
    }
    Some((lit, lead))
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
    if !body[..close]
        .iter()
        .all(|&c| c.is_ascii_alphabetic() || c == b'-')
    {
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
