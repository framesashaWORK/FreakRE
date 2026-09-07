//! Safe bounded regex engine. Thompson-NFA construction, bounded simulation.
//! Supported: literals, char classes [a-z], bounded repeats {n,m} (m<=4096),
//!             unbounded * and + (Thompson split states), alternation |,
//!             concatenation, dot (any byte), escape classes \d \w \s,
//!             inline flags (?i) (?-u) (?is-u) at the start of the pattern.
//! NOT supported: backreferences, lookahead/behind, anchors ^ $ \b \B,
//!             inline flags anywhere except the very beginning.

use crate::{Match, Searcher};

const MAX_REPEAT: usize = 4096;
const MAX_STATES: usize = 65536;

#[derive(Debug, Clone)]
pub enum PatternError {
    Syntax(String),
    Unsupported(String),
    TooComplex,
}

impl core::fmt::Display for PatternError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PatternError::Syntax(m) => write!(f, "PatternError: {}", m),
            PatternError::Unsupported(m) => write!(f, "PatternError: unsupported construct: {}", m),
            PatternError::TooComplex => write!(f, "PatternError: pattern too complex"),
        }
    }
}

impl std::error::Error for PatternError {}

/// Compiled pattern (NFA represented as state machine).
#[derive(Debug, Clone)]
pub struct Pattern {
    /// NFA states: each state has transitions on byte ranges.
    states: Vec<NfaState>,
    start: usize,
    accept: Vec<usize>,
    /// Original pattern string for debugging.
    _source: String,
}

#[derive(Clone, Debug)]
struct NfaState {
    /// Transitions: (byte_range_start, byte_range_end_inclusive, target_state)
    transitions: Vec<(u8, u8, usize)>,
    /// Epsilon transitions
    epsilon: Vec<usize>,
}

impl NfaState {
    fn new() -> Self {
        Self {
            transitions: Vec::new(),
            epsilon: Vec::new(),
        }
    }
}

/// Compile a safe regex pattern from a string.
pub fn compile(pattern: &str) -> Result<Pattern, PatternError> {
    let mut builder = NfaBuilder::new();
    builder.parse_alternation(pattern.as_bytes())?;
    builder.build()
}

struct NfaBuilder {
    states: Vec<NfaState>,
    start_state: usize,
    accept_state: usize,
    case_insensitive: bool,
}

impl NfaBuilder {
    fn new() -> Self {
        Self {
            states: vec![NfaState::new()], // state 0 = unused initial
            start_state: 0,
            accept_state: 0,
            case_insensitive: false,
        }
    }

    fn add_state(&mut self) -> Result<usize, PatternError> {
        if self.states.len() >= MAX_STATES {
            return Err(PatternError::TooComplex);
        }
        self.states.push(NfaState::new());
        Ok(self.states.len() - 1)
    }

    fn parse_alternation(&mut self, input: &[u8]) -> Result<(), PatternError> {
        let mut pos = 0;
        if Self::has_inline_flags(input, pos) {
            pos = self.parse_inline_flags(input, pos)?;
        }

        let start = self.add_state()?;
        let end = self.add_state()?;
        self.start_state = start;
        self.accept_state = end;

        loop {
            pos = self.parse_concat(input, pos, start, end)?;
            if pos < input.len() && input[pos] == b'|' {
                pos += 1;
            } else {
                break;
            }
        }

        if pos < input.len() {
            return Err(PatternError::Syntax("unbalanced ')'".into()));
        }
        Ok(())
    }

    fn has_inline_flags(input: &[u8], pos: usize) -> bool {
        if input.len() < pos + 3 || input[pos] != b'(' || input[pos + 1] != b'?' {
            return false;
        }
        let body = &input[pos + 2..];
        let close = match body.iter().position(|&b| b == b')') {
            Some(c) => c,
            None => return false,
        };
        if close == 0 {
            return false;
        }
        body[..close]
            .iter()
            .all(|&b| b.is_ascii_alphabetic() || b == b'-')
    }

    fn parse_inline_flags(&mut self, input: &[u8], pos: usize) -> Result<usize, PatternError> {
        let mut p = pos + 2;
        let mut negate = false;
        let mut any = false;
        while p < input.len() && input[p] != b')' {
            match input[p] {
                b'-' if !negate => negate = true,
                b'i' => self.case_insensitive = !negate,
                b's' | b'm' | b'u' | b'x' => {}
                _ => return Err(PatternError::Syntax("unsupported inline flag".into())),
            }
            if input[p] != b'-' {
                any = true;
            }
            p += 1;
        }
        if !any {
            return Err(PatternError::Syntax("empty inline flags".into()));
        }
        Ok(p + 1)
    }

    fn parse_concat(
        &mut self,
        input: &[u8],
        mut pos: usize,
        from: usize,
        end: usize,
    ) -> Result<usize, PatternError> {
        let mut current = from;

        while pos < input.len() && input[pos] != b'|' && input[pos] != b')' {
            let (next_state, new_pos) = self.parse_atom_with_repeat(input, pos, current)?;
            current = next_state;
            pos = new_pos;
        }

        // Connect the final state of this concatenation to the continuation.
        self.states[current].epsilon.push(end);

        Ok(pos)
    }

    fn parse_atom_with_repeat(
        &mut self,
        input: &[u8],
        pos: usize,
        from: usize,
    ) -> Result<(usize, usize), PatternError> {
        let frag_lo = self.states.len();
        let (atom_start, atom_end, new_pos) = self.parse_atom(input, pos)?;
        let frag_hi = self.states.len() - 1;

        if new_pos < input.len() && input[new_pos] == b'*' {
            let split = self.add_state()?;
            let after = self.add_state()?;
            self.states[from].epsilon.push(split);
            self.states[split].epsilon.push(atom_start);
            self.states[split].epsilon.push(after);
            self.states[atom_end].epsilon.push(atom_start);
            self.states[atom_end].epsilon.push(after);
            Ok((after, new_pos + 1))
        } else if new_pos < input.len() && input[new_pos] == b'+' {
            let after = self.add_state()?;
            self.states[from].epsilon.push(atom_start);
            self.states[atom_end].epsilon.push(atom_start);
            self.states[atom_end].epsilon.push(after);
            Ok((after, new_pos + 1))
        } else if new_pos < input.len() && input[new_pos] == b'{' {
            let (min, max, end_pos) = self.parse_bounded_repeat(input, new_pos)?;
            let join = self.add_state()?;
            if max == 0 {
                self.states[from].epsilon.push(join);
                return Ok((join, end_pos));
            }
            let mut prev = from;
            for i in 0..max {
                let (copy_start, copy_end) =
                    self.duplicate_fragment(frag_lo, frag_hi, atom_start, atom_end)?;
                self.states[prev].epsilon.push(copy_start);
                prev = copy_end;
                if i + 1 >= min {
                    self.states[prev].epsilon.push(join);
                }
            }
            if min == 0 {
                self.states[from].epsilon.push(join);
            }
            Ok((join, end_pos))
        } else if new_pos < input.len() && input[new_pos] == b'?' {
            // Optional: epsilon bypass
            let after = self.add_state()?;
            self.states[from].epsilon.push(atom_start);
            self.states[from].epsilon.push(after);
            self.states[atom_end].epsilon.push(after);
            Ok((after, new_pos + 1))
        } else {
            self.states[from].epsilon.push(atom_start);
            Ok((atom_end, new_pos))
        }
    }

    fn parse_atom(
        &mut self,
        input: &[u8],
        pos: usize,
    ) -> Result<(usize, usize, usize), PatternError> {
        if pos >= input.len() {
            return Err(PatternError::Syntax("unexpected end of pattern".into()));
        }

        match input[pos] {
            b'(' => {
                if pos + 1 < input.len() && input[pos + 1] == b'?' {
                    return Err(PatternError::Syntax(
                        "inline flags are only allowed at the start of the pattern".into(),
                    ));
                }
                let gstart = self.add_state()?;
                let gend = self.add_state()?;
                let mut p = pos + 1;
                loop {
                    p = self.parse_concat(input, p, gstart, gend)?;
                    if p < input.len() && input[p] == b'|' {
                        p += 1;
                    } else {
                        break;
                    }
                }
                if p >= input.len() || input[p] != b')' {
                    return Err(PatternError::Syntax("expected ')'".into()));
                }
                Ok((gstart, gend, p + 1))
            }
            b'[' => self.parse_char_class(input, pos),
            b'^' | b'$' => Err(PatternError::Syntax("unsupported anchor".into())),
            b'.' => {
                let s = self.add_state()?;
                let e = self.add_state()?;
                self.states[s].transitions.push((0x00, 0xFF, e));
                Ok((s, e, pos + 1))
            }
            b'\\' => {
                if pos + 1 >= input.len() {
                    return Err(PatternError::Syntax("trailing backslash".into()));
                }
                let escaped = input[pos + 1];
                let ranges: Vec<(u8, u8)> = match escaped {
                    b'd' => vec![(b'0', b'9')],
                    b'w' => vec![(b'0', b'9'), (b'A', b'Z'), (b'a', b'z'), (b'_', b'_')],
                    b's' => vec![(b'\t', b'\n'), (b'\r', b'\r'), (b' ', b' ')],
                    b'b' | b'B' => return Err(PatternError::Syntax("unsupported anchor".into())),
                    b'n' => vec![(0x0A, 0x0A)],
                    b't' => vec![(0x09, 0x09)],
                    b'r' => vec![(0x0D, 0x0D)],
                    b'/' => vec![(b'/', b'/')],
                    other => {
                        if self.case_insensitive {
                            let lc = other.to_ascii_lowercase();
                            let uc = other.to_ascii_uppercase();
                            if lc == uc {
                                vec![(other, other)]
                            } else {
                                vec![(lc, lc), (uc, uc)]
                            }
                        } else {
                            vec![(other, other)]
                        }
                    }
                };
                let s = self.add_state()?;
                let e = self.add_state()?;
                for (lo, hi) in ranges {
                    self.states[s].transitions.push((lo, hi, e));
                }
                Ok((s, e, pos + 2))
            }
            c => {
                let s = self.add_state()?;
                let e = self.add_state()?;
                if self.case_insensitive {
                    let lc = c.to_ascii_lowercase();
                    let uc = c.to_ascii_uppercase();
                    self.states[s].transitions.push((lc, lc, e));
                    if uc != lc {
                        self.states[s].transitions.push((uc, uc, e));
                    }
                } else {
                    self.states[s].transitions.push((c, c, e));
                }
                Ok((s, e, pos + 1))
            }
        }
    }

    fn parse_char_class(
        &mut self,
        input: &[u8],
        pos: usize,
    ) -> Result<(usize, usize, usize), PatternError> {
        if input[pos] != b'[' {
            return Err(PatternError::Syntax("expected '['".into()));
        }
        let mut p = pos + 1;
        let negate = if p < input.len() && input[p] == b'^' {
            p += 1;
            true
        } else {
            false
        };

        let mut ranges: Vec<(u8, u8)> = Vec::new();
        while p < input.len() && input[p] != b']' {
            let lo = input[p];
            p += 1;
            if p + 1 < input.len() && input[p] == b'-' && input[p + 1] != b']' {
                let hi = input[p + 1];
                p += 2;
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        if p >= input.len() {
            return Err(PatternError::Syntax("unterminated character class".into()));
        }
        p += 1; // skip ']'

        // Case-insensitive: fold ASCII letters into mirrored-case ranges so
        // (?i)[a-z] also matches 'A'-'Z'. Negated classes complement the
        // folded set below, so (?i)[^a-z] excludes both cases.
        if self.case_insensitive {
            let mut folded = Vec::with_capacity(ranges.len() * 3);
            for &(lo, hi) in &ranges {
                folded.push((lo, hi));
                let l1 = lo.max(b'a');
                let l2 = hi.min(b'z');
                if l1 <= l2 {
                    folded.push((l1 - 32, l2 - 32));
                }
                let u1 = lo.max(b'A');
                let u2 = hi.min(b'Z');
                if u1 <= u2 {
                    folded.push((u1 + 32, u2 + 32));
                }
            }
            ranges = folded;
        }

        let s = self.add_state()?;
        let e = self.add_state()?;

        if negate {
            // Build complement: all bytes NOT in ranges
            let mut covered = [false; 256];
            for &(lo, hi) in &ranges {
                for b in lo..=hi {
                    covered[b as usize] = true;
                }
            }
            let mut i = 0usize;
            while i < 256 {
                if !covered[i] {
                    let start = i;
                    while i < 256 && !covered[i] {
                        i += 1;
                    }
                    self.states[s]
                        .transitions
                        .push((start as u8, (i - 1) as u8, e));
                } else {
                    i += 1;
                }
            }
        } else {
            for (lo, hi) in ranges {
                self.states[s].transitions.push((lo, hi, e));
            }
        }

        Ok((s, e, p))
    }

    fn parse_bounded_repeat(
        &mut self,
        input: &[u8],
        pos: usize,
    ) -> Result<(usize, usize, usize), PatternError> {
        if input[pos] != b'{' {
            return Err(PatternError::Syntax("expected '{'".into()));
        }
        let mut p = pos + 1;
        let min = Self::parse_number(input, &mut p)?;
        let max = if p < input.len() && input[p] == b',' {
            p += 1;
            Self::parse_number(input, &mut p)?
        } else {
            min
        };
        if p >= input.len() || input[p] != b'}' {
            return Err(PatternError::Syntax("expected '}'".into()));
        }
        p += 1;

        if max > MAX_REPEAT {
            return Err(PatternError::TooComplex);
        }
        if min > max {
            return Err(PatternError::Syntax("min > max in repeat".into()));
        }

        Ok((min, max, p))
    }

    fn parse_number(input: &[u8], pos: &mut usize) -> Result<usize, PatternError> {
        let start = *pos;
        while *pos < input.len() && input[*pos].is_ascii_digit() {
            *pos += 1;
        }
        if *pos == start {
            return Err(PatternError::Syntax("expected number".into()));
        }
        let s = core::str::from_utf8(&input[start..*pos])
            .map_err(|_| PatternError::Syntax("invalid utf8".into()))?;
        s.parse::<usize>()
            .map_err(|_| PatternError::Syntax("invalid number".into()))
    }

    fn duplicate_fragment(
        &mut self,
        lo: usize,
        hi: usize,
        entry: usize,
        exit: usize,
    ) -> Result<(usize, usize), PatternError> {
        let count = hi - lo + 1;
        if self.states.len() + count >= MAX_STATES {
            return Err(PatternError::TooComplex);
        }
        let offset = self.states.len() - lo;
        let cloned: Vec<NfaState> = self.states[lo..=hi].to_vec();
        for mut st in cloned {
            for t in st.transitions.iter_mut() {
                if t.2 >= lo && t.2 <= hi {
                    t.2 += offset;
                }
            }
            for e in st.epsilon.iter_mut() {
                if *e >= lo && *e <= hi {
                    *e += offset;
                }
            }
            self.states.push(st);
        }
        Ok((entry + offset, exit + offset))
    }

    fn build(self) -> Result<Pattern, PatternError> {
        Ok(Pattern {
            states: self.states,
            start: self.start_state,
            accept: vec![self.accept_state],
            _source: String::new(),
        })
    }
}

impl Searcher for Pattern {
    fn find_all(&self, haystack: &[u8]) -> Vec<Match> {
        let mut results = Vec::new();
        // Simple NFA simulation with active state sets
        for start_pos in 0..haystack.len() {
            let mut active: Vec<usize> = vec![self.start];
            // Expand epsilon closure
            active = self.epsilon_closure(&active);

            for (i, &byte) in haystack.iter().enumerate().skip(start_pos) {
                let mut next_active = Vec::new();

                for &state in &active {
                    for &(lo, hi, target) in &self.states[state].transitions {
                        if byte >= lo && byte <= hi {
                            next_active.push(target);
                        }
                    }
                }

                next_active = self.epsilon_closure(&next_active);

                if next_active.is_empty() {
                    break;
                }

                // Check for accept states
                for &acc in &self.accept {
                    if next_active.contains(&acc) {
                        results.push(Match {
                            pattern_id: 0,
                            start: start_pos,
                            end: i + 1,
                        });
                    }
                }

                active = next_active;
            }
        }
        results
    }

    fn is_match(&self, haystack: &[u8]) -> bool {
        !self.find_all(haystack).is_empty()
    }
}

impl Pattern {
    /// Shortest match end (absolute offset) for a match that STARTS exactly at
    /// `start`, or `None`. Semantics are identical to the per-`start_pos` inner
    /// loop of [`Searcher::find_all`] (epsilon closure at start, stop when the
    /// active set drains, accept checked after each consumed byte), so the
    /// prefilter can verify candidates without changing match semantics.
    pub(crate) fn leftmost_shortest_from(&self, haystack: &[u8], start: usize) -> Option<usize> {
        let mut active = self.epsilon_closure(&[self.start]);
        for (i, &byte) in haystack.iter().enumerate().skip(start) {
            let mut next_active = Vec::new();
            for &state in &active {
                for &(lo, hi, target) in &self.states[state].transitions {
                    if byte >= lo && byte <= hi {
                        next_active.push(target);
                    }
                }
            }
            next_active = self.epsilon_closure(&next_active);
            if next_active.is_empty() {
                return None;
            }
            if self.accept.iter().any(|a| next_active.contains(a)) {
                return Some(i + 1);
            }
            active = next_active;
        }
        None
    }

    fn epsilon_closure(&self, states: &[usize]) -> Vec<usize> {
        let mut result = states.to_vec();
        let mut visited = vec![false; self.states.len()];
        for &s in states {
            visited[s] = true;
        }

        let mut i = 0;
        while i < result.len() {
            let epsilons = self.states[result[i]].epsilon.clone();
            for target in epsilons {
                if !visited[target] {
                    visited[target] = true;
                    result.push(target);
                }
            }
            i += 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal() {
        let pat = compile("hello").unwrap();
        assert!(pat.is_match(b"say hello world"));
        assert!(!pat.is_match(b"goodbye"));
    }

    #[test]
    fn test_char_class() {
        let pat = compile("[0-9]{3}").unwrap();
        assert!(pat.is_match(b"abc123def"));
        assert!(!pat.is_match(b"ab12cd"));
    }

    #[test]
    fn test_dot() {
        let pat = compile("a.c").unwrap();
        assert!(pat.is_match(b"abc"));
        assert!(pat.is_match(b"aXc"));
        assert!(!pat.is_match(b"ac"));
    }

    #[test]
    fn test_alternation() {
        let pat = compile("cat|dog").unwrap();
        assert!(pat.is_match(b"I have a cat"));
        assert!(pat.is_match(b"I have a dog"));
        assert!(!pat.is_match(b"I have a fish"));
    }

    #[test]
    fn test_case_insensitive_flag() {
        let pat = compile("(?i)hello").unwrap();
        assert!(pat.is_match(b"say HeLLo world"));
        assert!(!compile("hello").unwrap().is_match(b"HeLLo"));
        assert!(compile("(?is-u)ABC").unwrap().is_match(b"xabcx"));
    }

    #[test]
    fn test_case_insensitive_char_class() {
        assert!(compile("(?i)[a-z]+").unwrap().is_match(b"abcXYZ"));
        assert!(compile("(?i)[A-Z]+").unwrap().is_match(b"ABCxyz"));
        assert!(compile("(?i)[c-e]").unwrap().is_match(b"D"));
        assert!(!compile("(?i)[^a-z]").unwrap().is_match(b"aZ"));
        assert!(compile("(?i)[^a-z]").unwrap().is_match(b"0"));
        // Case-sensitive classes must be unaffected.
        assert!(compile("[a-z]+").unwrap().is_match(b"abc"));
        assert!(!compile("[a-z]+").unwrap().is_match(b"ABC"));
    }

    #[test]
    fn test_negated_flag() {
        let pat = compile("(?i-u)MiXeD").unwrap();
        assert!(pat.is_match(b"mixed"));
    }

    #[test]
    fn test_inline_flags_only_at_start() {
        assert!(compile("a(?i)b").is_err());
        assert!(compile("(?q)a").is_err());
        assert!(compile("(?)a").is_err());
    }

    #[test]
    fn test_escape_classes() {
        assert!(compile(r"\d\d\d").unwrap().is_match(b"abc123"));
        assert!(!compile(r"\d\d\d").unwrap().is_match(b"ab12cd"));
        assert!(compile(r"\w\w\w").unwrap().is_match(b"__a1"));
        assert!(!compile(r"\w\w\w").unwrap().is_match(b"a b"));
        assert!(compile(r"\s").unwrap().is_match(b"x y"));
        assert!(!compile(r"\s").unwrap().is_match(b"xy"));
    }

    #[test]
    fn test_anchors_rejected() {
        assert!(compile("^abc").is_err());
        assert!(compile("abc$").is_err());
        assert!(compile(r"a\b").is_err());
        assert!(compile(r"\Ba").is_err());
    }

    #[test]
    fn test_star_quantifier() {
        let pat = compile("ab*c").unwrap();
        assert!(pat.is_match(b"ac"));
        assert!(pat.is_match(b"xabbbcz"));
        assert!(!pat.is_match(b"aXc"));
        assert!(compile("a*b*c").unwrap().is_match(b"aaabbc"));
    }

    #[test]
    fn test_plus_quantifier() {
        let pat = compile("ab+c").unwrap();
        assert!(pat.is_match(b"zzabbc"));
        assert!(pat.is_match(b"abc"));
        assert!(!pat.is_match(b"ac"));
    }

    #[test]
    fn test_group_alternation() {
        let pat = compile("(cat|dog)s?").unwrap();
        assert!(pat.is_match(b"two cats"));
        assert!(pat.is_match(b"one dog"));
        assert!(!pat.is_match(b"cows"));
    }

    #[test]
    fn test_nested_groups() {
        let pat = compile("((a|b)c)d").unwrap();
        assert!(pat.is_match(b"acd"));
        assert!(pat.is_match(b"bcd"));
        assert!(!pat.is_match(b"abd"));
    }

    #[test]
    fn test_escaped_parens_are_literals() {
        let pat = compile(r"\(a\)").unwrap();
        assert!(pat.is_match(b"x(a)y"));
        assert!(pat.is_match(b"(a)"));
        assert!(!pat.is_match(b"ab"));
        let inner = compile(r"(a\))").unwrap();
        assert!(inner.is_match(b"x(a)y"));
        assert!(inner.is_match(b"a)"));
        assert!(!inner.is_match(b"a"));
        let unclosed = compile(r"(\)");
        assert!(unclosed.is_err());
    }

    #[test]
    fn test_bounded_repeat_of_multi_state_atom() {
        let pat = compile("(ab){2,3}").unwrap();
        assert!(pat.is_match(b"xabab"));
        assert!(pat.is_match(b"ababa"));
        assert!(!pat.is_match(b"aba"));
        assert!(!pat.is_match(b"a"));

        let exact = compile("(ab){2}").unwrap();
        assert!(exact.is_match(b"zababy"));
        assert!(!exact.is_match(b"aba"));
    }

    #[test]
    fn test_too_complex_is_error_not_panic() {
        let result = std::panic::catch_unwind(|| compile("(abcdefghijklmnop){4096}"));
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(PatternError::TooComplex)) => {}
            Ok(Err(e)) => panic!("unexpected error: {}", e),
            Err(_) => panic!("compile panicked"),
        }
    }
}
