//! freakre-patterns: Safe pattern matching engine.
//! - Aho-Corasick for multi-literal search (O(n) guaranteed)
//! - Bounded regex subset: char classes, bounded repeats {n,m} where m <= 4096
//! - NO backtracking, NO unbounded quantifiers, NO lookahead/lookbehind
//! - Byte-oriented (&[u8]), no UTF-8 requirement

pub mod ac;
pub mod regex;

pub use ac::{AhoCorasick, EmptyPatternError};
pub use regex::{Pattern, PatternError, compile};

/// A match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Index of the pattern that matched.
    pub pattern_id: usize,
    /// Start offset in the haystack.
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
}

/// Search trait implemented by both AC and regex engines.
pub trait Searcher {
    fn find_all(&self, haystack: &[u8]) -> Vec<Match>;
    fn is_match(&self, haystack: &[u8]) -> bool;
}

// ─── Convenience wrappers for yara-lite integration ──────────────

/// Wrapper around AhoCorasick with Vec<Vec<u8>> input API.
#[derive(Clone)]
pub struct AcSearcher {
    inner: AhoCorasick,
}

/// Match result from AcSearcher with pattern_index field.
#[derive(Debug, Clone, Copy)]
pub struct AcMatch {
    pub pattern_index: usize,
    pub start: usize,
    pub len: usize,
}

impl AcSearcher {
    pub fn new(patterns: &[Vec<u8>]) -> Result<Self, EmptyPatternError> {
        let refs: Vec<&[u8]> = patterns.iter().map(|p| p.as_slice()).collect();
        Ok(Self { inner: AhoCorasick::build(&refs)? })
    }

    /// Find all overlapping matches as a lazy iterator (O(1) memory).
    pub fn find_overlapping<'a>(&'a self, haystack: &'a [u8]) -> impl Iterator<Item = AcMatch> + 'a {
        self.inner.iter_overlapping(haystack).map(|m| AcMatch {
            pattern_index: m.pattern_id,
            start: m.start,
            len: m.end - m.start,
        })
    }
}

/// Safe regex wrapper compatible with yara-lite's Regex API.
#[derive(Debug)]
pub struct SafeRegex {
    pattern: Pattern,
}

/// Match result from SafeRegex.
#[derive(Debug, Clone, Copy)]
pub struct RegexMatch {
    pub start: usize,
    pub end: usize,
}

impl SafeRegex {
    pub fn new(pattern_str: &str) -> Result<Self, String> {
        let pattern = compile(pattern_str).map_err(|e| e.to_string())?;
        Ok(Self { pattern })
    }

    /// Iterate over all non-overlapping matches in byte data.
    pub fn find_iter<'a>(&'a self, data: &'a [u8]) -> RegexMatchIter<'a> {
        RegexMatchIter {
            pattern: &self.pattern,
            data,
            pos: 0,
        }
    }
}

pub struct RegexMatchIter<'a> {
    pattern: &'a Pattern,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for RegexMatchIter<'a> {
    type Item = RegexMatch;

    fn next(&mut self) -> Option<RegexMatch> {
        if self.pos >= self.data.len() {
            return None;
        }
        // Search from current position
        let remaining = &self.data[self.pos..];
        let matches = self.pattern.find_all(remaining);
        if matches.is_empty() {
            return None;
        }
        let m = &matches[0];
        let abs_start = self.pos + m.start;
        let abs_end = self.pos + m.end;
        // Advance past this match to avoid infinite loop on zero-width matches
        self.pos = if abs_end > abs_start { abs_end } else { abs_start + 1 };
        Some(RegexMatch { start: abs_start, end: abs_end })
    }
}
