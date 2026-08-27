//! freakre-patterns: Safe pattern matching engine.
//! - Aho-Corasick for multi-literal search (O(n) guaranteed)
//! - Bounded regex subset: char classes, bounded repeats {n,m} where m <= 4096
//! - NO backtracking, NO unbounded quantifiers, NO lookahead/lookbehind
//! - Byte-oriented (&[u8]), no UTF-8 requirement
//! - Regex scans are driven by an Aho-Corasick prefilter over mandatory
//!   literal prefixes; the full NFA only runs at candidate positions.
//!   Patterns without a provably mandatory literal fall back to the
//!   brute-force scan (see [`prefilter`] for the soundness contract).

pub mod ac;
pub mod prefilter;
pub mod regex;

use std::borrow::Cow;
use std::fmt;

pub use ac::{AhoCorasick, EmptyPatternError};
pub use prefilter::{plan_for, AltPrefix, PrefilterPlan};
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
///
/// On construction the pattern source is analyzed for mandatory literal
/// prefixes ([`plan_for`]). When every top-level alternation branch yields a
/// non-empty guaranteed prefix, one combined Aho-Corasick automaton over those
/// prefixes drives [`SafeRegex::find_iter`]: the NFA is simulated only at
/// candidate positions (plus a bounded window of `max_lead` bytes, see
/// [`prefilter`]). Otherwise iteration falls back to the original brute-force
/// scan with identical semantics.
#[derive(Debug)]
pub struct SafeRegex {
    pattern: Pattern,
    plan: PrefilterPlan,
    /// Combined AC over `plan.alts` literals (deduplicated); present iff
    /// `plan.usable`. Maps AC pattern id → alternative indices.
    prefilter: Option<RegexPrefilter>,
}

/// Per-pattern combined prefix automaton.
struct RegexPrefilter {
    ac: AhoCorasick,
    /// AC pattern id (unique literal) → alternative indices sharing it.
    owners: Vec<Vec<u32>>,
}

impl fmt::Debug for RegexPrefilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegexPrefilter")
            .field("literals", &self.ac.pattern_count())
            .finish()
    }
}

/// Match result from SafeRegex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexMatch {
    pub start: usize,
    pub end: usize,
}

fn build_prefilter(plan: &PrefilterPlan) -> Option<RegexPrefilter> {
    if !plan.usable || plan.alts.is_empty() {
        return None;
    }
    let mut uniq: Vec<Vec<u8>> = Vec::new();
    let mut owners: Vec<Vec<u32>> = Vec::new();
    for (ai, alt) in plan.alts.iter().enumerate() {
        if let Some(k) = uniq.iter().position(|u| u == &alt.literal) {
            owners[k].push(ai as u32);
        } else {
            uniq.push(alt.literal.clone());
            owners.push(vec![ai as u32]);
        }
    }
    let refs: Vec<&[u8]> = uniq.iter().map(|v| v.as_slice()).collect();
    // Literals are guaranteed non-empty by the planner, so build cannot fail;
    // degrade to brute force if it ever did.
    AhoCorasick::build(&refs).ok().map(|ac| RegexPrefilter { ac, owners })
}

impl SafeRegex {
    pub fn new(pattern_str: &str) -> Result<Self, String> {
        let pattern = compile(pattern_str).map_err(|e| e.to_string())?;
        let plan = plan_for(pattern_str);
        let prefilter = build_prefilter(&plan);
        Ok(Self { pattern, plan, prefilter })
    }

    /// Static mandatory-literal analysis of this pattern's source.
    pub fn plan(&self) -> &PrefilterPlan {
        &self.plan
    }

    /// `true` when [`SafeRegex::find_iter`] uses the AC prefilter path.
    pub fn is_prefiltered(&self) -> bool {
        self.prefilter.is_some()
    }

    /// Iterate over all non-overlapping matches in byte data.
    ///
    /// Semantics are identical on both paths: leftmost start wins and each
    /// reported match is the shortest match at that start; iteration resumes
    /// after its end. The prefiltered path only simulates the NFA at positions
    /// where a mandatory literal occurs.
    pub fn find_iter<'a>(&'a self, data: &'a [u8]) -> RegexMatchIter<'a> {
        match &self.prefilter {
            Some(pf) => {
                let mut hits: Vec<(u32, usize)> = Vec::new();
                // scan_overlapping emits hits in ascending end order and the
                // owner expansion preserves that order per alternative.
                pf.ac.scan_overlapping(data, |pid, end| {
                    for &ai in &pf.owners[pid] {
                        hits.push((ai, end));
                    }
                });
                RegexMatchIter::Filtered(FilteredRegexMatches {
                    re: self,
                    data,
                    hits: Cow::Owned(hits),
                    idx: 0,
                    pos: 0,
                })
            }
            None => RegexMatchIter::Legacy(BruteForceRegexMatches {
                pattern: &self.pattern,
                data,
                pos: 0,
            }),
        }
    }

    /// Non-overlapping matches restricted to precomputed candidate hits:
    /// `(alternative_index, literal_end)` pairs with ascending `literal_end`.
    ///
    /// Used by callers that run ONE shared automaton across many regexes
    /// (e.g. yara-lite) so the haystack is swept once in total. Produces the
    /// same sequence as [`SafeRegex::find_iter`] when `candidates` contains
    /// every occurrence of every alternative literal of this pattern.
    pub fn find_iter_filtered<'a>(
        &'a self,
        data: &'a [u8],
        candidates: &'a [(u32, usize)],
    ) -> FilteredRegexMatches<'a> {
        FilteredRegexMatches {
            re: self,
            data,
            hits: Cow::Borrowed(candidates),
            idx: 0,
            pos: 0,
        }
    }
}

#[cfg(test)]
fn assert_equivalent(src: &str, data: &[u8]) {
    let re = SafeRegex::new(src).unwrap();
    let legacy = legacy_collect(src, data);
    let got = filtered_collect(src, data);
    assert_eq!(legacy, got, "mismatch for /{src}/ on {data:?}");
    if re.is_prefiltered() {
        let pf = re.prefilter.as_ref().unwrap();
        let mut hits: Vec<(u32, usize)> = Vec::new();
        pf.ac.scan_overlapping(data, |pid, end| {
            for &ai in &pf.owners[pid] {
                hits.push((ai, end));
            }
        });
        let via_shared: Vec<RegexMatch> = re.find_iter_filtered(data, &hits).collect();
        assert_eq!(legacy, via_shared, "shared-sweep mismatch for /{src}/");
    }
}

#[test]
fn prefiltered_matches_brute_force() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("hello", b"xhexxhellohello!hell".to_vec()),
        ("ab*c", b"acxabbbcxxabc".to_vec()),
        ("ab+c", b"abbbc ab ac".to_vec()),
        ("ab?c", b"abcxacxxabc".to_vec()),
        ("cat|dog", b"catdog bird cat hotdog".to_vec()),
        ("a[0-9]{2}b", b"a12bxa9bxa00bx".to_vec()),
        (r"a\*b", b"za*bz a b".to_vec()),
        ("\\nX", b"ok\nXno\nX".to_vec()),
        ("(cat|dog)s?", b"cats dogs cow".to_vec()),
        ("MARKER.*END", b"junk MARKER mid END tail MARKER x END".to_vec()),
        ("miss_me", b"nothing here at all".to_vec()),
    ];
    for (src, data) in cases {
        assert!(
            SafeRegex::new(src).unwrap().is_prefiltered(),
            "/{src}/ should prefilter"
        );
        assert_equivalent(src, &data);
    }
}

#[test]
fn fallback_matches_brute_force() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("(?i)MiXeD", b"mixed MiXeD MIXED".to_vec()),
        (r"\dABC", b"x7ABCy9ABC".to_vec()),
        ("a|", b"aa ba".to_vec()), // zero-width branch → fallback
        ("(cat)x", b"catx cat".to_vec()),
        ("[a-z]ail", b"tail fail".to_vec()),
    ];
    for (src, data) in cases {
        assert!(
            !SafeRegex::new(src).unwrap().is_prefiltered(),
            "/{src}/ should fall back"
        );
        assert_equivalent(src, &data);
    }
}

#[test]
fn filtered_api_with_external_candidates() {
    let re = SafeRegex::new("hello").unwrap();
    let data = b"xxhelloxhello";
    let cands = [(0u32, 7usize), (0, 13)];
    let ms: Vec<RegexMatch> = re.find_iter_filtered(data, &cands).collect();
    assert_eq!(ms.len(), 2);
    assert_eq!((ms[0].start, ms[0].end), (2, 7));
    assert_eq!((ms[1].start, ms[1].end), (8, 13));

    let none: Vec<RegexMatch> = re.find_iter_filtered(data, &[]).collect();
    assert!(none.is_empty());
}

#[test]
fn plan_is_exposed() {
    let re = SafeRegex::new("cat|dog").unwrap();
    let plan = re.plan();
    assert!(plan.usable);
    assert_eq!(plan.alts.len(), 2);
    assert_eq!(plan.alts[0].literal, b"cat".to_vec());
}

pub enum RegexMatchIter<'a> {
    /// AC-prefiltered candidate verification.
    Filtered(FilteredRegexMatches<'a>),
    /// Original O(n·m) all-starts scan (fallback for unfilterable patterns).
    Legacy(BruteForceRegexMatches<'a>),
}

impl<'a> Iterator for RegexMatchIter<'a> {
    type Item = RegexMatch;

    fn next(&mut self) -> Option<RegexMatch> {
        match self {
            RegexMatchIter::Filtered(it) => it.next(),
            RegexMatchIter::Legacy(it) => it.next(),
        }
    }
}

pub struct FilteredRegexMatches<'a> {
    re: &'a SafeRegex,
    data: &'a [u8],
    /// `(alternative_index, literal_end)` ascending by literal end.
    hits: Cow<'a, [(u32, usize)]>,
    idx: usize,
    pos: usize,
}

impl<'a> Iterator for FilteredRegexMatches<'a> {
    type Item = RegexMatch;

    fn next(&mut self) -> Option<RegexMatch> {
        let alts = &self.re.plan.alts;
        while self.idx < self.hits.len() {
            if self.pos >= self.data.len() {
                return None;
            }
            let (ai, end) = self.hits[self.idx];
            self.idx += 1;
            let alt = &alts[ai as usize];
            let lit_len = alt.literal.len();
            if end < lit_len || end > self.data.len() {
                continue;
            }
            let lit_start = end - lit_len;
            // Bounded window: the match may start up to `max_lead` bytes
            // before the literal (always 0 with the current extractor).
            let lo = self.pos.max(lit_start.saturating_sub(alt.max_lead));
            for s in lo..=lit_start {
                if let Some(e) = self.re.pattern.leftmost_shortest_from(self.data, s) {
                    self.pos = if e > s { e } else { s + 1 };
                    return Some(RegexMatch { start: s, end: e });
                }
            }
        }
        None
    }
}

pub struct BruteForceRegexMatches<'a> {
    pattern: &'a Pattern,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for BruteForceRegexMatches<'a> {
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

/// Collect matches with the brute-force (legacy) scan.
#[cfg(test)]
fn legacy_collect(src: &str, data: &[u8]) -> Vec<RegexMatch> {
    let pattern = compile(src).unwrap();
    let it = BruteForceRegexMatches {
        pattern: &pattern,
        data,
        pos: 0,
    };
    it.collect()
}

/// Collect matches via the canonical [`SafeRegex`] path (prefilter when possible).
#[cfg(test)]
fn filtered_collect(src: &str, data: &[u8]) -> Vec<RegexMatch> {
    SafeRegex::new(src).unwrap().find_iter(data).collect()
}
