#![allow(dead_code, unused_assignments)]
//! # Binary Diffing
//!
//! Compare two binaries to find similar functions and changes.
//! Useful for patch analysis, malware variant detection, and
//! understanding updates to closed-source software.
//!
//! ## Algorithms
//!
//! 1. **Name-based**: Match functions by name (fast, but limited)
//! 2. **Size-based**: Match functions by size (quick heuristic)
//! 3. **Mnemonic-based**: Compare instruction mnemonics decoded from
//!    stored `code_bytes` (MD-index like Diaphora); when raw bytes are
//!    unavailable, falls back to a combined size/name score

use project_db::{ProjectDatabase, FunctionEntry};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const MAX_DECODED_INSTRUCTIONS: usize = 65536;
const MAX_CONSECUTIVE_DECODE_FAILURES: usize = 32;

#[derive(Error, Debug)]
pub enum DiffError {
    #[error("Database error: {0}")]
    Database(#[from] project_db::DbError),
    #[error("No functions to compare")]
    NoFunctions,
    #[error("Timeout during diffing")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, DiffError>;

/// A match between two functions
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FunctionMatch {
    pub address_a: u64,
    pub address_b: u64,
    pub name_a: String,
    pub name_b: String,
    pub similarity: f64,  // 0.0 - 1.0
    pub match_type: MatchType,
    pub details: MatchDetails,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MatchType {
    /// Exact name match
    NameMatch,
    /// Same size
    SizeMatch,
    /// Similar instruction mnemonics (decoded from code_bytes)
    MnemonicMatch,
    /// Combined size/name score (no mnemonic data available)
    Combined,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatchDetails {
    pub name_score: f64,
    pub size_score: f64,
    pub mnemonic_score: f64,
    pub matched_instructions: usize,
    pub total_instructions_a: usize,
    pub total_instructions_b: usize,
}

/// Function that exists only in one binary
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnmatchedFunction {
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub in_binary: BinarySide,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BinarySide {
    A,
    B,
}

/// Results of a binary diff
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiffResult {
    pub matches: Vec<FunctionMatch>,
    pub unmatched_a: Vec<UnmatchedFunction>,
    pub unmatched_b: Vec<UnmatchedFunction>,
    pub stats: DiffStats,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiffStats {
    pub total_functions_a: usize,
    pub total_functions_b: usize,
    pub matched_count: usize,
    pub unmatched_a_count: usize,
    pub unmatched_b_count: usize,
    /// Mean similarity over non-SizeMatch matches (size-only pairs are too
    /// weak a signal to count toward confidence stats).
    pub average_similarity: f64,
    /// Matches with similarity >= 0.99, excluding pure SizeMatch pairs.
    pub perfect_matches: usize,
}

/// Binary differ
pub struct BinaryDiffer {
    similarity_threshold: f64,
    use_name_matching: bool,
    use_size_matching: bool,
    use_mnemonic_matching: bool,
    timeout: Option<Duration>,
}

impl BinaryDiffer {
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.7,
            use_name_matching: true,
            use_size_matching: true,
            use_mnemonic_matching: true,
            timeout: None,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn disable_name_matching(mut self) -> Self {
        self.use_name_matching = false;
        self
    }

    pub fn disable_size_matching(mut self) -> Self {
        self.use_size_matching = false;
        self
    }

    pub fn disable_mnemonic_matching(mut self) -> Self {
        self.use_mnemonic_matching = false;
        self
    }

    /// Compare two project databases
    pub fn diff(&self, db_a: &ProjectDatabase, db_b: &ProjectDatabase) -> Result<DiffResult> {
        let deadline = self.timeout.map(|t| Instant::now() + t);

        let funcs_a = db_a.list_functions()?;
        let funcs_b = db_b.list_functions()?;

        if funcs_a.is_empty() || funcs_b.is_empty() {
            return Err(DiffError::NoFunctions);
        }

        self.check_deadline(deadline)?;

        let mut matches = Vec::new();
        let mut matched_a = HashSet::new();
        let mut matched_b = HashSet::new();

        // Phase 1: Name-based matching
        if self.use_name_matching {
            let name_matches = self.match_by_name(&funcs_a, &funcs_b);
            for m in name_matches {
                matched_a.insert(m.address_a);
                matched_b.insert(m.address_b);
                matches.push(m);
            }
        }

        self.check_deadline(deadline)?;

        // Phase 2: Size-based matching (for unmatched functions)
        if self.use_size_matching {
            let unmatched_a: Vec<_> = funcs_a.iter()
                .filter(|f| !matched_a.contains(&f.address))
                .collect();
            let unmatched_b: Vec<_> = funcs_b.iter()
                .filter(|f| !matched_b.contains(&f.address))
                .collect();

            let size_matches = self.match_by_size(&unmatched_a, &unmatched_b, deadline)?;
            for m in size_matches {
                matched_a.insert(m.address_a);
                matched_b.insert(m.address_b);
                matches.push(m);
            }
        }

        self.check_deadline(deadline)?;

        // Phase 3: Mnemonic-based matching
        if self.use_mnemonic_matching {
            let unmatched_a: Vec<_> = funcs_a.iter()
                .filter(|f| !matched_a.contains(&f.address))
                .collect();
            let unmatched_b: Vec<_> = funcs_b.iter()
                .filter(|f| !matched_b.contains(&f.address))
                .collect();

            let mnemonic_matches = self.match_by_mnemonics(&unmatched_a, &unmatched_b, deadline)?;
            for m in mnemonic_matches {
                if m.similarity >= self.similarity_threshold {
                    matched_a.insert(m.address_a);
                    matched_b.insert(m.address_b);
                    matches.push(m);
                }
            }
        }

        // Collect unmatched functions
        let unmatched_a: Vec<_> = funcs_a.iter()
            .filter(|f| !matched_a.contains(&f.address))
            .map(|f| UnmatchedFunction {
                address: f.address,
                name: f.name.clone(),
                size: f.size,
                in_binary: BinarySide::A,
            })
            .collect();

        let unmatched_b: Vec<_> = funcs_b.iter()
            .filter(|f| !matched_b.contains(&f.address))
            .map(|f| UnmatchedFunction {
                address: f.address,
                name: f.name.clone(),
                size: f.size,
                in_binary: BinarySide::B,
            })
            .collect();

        // Calculate stats. Pure SizeMatch pairs are excluded from both
        // averages and perfect-match counts below: equal-size functions are
        // frequently unrelated, so their similarity is weak evidence and
        // must not inflate confidence stats.
        let confidently_scored: Vec<_> = matches.iter()
            .filter(|m| m.match_type != MatchType::SizeMatch)
            .collect();
        let avg_similarity = if confidently_scored.is_empty() {
            0.0
        } else {
            confidently_scored.iter().map(|m| m.similarity).sum::<f64>()
                / confidently_scored.len() as f64
        };

        let perfect_matches = matches.iter()
            .filter(|m| m.similarity >= 0.99 && m.match_type != MatchType::SizeMatch)
            .count();

        let stats = DiffStats {
            total_functions_a: funcs_a.len(),
            total_functions_b: funcs_b.len(),
            matched_count: matches.len(),
            unmatched_a_count: unmatched_a.len(),
            unmatched_b_count: unmatched_b.len(),
            average_similarity: avg_similarity,
            perfect_matches,
        };

        Ok(DiffResult {
            matches,
            unmatched_a,
            unmatched_b,
            stats,
        })
    }

    /// Match functions by name. Each B-side function is consumed at most
    /// once: candidate pairs are assigned greedily by best size fit
    /// (ties broken by lowest B then A address), so duplicate names on
    /// either side resolve deterministically instead of first-come or
    /// last-write-wins.
    fn match_by_name(&self, funcs_a: &[FunctionEntry], funcs_b: &[FunctionEntry]) -> Vec<FunctionMatch> {
        let mut b_by_name: HashMap<&str, Vec<&FunctionEntry>> = HashMap::new();

        for f in funcs_b {
            b_by_name.entry(&f.name).or_default().push(f);
        }

        let mut pairs: Vec<(usize, u64, u64, &FunctionEntry, &FunctionEntry)> = Vec::new();
        for fa in funcs_a {
            if let Some(candidates) = b_by_name.get(fa.name.as_str()) {
                for fb in candidates {
                    pairs.push((fb.size.abs_diff(fa.size), fb.address, fa.address, fa, fb));
                }
            }
        }
        pairs.sort_by_key(|(size_dist, addr_b, addr_a, _, _)| {
            (*size_dist, *addr_b, *addr_a)
        });

        let mut used_a: HashSet<u64> = HashSet::new();
        let mut used_b: HashSet<u64> = HashSet::new();
        let mut matches: Vec<FunctionMatch> = Vec::new();

        for (_, _, _, fa, fb) in pairs {
            if !used_a.insert(fa.address) || !used_b.insert(fb.address) {
                continue;
            }

            let size_score = self.size_similarity(fa.size, fb.size);
            matches.push(FunctionMatch {
                address_a: fa.address,
                address_b: fb.address,
                name_a: fa.name.clone(),
                name_b: fb.name.clone(),
                similarity: 1.0,
                match_type: MatchType::NameMatch,
                details: MatchDetails {
                    name_score: 1.0,
                    size_score,
                    mnemonic_score: 0.0,
                    matched_instructions: 0,
                    total_instructions_a: 0,
                    total_instructions_b: 0,
                },
            });
        }

        matches.sort_by_key(|m| m.address_a);
        matches
    }

    /// Match functions by size
    fn match_by_size(
        &self,
        funcs_a: &[&FunctionEntry],
        funcs_b: &[&FunctionEntry],
        deadline: Option<Instant>,
    ) -> Result<Vec<FunctionMatch>> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        for fa in funcs_a {
            self.check_deadline(deadline)?;
            let mut best_match: Option<(&FunctionEntry, f64)> = None;

            for fb in funcs_b {
                if matched_b.contains(&fb.address) {
                    continue;
                }

                let similarity = self.size_similarity(fa.size, fb.size);
                if similarity >= self.similarity_threshold
                    && best_match.map(|(_, s)| similarity > s).unwrap_or(true) {
                        best_match = Some((fb, similarity));
                    }
            }

            if let Some((fb, similarity)) = best_match {
                matched_b.insert(fb.address);
                matches.push(FunctionMatch {
                    address_a: fa.address,
                    address_b: fb.address,
                    name_a: fa.name.clone(),
                    name_b: fb.name.clone(),
                    similarity,
                    match_type: MatchType::SizeMatch,
                    details: MatchDetails {
                        name_score: if fa.name == fb.name { 1.0 } else { 0.0 },
                        size_score: similarity,
                        mnemonic_score: 0.0,
                        matched_instructions: 0,
                        total_instructions_a: 0,
                        total_instructions_b: 0,
                    },
                });
            }
        }

        Ok(matches)
    }

    /// Match functions by instruction mnemonics decoded from `code_bytes`.
    ///
    /// `mnemonic_score` is the fraction of matched mnemonics (multiset
    /// intersection over the larger stream); `matched_instructions` and the
    /// totals carry the raw counts. Functions without decodable bytes fall
    /// back to a combined size/name score and are reported as `Combined`.
    fn match_by_mnemonics(
        &self,
        funcs_a: &[&FunctionEntry],
        funcs_b: &[&FunctionEntry],
        deadline: Option<Instant>,
    ) -> Result<Vec<FunctionMatch>> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        let streams_a = Self::mnemonic_streams(funcs_a);
        let streams_b = Self::mnemonic_streams(funcs_b);

        for fa in funcs_a {
            self.check_deadline(deadline)?;
            let stream_a = streams_a.get(&fa.address);
            let mut best_match: Option<(&FunctionEntry, f64, f64, usize, usize, usize)> = None;

            for fb in funcs_b {
                self.check_deadline(deadline)?;
                if matched_b.contains(&fb.address) {
                    continue;
                }

                let stream_b = streams_b.get(&fb.address);
                let size_sim = self.size_similarity(fa.size, fb.size);
                let name_sim = self.name_similarity(&fa.name, &fb.name);

                // Only pair streams decoded in the SAME width mode; mixing
                // modes would compare unrelated instruction histograms.
                let comparable = matches!(
                    (stream_a, stream_b),
                    (Some((ma, a)), Some((mb, b)))
                        if ma == mb && !a.is_empty() && !b.is_empty()
                );

                let (combined, mnemonic_score, matched_i, total_a, total_b) =
                    if comparable {
                        let (_, a) = stream_a.unwrap();
                        let (_, b) = stream_b.unwrap();
                        let (matched_i, mnemonic_score) =
                            Self::mnemonic_overlap(a, b);
                        let combined =
                            mnemonic_score * 0.5 + size_sim * 0.3 + name_sim * 0.2;
                        (combined, mnemonic_score, matched_i, a.len(), b.len())
                    } else {
                        (
                            size_sim * 0.7 + name_sim * 0.3,
                            0.0,
                            0,
                            0,
                            0,
                        )
                    };

                if combined >= self.similarity_threshold
                    && best_match
                        .map(|(_, s, _, _, _, _)| combined > s)
                        .unwrap_or(true)
                    {
                        best_match = Some((fb, combined, mnemonic_score, matched_i, total_a, total_b));
                    }
            }

            if let Some((fb, similarity, mnemonic_score, matched_i, total_a, total_b)) =
                best_match
            {
                matched_b.insert(fb.address);
                let has_mnemonic_data = matches!(
                    (stream_a, streams_b.get(&fb.address)),
                    (Some((ma, a)), Some((mb, b)))
                        if ma == mb && !a.is_empty() && !b.is_empty()
                );
                matches.push(FunctionMatch {
                    address_a: fa.address,
                    address_b: fb.address,
                    name_a: fa.name.clone(),
                    name_b: fb.name.clone(),
                    similarity,
                    match_type: if has_mnemonic_data {
                        MatchType::MnemonicMatch
                    } else {
                        MatchType::Combined
                    },
                    details: MatchDetails {
                        name_score: self.name_similarity(&fa.name, &fb.name),
                        size_score: self.size_similarity(fa.size, fb.size),
                        mnemonic_score,
                        matched_instructions: matched_i,
                        total_instructions_a: total_a,
                        total_instructions_b: total_b,
                    },
                });
            }
        }

        Ok(matches)
    }

    /// Decode mnemonic streams once per function, recording the width mode
    /// (64- or 32-bit) each stream was decoded with so pairs are only
    /// compared when both sides used the same mode.
    fn mnemonic_streams(
        funcs: &[&FunctionEntry],
    ) -> HashMap<u64, (bool, Vec<freakre_x86::Mnemonic>)> {
        funcs
            .iter()
            .filter_map(|f| {
                let code = f.code_bytes.as_deref()?;
                Self::detect_mnemonic_stream(code).map(|(mode, s)| (f.address, (mode, s)))
            })
            .collect()
    }

    /// Pick a single decode width per function by linear-sweeping in both
    /// modes and keeping the richer stream (ties -> x64). Returns the chosen
    /// mode with its stream; comparison code must reject cross-mode pairs.
    fn detect_mnemonic_stream(code: &[u8]) -> Option<(bool, Vec<freakre_x86::Mnemonic>)> {
        if code.is_empty() {
            return None;
        }

        let as_64 = Self::decode_mnemonics(code, true);
        let as_32 = Self::decode_mnemonics(code, false);
        if as_64.len() >= as_32.len() {
            (!as_64.is_empty()).then_some((true, as_64))
        } else {
            (!as_32.is_empty()).then_some((false, as_32))
        }
    }

    fn decode_mnemonics(code: &[u8], is_64bit: bool) -> Vec<freakre_x86::Mnemonic> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        let mut failures = 0usize;

        while offset < code.len() && out.len() < MAX_DECODED_INSTRUCTIONS {
            match freakre_x86::decode(&code[offset..], is_64bit) {
                Ok(instr) if instr.length > 0 => {
                    if instr.mnemonic != freakre_x86::Mnemonic::Unknown {
                        out.push(instr.mnemonic);
                    }
                    offset += instr.length;
                    failures = 0;
                }
                _ => {
                    failures += 1;
                    if failures >= MAX_CONSECUTIVE_DECODE_FAILURES {
                        break;
                    }
                    offset += 1;
                }
            }
        }

        out
    }

    /// Multiset intersection of two mnemonic histograms.
    /// Returns (matched_count, score against the longer stream).
    fn mnemonic_overlap(
        seq_a: &[freakre_x86::Mnemonic],
        seq_b: &[freakre_x86::Mnemonic],
    ) -> (usize, f64) {
        let hist = |seq: &[freakre_x86::Mnemonic]| -> HashMap<&'static str, usize> {
            let mut h: HashMap<&'static str, usize> = HashMap::new();
            for m in seq {
                *h.entry(m.as_str()).or_insert(0) += 1;
            }
            h
        };

        let ha = hist(seq_a);
        let hb = hist(seq_b);
        let mut matched = 0usize;
        for (name, count_a) in &ha {
            if let Some(count_b) = hb.get(name) {
                matched += (*count_a).min(*count_b);
            }
        }

        let total = seq_a.len().max(seq_b.len());
        let score = if total == 0 {
            0.0
        } else {
            matched as f64 / total as f64
        };
        (matched, score)
    }

    /// Returns Err(DiffError::Timeout) once the deadline has passed.
    fn check_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        match deadline {
            Some(d) if Instant::now() >= d => Err(DiffError::Timeout),
            _ => Ok(()),
        }
    }

    /// Calculate size similarity (0.0 - 1.0)
    fn size_similarity(&self, size_a: usize, size_b: usize) -> f64 {
        if size_a == 0 && size_b == 0 {
            return 1.0;
        }
        let max_size = size_a.max(size_b);
        let min_size = size_a.min(size_b);
        min_size as f64 / max_size as f64
    }

    /// Calculate name similarity using Jaro-Winkler distance
    fn name_similarity(&self, name_a: &str, name_b: &str) -> f64 {
        if name_a == name_b {
            return 1.0;
        }

        let len_a = name_a.len();
        let len_b = name_b.len();
        
        if len_a == 0 || len_b == 0 {
            return 0.0;
        }

        // Jaro-Winkler similarity: standard for matching symbol names,
        // it rewards a shared prefix so "main" and "main2" score high.
        let a: Vec<char> = name_a.chars().collect();
        let b: Vec<char> = name_b.chars().collect();
        let la = a.len();
        let lb = b.len();

        let match_distance = (la.max(lb) / 2).saturating_sub(1);
        let mut a_matched = vec![false; la];
        let mut b_matched = vec![false; lb];
        let mut matches = 0usize;

        for i in 0..la {
            let start = i.saturating_sub(match_distance);
            let end = (i + match_distance).min(lb - 1);
            for j in start..=end {
                if !b_matched[j] && a[i] == b[j] {
                    a_matched[i] = true;
                    b_matched[j] = true;
                    matches += 1;
                    break;
                }
            }
        }

        if matches == 0 {
            return 0.0;
        }

        let mut transpositions = 0usize;
        let mut k = 0usize;
        for i in 0..la {
            if a_matched[i] {
                while k < lb && !b_matched[k] {
                    k += 1;
                }
                if k < lb && a[i] != b[k] {
                    transpositions += 1;
                }
                k += 1;
            }
        }

        let jaro = (matches as f64 / la as f64
            + matches as f64 / lb as f64
            + (matches as f64 - transpositions as f64 / 2.0) / matches as f64)
            / 3.0;

        let mut prefix = 0usize;
        for i in 0..la.min(lb) {
            if a[i] == b[i] {
                prefix += 1;
            } else {
                break;
            }
            if prefix == 4 {
                break;
            }
        }

        jaro + prefix as f64 * 0.1 * (1.0 - jaro)
    }
}

impl Default for BinaryDiffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a diff report in text format
pub fn generate_report(result: &DiffResult) -> String {
    let mut report = String::new();

    report.push_str("=== Binary Diff Report ===\n\n");
    
    report.push_str(&format!("Binary A: {} functions\n", result.stats.total_functions_a));
    report.push_str(&format!("Binary B: {} functions\n", result.stats.total_functions_b));
    report.push_str(&format!("Matched: {} ({:.1}%)\n", 
        result.stats.matched_count,
        result.stats.matched_count as f64 / result.stats.total_functions_a.max(1) as f64 * 100.0
    ));
    report.push_str(&format!("Unmatched in A: {}\n", result.stats.unmatched_a_count));
    report.push_str(&format!("Unmatched in B: {}\n", result.stats.unmatched_b_count));
    report.push_str(&format!("Average similarity: {:.1}%\n", result.stats.average_similarity * 100.0));
    report.push_str(&format!("Perfect matches: {}\n\n", result.stats.perfect_matches));

    report.push_str("=== Matched Functions ===\n");
    for m in &result.matches {
        report.push_str(&format!(
            "  0x{:X} ({}) <-> 0x{:X} ({}) [{:.1}%] ({:?})\n",
            m.address_a, m.name_a,
            m.address_b, m.name_b,
            m.similarity * 100.0,
            m.match_type
        ));
    }

    if !result.unmatched_a.is_empty() {
        report.push_str("\n=== Unmatched in Binary A ===\n");
        for f in &result.unmatched_a {
            report.push_str(&format!("  0x{:X} {} ({} bytes)\n", f.address, f.name, f.size));
        }
    }

    if !result.unmatched_b.is_empty() {
        report.push_str("\n=== Unmatched in Binary B ===\n");
        for f in &result.unmatched_b {
            report.push_str(&format!("  0x{:X} {} ({} bytes)\n", f.address, f.name, f.size));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(base: &std::path::Path, tag: &str, funcs: Vec<FunctionEntry>) -> ProjectDatabase {
        let dir = base.join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let mut db = ProjectDatabase::create(
            dir.join("project.bdb"),
            std::path::PathBuf::from("binary.exe"),
            "hash".to_string(),
            "x86_64".to_string(),
            "PE".to_string(),
        )
        .unwrap();
        for f in funcs {
            db.add_function(f).unwrap();
        }
        db
    }

    #[test]
    fn test_size_similarity() {
        let differ = BinaryDiffer::new();

        assert_eq!(differ.size_similarity(100, 100), 1.0);
        assert_eq!(differ.size_similarity(100, 50), 0.5);
        assert_eq!(differ.size_similarity(0, 0), 1.0);
    }

    #[test]
    fn test_name_similarity() {
        let differ = BinaryDiffer::new();

        assert_eq!(differ.name_similarity("main", "main"), 1.0);
        assert!(differ.name_similarity("main", "main2") > 0.8);
        assert!(differ.name_similarity("foo", "bar") < 0.5);
    }

    #[test]
    fn test_diff_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let func = FunctionEntry::new(0x401000, "func_a".to_string(), 64);
        let db_a = make_db(tmp.path(), "a", vec![func.clone()]);
        let db_b = make_db(tmp.path(), "b", vec![func]);

        let differ = BinaryDiffer::new().with_timeout(Duration::ZERO);
        let result = differ.diff(&db_a, &db_b);

        match result {
            Err(DiffError::Timeout) => {}
            other => panic!("expected Timeout, got {:?}", other.err()),
        }
    }

    #[test]
    fn test_mnemonic_matching_counts_real_instructions() {
        let tmp = tempfile::tempdir().unwrap();

        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];

        let mut fa = FunctionEntry::new(0x401000, "alpha_v1".to_string(), code.len());
        fa.code_bytes = Some(code.clone());
        let mut fb = FunctionEntry::new(0x402000, "alpha_v2".to_string(), code.len());
        fb.code_bytes = Some(code);

        let db_a = make_db(tmp.path(), "a", vec![fa]);
        let db_b = make_db(tmp.path(), "b", vec![fb]);

        let differ = BinaryDiffer::new()
            .disable_size_matching()
            .disable_name_matching();
        let result = differ.diff(&db_a, &db_b).unwrap();

        assert_eq!(result.matches.len(), 1);
        let m = &result.matches[0];
        assert_eq!(m.match_type, MatchType::MnemonicMatch);
        // Dual-mode sweep yields 6 instructions (32-bit reading wins here).
        assert_eq!(m.details.matched_instructions, 6);
        assert_eq!(m.details.total_instructions_a, 6);
        assert_eq!(m.details.total_instructions_b, 6);
        assert!((m.details.mnemonic_score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_combined_fallback_without_code_bytes() {
        let tmp = tempfile::tempdir().unwrap();

        let fa = FunctionEntry::new(0x401000, "one_thing".to_string(), 100);
        let fb = FunctionEntry::new(0x402000, "another_one".to_string(), 100);

        let db_a = make_db(tmp.path(), "a", vec![fa]);
        let db_b = make_db(tmp.path(), "b", vec![fb]);

        let differ = BinaryDiffer::new().disable_size_matching();
        let result = differ.diff(&db_a, &db_b).unwrap();

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].match_type, MatchType::Combined);
        assert_eq!(result.matches[0].details.matched_instructions, 0);
        assert!(result.matches[0].details.size_score > 0.99);
        assert!(result.matches[0].details.mnemonic_score.abs() < 1e-9);
    }

    #[test]
    fn test_detect_mnemonic_stream() {
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
        let (mode_64, stream) = BinaryDiffer::detect_mnemonic_stream(&code).unwrap();
        // The dual-mode sweep picks the richer stream: in 32-bit these bytes
        // decode as push/dec/mov/xor/pop/ret (6), beating the 64-bit read.
        assert!(!mode_64);
        assert_eq!(stream.len(), 6);

        assert!(BinaryDiffer::detect_mnemonic_stream(&[]).is_none());
    }

    /// Regression: two unrelated functions of identical size used to be
    /// reported with similarity 1.0, counting as perfect matches and
    /// inflating average_similarity. Pure SizeMatch pairs must be excluded
    /// from both confidence stats.
    #[test]
    fn test_equal_size_unrelated_funcs_not_perfect_match() {
        let tmp = tempfile::tempdir().unwrap();

        let fa = FunctionEntry::new(0x401000, "parse_header_v1".to_string(), 128);
        let fb = FunctionEntry::new(0x402000, "checksum_blob_v9".to_string(), 128);

        let db_a = make_db(tmp.path(), "a", vec![fa]);
        let db_b = make_db(tmp.path(), "b", vec![fb]);

        let differ = BinaryDiffer::new();
        let result = differ.diff(&db_a, &db_b).unwrap();

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].match_type, MatchType::SizeMatch);
        assert_eq!(result.stats.perfect_matches, 0);
        assert_eq!(result.stats.average_similarity, 0.0);
        // The tentative size pairing is still reported.
        assert_eq!(result.stats.matched_count, 1);
    }

    /// Regression: duplicate names in A must not match the same B function
    /// repeatedly, and each B target is consumed at most once.
    #[test]
    fn test_duplicate_names_in_a_consumed_once() {
        let tmp = tempfile::tempdir().unwrap();

        let fa1 = FunctionEntry::new(0x401000, "sub".to_string(), 10);
        let fa2 = FunctionEntry::new(0x402000, "sub".to_string(), 20);
        let fb = FunctionEntry::new(0x501000, "sub".to_string(), 20);

        let db_a = make_db(tmp.path(), "a", vec![fa1, fa2]);
        let db_b = make_db(tmp.path(), "b", vec![fb]);

        let differ = BinaryDiffer::new()
            .disable_size_matching()
            .disable_mnemonic_matching();
        let result = differ.diff(&db_a, &db_b).unwrap();

        let name_matches: Vec<_> = result.matches.iter()
            .filter(|m| m.match_type == MatchType::NameMatch)
            .collect();
        assert_eq!(name_matches.len(), 1);
        // Closest-size candidate wins deterministically.
        assert_eq!(name_matches[0].address_a, 0x402000);
        assert_eq!(name_matches[0].address_b, 0x501000);
        assert_eq!(result.stats.matched_count, 1);
        assert_eq!(result.unmatched_a.len(), 1);
        assert_eq!(result.unmatched_b.len(), 0);
    }

    /// Regression: duplicate names in B are resolved deterministically
    /// (closest size, then lowest address) instead of last-write-wins.
    #[test]
    fn test_duplicate_names_in_b_resolved_deterministically() {
        let tmp = tempfile::tempdir().unwrap();

        let fa = FunctionEntry::new(0x401000, "sub".to_string(), 20);
        let fb1 = FunctionEntry::new(0x501000, "sub".to_string(), 10);
        let fb2 = FunctionEntry::new(0x502000, "sub".to_string(), 20);

        let db_a = make_db(tmp.path(), "a", vec![fa]);
        let db_b = make_db(tmp.path(), "b", vec![fb1, fb2]);

        let differ = BinaryDiffer::new()
            .disable_size_matching()
            .disable_mnemonic_matching();
        let result = differ.diff(&db_a, &db_b).unwrap();

        let name_matches: Vec<_> = result.matches.iter()
            .filter(|m| m.match_type == MatchType::NameMatch)
            .collect();
        assert_eq!(name_matches.len(), 1);
        assert_eq!(name_matches[0].address_b, 0x502000);
        assert_eq!(result.unmatched_b.len(), 1);
    }
}


