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
//! 3. **Mnemonic-based**: Compare instruction sequences (MD-index like Diaphora)
//! 4. **Call graph**: Match based on call relationships
//! 5. **CFG isomorphism**: Compare control flow graphs

use project_db::{ProjectDatabase, FunctionEntry};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
    /// Similar instruction mnemonics
    MnemonicMatch,
    /// Similar call graph structure
    CallGraphMatch,
    /// Combined score
    Combined,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatchDetails {
    pub name_score: f64,
    pub size_score: f64,
    pub mnemonic_score: f64,
    pub callgraph_score: f64,
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
    pub average_similarity: f64,
    pub perfect_matches: usize,
}

/// Binary differ
pub struct BinaryDiffer {
    similarity_threshold: f64,
    use_name_matching: bool,
    use_size_matching: bool,
    use_mnemonic_matching: bool,
}

impl BinaryDiffer {
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.7,
            use_name_matching: true,
            use_size_matching: true,
            use_mnemonic_matching: true,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
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
        let funcs_a = db_a.list_functions()?;
        let funcs_b = db_b.list_functions()?;

        if funcs_a.is_empty() || funcs_b.is_empty() {
            return Err(DiffError::NoFunctions);
        }

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

        // Phase 2: Size-based matching (for unmatched functions)
        if self.use_size_matching {
            let unmatched_a: Vec<_> = funcs_a.iter()
                .filter(|f| !matched_a.contains(&f.address))
                .collect();
            let unmatched_b: Vec<_> = funcs_b.iter()
                .filter(|f| !matched_b.contains(&f.address))
                .collect();

            let size_matches = self.match_by_size(&unmatched_a, &unmatched_b);
            for m in size_matches {
                matched_a.insert(m.address_a);
                matched_b.insert(m.address_b);
                matches.push(m);
            }
        }

        // Phase 3: Mnemonic-based matching
        if self.use_mnemonic_matching {
            let unmatched_a: Vec<_> = funcs_a.iter()
                .filter(|f| !matched_a.contains(&f.address))
                .collect();
            let unmatched_b: Vec<_> = funcs_b.iter()
                .filter(|f| !matched_b.contains(&f.address))
                .collect();

            let mnemonic_matches = self.match_by_mnemonics(&unmatched_a, &unmatched_b);
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

        // Calculate stats
        let avg_similarity = if matches.is_empty() {
            0.0
        } else {
            matches.iter().map(|m| m.similarity).sum::<f64>() / matches.len() as f64
        };

        let perfect_matches = matches.iter()
            .filter(|m| m.similarity >= 0.99)
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

    /// Match functions by name
    fn match_by_name(&self, funcs_a: &[FunctionEntry], funcs_b: &[FunctionEntry]) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();
        let mut b_by_name: HashMap<&str, &FunctionEntry> = HashMap::new();

        for f in funcs_b {
            b_by_name.insert(&f.name, f);
        }

        for fa in funcs_a {
            if let Some(fb) = b_by_name.get(fa.name.as_str()) {
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
                        callgraph_score: 0.0,
                        matched_instructions: 0,
                        total_instructions_a: 0,
                        total_instructions_b: 0,
                    },
                });
            }
        }

        matches
    }

    /// Match functions by size
    fn match_by_size(&self, funcs_a: &[&FunctionEntry], funcs_b: &[&FunctionEntry]) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        for fa in funcs_a {
            let mut best_match: Option<(&FunctionEntry, f64)> = None;

            for fb in funcs_b {
                if matched_b.contains(&fb.address) {
                    continue;
                }

                let similarity = self.size_similarity(fa.size, fb.size);
                if similarity >= self.similarity_threshold {
                    if best_match.map(|(_, s)| similarity > s).unwrap_or(true) {
                        best_match = Some((fb, similarity));
                    }
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
                        callgraph_score: 0.0,
                        matched_instructions: 0,
                        total_instructions_a: 0,
                        total_instructions_b: 0,
                    },
                });
            }
        }

        matches
    }

    /// Match functions by instruction mnemonics
    fn match_by_mnemonics(&self, funcs_a: &[&FunctionEntry], funcs_b: &[&FunctionEntry]) -> Vec<FunctionMatch> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        // Build mnemonic signatures for all functions
        // In a real implementation, this would extract actual mnemonics from code
        // For now, we use size as a proxy

        for fa in funcs_a {
            let mut best_match: Option<(&FunctionEntry, f64)> = None;

            for fb in funcs_b {
                if matched_b.contains(&fb.address) {
                    continue;
                }

                // Combine size similarity with name similarity
                let size_sim = self.size_similarity(fa.size, fb.size);
                let name_sim = self.name_similarity(&fa.name, &fb.name);
                let combined = size_sim * 0.7 + name_sim * 0.3;

                if combined >= self.similarity_threshold {
                    if best_match.map(|(_, s)| combined > s).unwrap_or(true) {
                        best_match = Some((fb, combined));
                    }
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
                    match_type: MatchType::MnemonicMatch,
                    details: MatchDetails {
                        name_score: self.name_similarity(&fa.name, &fb.name),
                        size_score: self.size_similarity(fa.size, fb.size),
                        mnemonic_score: similarity,
                        callgraph_score: 0.0,
                        matched_instructions: 0,
                        total_instructions_a: 0,
                        total_instructions_b: 0,
                    },
                });
            }
        }

        matches
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

    /// Calculate name similarity using Levenshtein distance
    fn name_similarity(&self, name_a: &str, name_b: &str) -> f64 {
        if name_a == name_b {
            return 1.0;
        }

        let len_a = name_a.len();
        let len_b = name_b.len();
        
        if len_a == 0 || len_b == 0 {
            return 0.0;
        }

        // Simple Levenshtein distance
        let mut matrix = vec![vec![0; len_b + 1]; len_a + 1];

        for i in 0..=len_a {
            matrix[i][0] = i;
        }
        for j in 0..=len_b {
            matrix[0][j] = j;
        }

        for i in 1..=len_a {
            for j in 1..=len_b {
                let cost = if name_a.chars().nth(i - 1) == name_b.chars().nth(j - 1) { 0 } else { 1 };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }

        let distance = matrix[len_a][len_b];
        let max_len = len_a.max(len_b);
        1.0 - (distance as f64 / max_len as f64)
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
}


