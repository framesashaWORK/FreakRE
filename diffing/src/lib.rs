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
//! 4. **Topology-based** (`structural_matches`): refine an intra-binary
//!    callgraph similarity iteratively (small-subgraph-matching style) and
//!    match leftover functions whose neighborhoods agree even when names,
//!    sizes and mnemonics do not.
//!
//! ## Topology algorithm (Phase 4, deterministic)
//!
//! Inputs are the address-sorted function slices plus their undirected
//! callgraphs (callees ∪ callers, sorted/deduped, hub-capped at 32
//! neighbors). Pairs already matched by phases 1–3 are *pinned* at their
//! existing similarity and never updated.
//!
//! * **Initialization**: for every pair (a, b), `sim(a,b)` is the pinned
//!   similarity when phases 1–3 agreed on the pair, otherwise a damped
//!   content prior `0.5 · (0.7·size_sim + 0.3·name_sim)` — the same content
//!   signal used today, weakened because these pairs failed earlier phases.
//! * **Refinement** (K = 3 fixed rounds, so cycles always terminate):
//!   `sim(A,B) ← 0.5·sim(A,B) + 0.5·neighbor_affinity`, where
//!   `neighbor_affinity` greedily best-matches the two sorted neighbor
//!   lists under used-sets (Hungarian is deliberately overkill), sums the
//!   chosen pair scores, clamps to `[0,1]`, and normalizes by
//!   `min(32, max(|N(A)|, |N(B)|))` — the cap keeps huge fan-out hubs from
//!   crushing or dominating the term.
//! * **Assignment**: pairs with `sim ≥ 0.65` whose endpoints are still
//!   unmatched are taken greedily by score descending (ties broken by lower
//!   A-index then B-index); each function is consumed once.
//!
//! All scoring walks index-ordered vectors only; no HashMap iteration order
//! participates in any comparison, so results are fully reproducible.

mod callgraph;

use project_db::{ProjectDatabase, FunctionEntry};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::callgraph::CallGraph;

const MAX_DECODED_INSTRUCTIONS: usize = 65536;
const MAX_CONSECUTIVE_DECODE_FAILURES: usize = 32;

/// Fixed number of similarity-propagation rounds (small-subgraph-matching
/// style). Bounded up front so cyclic graphs cannot loop forever.
const STRUCTURAL_REFINEMENT_ROUNDS: usize = 3;

/// Minimum refined similarity for a pair to be eligible as a structural match.
const STRUCTURAL_MATCH_THRESHOLD: f64 = 0.65;

/// Weight of the neighbor term vs. the current similarity during refinement:
/// `new = 0.5·old + 0.5·neighbor_affinity`.
const STRUCTURAL_NEIGHBOR_WEIGHT: f64 = 0.5;

/// Damping applied to the content prior for pairs not matched by phases 1–3.
const STRUCTURAL_PRIOR_DAMPING: f64 = 0.5;

/// Content-prior blend inside the initialization prior (matches the
/// Combined fallback used by the mnemonic phase).
const STRUCTURAL_CONTENT_SIZE_WEIGHT: f64 = 0.7;
const STRUCTURAL_CONTENT_NAME_WEIGHT: f64 = 0.3;

/// Cap on how many neighbor pairs contribute to one node-pair comparison
/// (hub guard on top of [`callgraph::MAX_STORED_NEIGHBORS`]).
const MAX_NEIGHBOR_PAIRS_PER_COMPARISON: usize = 32;

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

/// A topology-only match produced by Phase 4.
///
/// These pairs never appear in `DiffResult::matches`; existing match
/// categories stay untouched for backwards compatibility. The extended
/// input struct is additive: `callees` defaults to `None`, so callers that
/// do not track call targets compile and behave unchanged (Phase 4 then
/// degrades to the content prior and matches nothing).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MatchPair {
    pub address_a: u64,
    pub address_b: u64,
    pub name_a: String,
    pub name_b: String,
    /// Refined structural similarity at assignment time (≥ 0.65).
    pub similarity: f64,
}

/// Diffing-side function descriptor: the subset of `FunctionEntry` used by
/// the matcher, extended additively with optional intra-binary call
/// targets. Constructing this from a `FunctionEntry` leaves `callees`
/// empty; populating it from xrefs is wired by callers, not here.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DiffFunction {
    pub address: u64,
    pub name: String,
    pub size: usize,
    #[serde(default)]
    pub code_bytes: Option<Vec<u8>>,
    /// Callee addresses (intra-binary call targets), when known.
    #[serde(default)]
    pub callees: Option<Vec<u64>>,
}

impl From<&FunctionEntry> for DiffFunction {
    fn from(f: &FunctionEntry) -> Self {
        Self {
            address: f.address,
            name: f.name.clone(),
            size: f.size,
            code_bytes: f.code_bytes.clone(),
            callees: None,
        }
    }
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
    /// Topology-only matches from Phase 4 (functions not matched by the
    /// content phases). Empty unless callees were supplied via
    /// [`DiffFunction`].
    pub structural_matches: Vec<MatchPair>,
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
    /// Number of Phase 4 topology matches (subset of functions left
    /// unmatched by phases 1–3).
    pub matched_by_structure: usize,
    /// Mean similarity across `structural_matches` (0.0 when none).
    pub average_structural_score: f64,
}

/// Binary differ
pub struct BinaryDiffer {
    similarity_threshold: f64,
    use_name_matching: bool,
    use_size_matching: bool,
    use_mnemonic_matching: bool,
    use_structural_matching: bool,
    timeout: Option<Duration>,
}

impl BinaryDiffer {
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.7,
            use_name_matching: true,
            use_size_matching: true,
            use_mnemonic_matching: true,
            use_structural_matching: true,
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

    pub fn disable_structural_matching(mut self) -> Self {
        self.use_structural_matching = false;
        self
    }

    /// Compare two project databases.
    ///
    /// `FunctionEntry` carries no call-target information, so the topology
    /// phase sees callee-less graphs here; use [`BinaryDiffer::diff_functions`]
    /// with populated [`DiffFunction::callees`] to enable structural matching.
    pub fn diff(&self, db_a: &ProjectDatabase, db_b: &ProjectDatabase) -> Result<DiffResult> {
        let funcs_a: Vec<DiffFunction> =
            db_a.list_functions()?.iter().map(DiffFunction::from).collect();
        let funcs_b: Vec<DiffFunction> =
            db_b.list_functions()?.iter().map(DiffFunction::from).collect();
        self.diff_functions(&funcs_a, &funcs_b)
    }

    /// Compare two already-extracted function lists. Slices are sorted by
    /// address internally so all downstream indexing is deterministic.
    ///
    /// Runs phases 1–3 (name → size → mnemonic) and then, for functions
    /// still unmatched, Phase 4 callgraph refinement whose pairs are
    /// reported separately in [`DiffResult::structural_matches`].
    pub fn diff_functions(
        &self,
        funcs_a: &[DiffFunction],
        funcs_b: &[DiffFunction],
    ) -> Result<DiffResult> {
        let deadline = self.timeout.map(|t| Instant::now() + t);

        let mut funcs_a: Vec<DiffFunction> = funcs_a.to_vec();
        let mut funcs_b: Vec<DiffFunction> = funcs_b.to_vec();
        funcs_a.sort_by_key(|f| f.address);
        funcs_b.sort_by_key(|f| f.address);

        if funcs_a.is_empty() || funcs_b.is_empty() {
            return Err(DiffError::NoFunctions);
        }

        self.check_deadline(deadline)?;

        let mut matches: Vec<FunctionMatch> = Vec::new();
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

        self.check_deadline(deadline)?;

        // Phase 4: Callgraph / topology matching over leftovers
        let structural_matches = if self.use_structural_matching {
            let cg_a = CallGraph::build(&funcs_a);
            let cg_b = CallGraph::build(&funcs_b);

            let idx_a: HashMap<u64, usize> = funcs_a
                .iter()
                .enumerate()
                .map(|(i, f)| (f.address, i))
                .collect();
            let idx_b: HashMap<u64, usize> = funcs_b
                .iter()
                .enumerate()
                .map(|(j, f)| (f.address, j))
                .collect();

            // Pairs agreed on by phases 1–3 are pinned at their similarity:
            // they act as fixed anchors during propagation and are excluded
            // from re-assignment.
            let pinned: HashMap<(usize, usize), f64> = matches
                .iter()
                .filter_map(|m| {
                    let i = idx_a.get(&m.address_a)?;
                    let j = idx_b.get(&m.address_b)?;
                    Some(((*i, *j), m.similarity))
                })
                .collect();

            self.match_by_structure(
                &funcs_a,
                &funcs_b,
                &cg_a,
                &cg_b,
                &matched_a,
                &matched_b,
                &pinned,
                deadline,
            )?
        } else {
            Vec::new()
        };

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

        let matched_by_structure = structural_matches.len();
        let average_structural_score = if structural_matches.is_empty() {
            0.0
        } else {
            structural_matches.iter().map(|m| m.similarity).sum::<f64>()
                / structural_matches.len() as f64
        };

        let stats = DiffStats {
            total_functions_a: funcs_a.len(),
            total_functions_b: funcs_b.len(),
            matched_count: matches.len(),
            unmatched_a_count: unmatched_a.len(),
            unmatched_b_count: unmatched_b.len(),
            average_similarity: avg_similarity,
            perfect_matches,
            matched_by_structure,
            average_structural_score,
        };

        Ok(DiffResult {
            matches,
            unmatched_a,
            unmatched_b,
            stats,
            structural_matches,
        })
    }

    /// Match functions by name. Each B-side function is consumed at most
    /// once: candidate pairs are assigned greedily by best size fit
    /// (ties broken by lowest B then A address), so duplicate names on
    /// either side resolve deterministically instead of first-come or
    /// last-write-wins.
    fn match_by_name(&self, funcs_a: &[DiffFunction], funcs_b: &[DiffFunction]) -> Vec<FunctionMatch> {
        let mut b_by_name: HashMap<&str, Vec<&DiffFunction>> = HashMap::new();

        for f in funcs_b {
            b_by_name.entry(&f.name).or_default().push(f);
        }

        let mut pairs: Vec<(usize, u64, u64, &DiffFunction, &DiffFunction)> = Vec::new();
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
        funcs_a: &[&DiffFunction],
        funcs_b: &[&DiffFunction],
        deadline: Option<Instant>,
    ) -> Result<Vec<FunctionMatch>> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        for fa in funcs_a {
            self.check_deadline(deadline)?;
            let mut best_match: Option<(&DiffFunction, f64)> = None;

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
        funcs_a: &[&DiffFunction],
        funcs_b: &[&DiffFunction],
        deadline: Option<Instant>,
    ) -> Result<Vec<FunctionMatch>> {
        let mut matches = Vec::new();
        let mut matched_b = HashSet::new();

        let streams_a = Self::mnemonic_streams(funcs_a);
        let streams_b = Self::mnemonic_streams(funcs_b);

        for fa in funcs_a {
            self.check_deadline(deadline)?;
            let stream_a = streams_a.get(&fa.address);
            let mut best_match: Option<(&DiffFunction, f64, f64, usize, usize, usize)> = None;

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
                let pair = match (stream_a, stream_b) {
                    (Some((ma, a)), Some((mb, b)))
                        if ma == mb && !a.is_empty() && !b.is_empty() =>
                    {
                        Some((a, b))
                    }
                    _ => None,
                };

                let (combined, mnemonic_score, matched_i, total_a, total_b) =
                    if let Some((a, b)) = pair {
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

    /// Phase 4: callgraph similarity refinement and greedy assignment.
    ///
    /// See the module-level documentation for the algorithm. Parameters:
    /// pinned pairs (agreed by phases 1–3) hold their similarity constant
    /// and are excluded from assignment; `matched_a`/`matched_b` keep
    /// already-consumed functions out of the structural output so existing
    /// match categories remain untouched.
    #[allow(clippy::too_many_arguments)]
    fn match_by_structure(
        &self,
        funcs_a: &[DiffFunction],
        funcs_b: &[DiffFunction],
        cg_a: &CallGraph,
        cg_b: &CallGraph,
        matched_a: &HashSet<u64>,
        matched_b: &HashSet<u64>,
        pinned: &HashMap<(usize, usize), f64>,
        deadline: Option<Instant>,
    ) -> Result<Vec<MatchPair>> {
        // Edge case: empty graphs (or fully consumed sides) — nothing to do.
        if funcs_a.is_empty() || funcs_b.is_empty() {
            return Ok(Vec::new());
        }

        let n_a = funcs_a.len();
        let n_b = funcs_b.len();

        // --- Initialization -------------------------------------------------
        let mut sim: Vec<Vec<f64>> = vec![vec![0.0; n_b]; n_a];
        for (i, fa) in funcs_a.iter().enumerate() {
            for (j, fb) in funcs_b.iter().enumerate() {
                sim[i][j] = if let Some(s) = pinned.get(&(i, j)) {
                    *s
                } else {
                    // Damped content prior for pairs that earlier phases did
                    // NOT match together. Note a pair where a is matched to
                    // some other b' still gets the prior here — only exact
                    // pinned agreements are anchors.
                    let content = self.size_similarity(fa.size, fb.size)
                        * STRUCTURAL_CONTENT_SIZE_WEIGHT
                        + self.name_similarity(&fa.name, &fb.name)
                            * STRUCTURAL_CONTENT_NAME_WEIGHT;
                    content * STRUCTURAL_PRIOR_DAMPING
                };
            }
        }

        // --- Iterative refinement (K fixed rounds; cycles terminate) -------
        for _ in 0..STRUCTURAL_REFINEMENT_ROUNDS {
            self.check_deadline(deadline)?;
            let mut next = vec![vec![0.0; n_b]; n_a];
            for i in 0..n_a {
                for j in 0..n_b {
                    next[i][j] = if let Some(s) = pinned.get(&(i, j)) {
                        *s
                    } else {
                        let neighbor_term = Self::neighbor_affinity(
                            &sim,
                            &cg_a.neighbors[i],
                            &cg_b.neighbors[j],
                        );
                        (1.0 - STRUCTURAL_NEIGHBOR_WEIGHT) * sim[i][j]
                            + STRUCTURAL_NEIGHBOR_WEIGHT * neighbor_term
                    };
                }
            }
            sim = next;
        }

        // --- Assignment: greedy by score desc, endpoints used once ----------
        let mut candidates: Vec<(usize, usize)> = (0..n_a)
            .flat_map(|i| (0..n_b).map(move |j| (i, j)))
            .filter(|&(i, j)| {
                sim[i][j] >= STRUCTURAL_MATCH_THRESHOLD
                    && !matched_a.contains(&funcs_a[i].address)
                    && !matched_b.contains(&funcs_b[j].address)
            })
            .collect();

        candidates.sort_by(|&(i1, j1), &(i2, j2)| {
            let ord = sim[i2][j2]
                .partial_cmp(&sim[i1][j1])
                .unwrap_or(std::cmp::Ordering::Equal);
            ord.then(i1.cmp(&i2)).then(j1.cmp(&j2))
        });

        let mut used_a: HashSet<usize> = HashSet::new();
        let mut used_b: HashSet<usize> = HashSet::new();
        let mut out = Vec::new();

        for (i, j) in candidates {
            if !used_a.insert(i) || !used_b.insert(j) {
                continue;
            }
            out.push(MatchPair {
                address_a: funcs_a[i].address,
                address_b: funcs_b[j].address,
                name_a: funcs_a[i].name.clone(),
                name_b: funcs_b[j].name.clone(),
                similarity: sim[i][j],
            });
        }

        Ok(out)
    }

    /// Greedy best-match between two sorted neighbor lists against the
    /// current similarity matrix.
    ///
    /// Repeatedly takes the highest-similarity unused (u, v) combination
    /// (strict-improvement comparison makes ties resolve to the first pair
    /// in index order — deterministic), marks both used, and accumulates.
    /// The sum is normalized by `min(MAX, max(|N_i|, |N_j|))` with MAX =
    /// [`MAX_NEIGHBOR_PAIRS_PER_COMPARISON`]: without the cap a 500-fan-out
    /// hub paired against a 3-callee function would dilute its score toward
    /// zero, and a hub pairing would otherwise also dominate runtime. An
    /// empty neighborhood contributes 0 (neutral-negative), which lets
    /// content evidence decide leaf-only comparisons.
    fn neighbor_affinity(sim: &[Vec<f64>], ni: &[usize], nj: &[usize]) -> f64 {
        if ni.is_empty() || nj.is_empty() {
            return 0.0;
        }

        let wanted = ni.len().min(nj.len());
        let mut used_i = vec![false; ni.len()];
        let mut used_j = vec![false; nj.len()];
        let mut total = 0.0f64;

        for _ in 0..wanted {
            let mut best: Option<(f64, usize, usize)> = None;
            for (ui, &u) in ni.iter().enumerate() {
                if used_i[ui] {
                    continue;
                }
                for (vj, &v) in nj.iter().enumerate() {
                    if used_j[vj] {
                        continue;
                    }
                    let s = sim[u][v];
                    if best.is_none_or(|(bs, _, _)| s > bs) {
                        best = Some((s, ui, vj));
                    }
                }
            }
            let Some((s, ui, vj)) = best else { break };
            used_i[ui] = true;
            used_j[vj] = true;
            total += s.min(1.0);
        }

        let denom = ni.len().max(nj.len()).clamp(1, MAX_NEIGHBOR_PAIRS_PER_COMPARISON);
        (total / denom as f64).clamp(0.0, 1.0)
    }

    /// Decode mnemonic streams once per function, recording the width mode
    /// (64- or 32-bit) each stream was decoded with so pairs are only
    /// compared when both sides used the same mode.
    fn mnemonic_streams(
        funcs: &[&DiffFunction],
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
        let hist = |seq: &[freakre_x86::Mnemonic]| -> HashMap<String, usize> {
            let mut h: HashMap<String, usize> = HashMap::new();
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
    report.push_str(&format!("Perfect matches: {}\n", result.stats.perfect_matches));
    report.push_str(&format!(
        "Structural (topology) matches: {} (avg {:.1}%)\n\n",
        result.stats.matched_by_structure,
        result.stats.average_structural_score * 100.0
    ));

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

    if !result.structural_matches.is_empty() {
        report.push_str("\n=== Structural (Topology) Matches ===\n");
        for m in &result.structural_matches {
            report.push_str(&format!(
                "  0x{:X} ({}) <-> 0x{:X} ({}) [{:.1}%]\n",
                m.address_a, m.name_a,
                m.address_b, m.name_b,
                m.similarity * 100.0
            ));
        }
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
    use crate::callgraph::MAX_STORED_NEIGHBORS;

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

    /// Helper: build a renamed-but-topologically-identical diamond
    ///
    /// ```text
    ///     root          root'
    ///    /     \       /     \
    ///  left   right  left'  right'
    ///    \     /       \    /
    ///     sink          sink'
    /// ```
    ///
    /// `root` and `sink` keep their names (they become pinned anchors via the
    /// name phase); the two mid nodes are renamed and resized so phases 1-3
    /// cannot pair them.
    fn diamond_funcs() -> (Vec<DiffFunction>, Vec<DiffFunction>) {
        let mk = |address: u64, name: &str, size: usize, callees: Vec<u64>| DiffFunction {
            address,
            name: name.to_string(),
            size,
            code_bytes: None,
            callees: Some(callees),
        };

        let (ra, la, ra2, sa) = (0x401000u64, 0x401100u64, 0x401200u64, 0x401300u64);
        let (rb, lb, rb2, sb) = (0x501000u64, 0x501100u64, 0x501200u64, 0x501300u64);

        let a = vec![
            mk(ra, "diamond_source_root", 900, vec![la, ra2]),
            mk(la, "onyx_harbor_lane", 200, vec![sa]),
            mk(ra2, "cobalt_metal_work", 480, vec![sa]),
            mk(sa, "shared_diamond_sink", 600, vec![]),
        ];
        let b = vec![
            mk(rb, "diamond_source_root", 850, vec![lb, rb2]),
            mk(lb, "marble_quartz_run", 190, vec![sb]),
            mk(rb2, "pewter_glass_owl", 460, vec![sb]),
            mk(sb, "shared_diamond_sink", 680, vec![]),
        ];
        (a, b)
    }

    /// Phase 4 must recover the renamed mid nodes of an isomorphic diamond
    /// callgraph even though their names and sizes differ. The shared-name
    /// root/sink act as pinned anchors; content phases 2/3 are disabled so
    /// the structural phase is exercised in isolation.
    #[test]
    fn test_structural_diamond_renamed_funcs_matched() {
        let (funcs_a, funcs_b) = diamond_funcs();

        let differ = BinaryDiffer::new()
            .disable_size_matching()
            .disable_mnemonic_matching();

        let result = differ.diff_functions(&funcs_a, &funcs_b).unwrap();

        // Anchors matched by name only; nothing else leaked into old categories.
        assert_eq!(result.matches.len(), 2);
        assert!(result
            .matches
            .iter()
            .all(|m| m.match_type == MatchType::NameMatch));

        // Both renamed mid nodes recovered structurally, in the correct
        // orientation (left->left', right->right').
        assert_eq!(result.structural_matches.len(), 2);
        let by_a: HashMap<u64, &MatchPair> = result
            .structural_matches
            .iter()
            .map(|m| (m.address_a, m))
            .collect();
        assert_eq!(by_a[&0x401100].address_b, 0x501100); // left <-> left'
        assert_eq!(by_a[&0x401200].address_b, 0x501200); // right <-> right'
        for m in &result.structural_matches {
            assert!(
                m.similarity >= STRUCTURAL_MATCH_THRESHOLD && m.similarity <= 1.0,
                "similarity {} outside [{}, 1.0]",
                m.similarity,
                STRUCTURAL_MATCH_THRESHOLD
            );
        }
        // Names carried through for reporting.
        assert_eq!(by_a[&0x401100].name_a, "onyx_harbor_lane");
        assert_eq!(by_a[&0x401100].name_b, "marble_quartz_run");

        // Stats reflect topology matches additively; legacy fields untouched.
        assert_eq!(result.stats.matched_by_structure, 2);
        assert!(result.stats.average_structural_score >= STRUCTURAL_MATCH_THRESHOLD);
        // Structural matches do not consume functions from the legacy
        // unmatched lists (back-compat).
        assert_eq!(result.stats.unmatched_a_count, 2);
        assert_eq!(result.stats.unmatched_b_count, 2);

        // Determinism: a second run yields bit-identical pairs.
        let again = differ.diff_functions(&funcs_a, &funcs_b).unwrap();
        assert_eq!(again.structural_matches, result.structural_matches);
        assert_eq!(again.stats.matched_by_structure, 2);
    }

    /// A hub with fan-out beyond [`callgraph::MAX_STORED_NEIGHBORS`] plus a
    /// leaf cycle must terminate (fixed K rounds) and stay deterministic;
    /// the truncation cap keeps refinement work bounded.
    #[test]
    fn test_hub_graph_termination_and_determinism() {
        const LEAVES: usize = 40; // > MAX_STORED_NEIGHBORS (32)

        let mut funcs_a = Vec::new();
        let mut funcs_b = Vec::new();

        let hub_a = 0x401000u64;
        let hub_b = 0x501000u64;
        let leaves_a: Vec<u64> = (0..LEAVES).map(|i| 0x401100 + i as u64 * 0x10).collect();
        let leaves_b: Vec<u64> = (0..LEAVES).map(|i| 0x501100 + i as u64 * 0x10).collect();

        // Hub -> every leaf; triangle cycle among the first three leaves.
        let mut hub_callees_a = leaves_a.clone();
        hub_callees_a.push(leaves_a[1]);
        funcs_a.push(DiffFunction {
            address: hub_a,
            name: "hub_a_central_dispatch".to_string(),
            size: 5000,
            code_bytes: None,
            callees: Some(hub_callees_a),
        });
        for (i, &la) in leaves_a.iter().enumerate() {
            // Undirected edges are recorded from callees alone; give each
            // leaf its own callee back into the cycle to close the loop.
            let callee = match i {
                0 => leaves_a[1],
                1 => leaves_a[2],
                2 => leaves_a[0],
                _ => hub_a,
            };
            let mut c = vec![callee];
            if i < 3 {
                c.push(hub_a);
            }
            funcs_a.push(DiffFunction {
                address: la,
                name: format!("spoke_alpha_routine_{:02}", i),
                size: 64 + i,
                code_bytes: None,
                callees: Some(c),
            });
        }

        let mut hub_callees_b = leaves_b.clone();
        hub_callees_b.push(leaves_b[1]);
        funcs_b.push(DiffFunction {
            address: hub_b,
            name: "hub_b_central_dispatch".to_string(),
            size: 4600,
            code_bytes: None,
            callees: Some(hub_callees_b),
        });
        for (i, &lb) in leaves_b.iter().enumerate() {
            let callee = match i {
                0 => leaves_b[1],
                1 => leaves_b[2],
                2 => leaves_b[0],
                _ => hub_b,
            };
            let mut c = vec![callee];
            if i < 3 {
                c.push(hub_b);
            }
            funcs_b.push(DiffFunction {
                address: lb,
                name: format!("spoke_omega_kernel_{:02}", i),
                size: 58 + i,
                code_bytes: None,
                callees: Some(c),
            });
        }

        // All names are distinct across sides, so no content phase can
        // pre-match anything; the bounded timeout proves termination of the
        // fixed-round refinement on a cyclic, high-fan-out graph.
        let differ =
            BinaryDiffer::new()
                .disable_size_matching()
                .disable_mnemonic_matching()
                .with_timeout(Duration::from_secs(30));

        let first = differ.diff_functions(&funcs_a, &funcs_b).unwrap();
        let second = differ.diff_functions(&funcs_a, &funcs_b).unwrap();

        assert_eq!(first.structural_matches, second.structural_matches);
        assert_eq!(
            first.stats.matched_by_structure,
            second.stats.matched_by_structure
        );
        assert_eq!(
            first.stats.average_structural_score,
            second.stats.average_structural_score
        );

        // Graph sanity: the hub's adjacency was truncated to the cap.
        let cg = CallGraph::build(&funcs_a);
        assert_eq!(cg.neighbors[0].len(), MAX_STORED_NEIGHBORS);
    }

    /// Empty inputs must be safe (graceful error at the API boundary, empty
    /// output inside Phase 4), and callee-less descriptors must degrade to
    /// zero structural matches. Also pins the serde back-compat guarantee:
    /// legacy JSON without the `callees` field still deserializes.
    #[test]
    fn test_empty_inputs_and_calleeless_degradation() {
        let differ = BinaryDiffer::new();

        // Empty sides never panic; they surface NoFunctions.
        assert!(matches!(
            differ.diff_functions(&[], &[]),
            Err(DiffError::NoFunctions)
        ));
        let solo = DiffFunction {
            address: 1,
            name: "solo".to_string(),
            size: 16,
            code_bytes: None,
            callees: Some(vec![]),
        };
        assert!(matches!(
            differ.diff_functions(&[solo], &[]),
            Err(DiffError::NoFunctions)
        ));

        // Phase 4 internals on empty graphs return an empty match set.
        let cg = CallGraph::build(&[]);
        assert!(cg.neighbors.is_empty());
        let out = differ.match_by_structure(
            &[],
            &[],
            &cg,
            &cg,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            None,
        );
        assert!(out.unwrap().is_empty());

        // Callee-less functions: topology phase degrades to the content
        // prior and reports nothing structural.
        let a = DiffFunction {
            address: 0x10,
            name: "aaa_legacy_one".to_string(),
            size: 100,
            code_bytes: None,
            callees: None,
        };
        let b = DiffFunction {
            address: 0x20,
            name: "bbb_modern_two".to_string(),
            size: 100,
            code_bytes: None,
            callees: None,
        };
        let res = BinaryDiffer::new()
            .disable_size_matching()
            .disable_mnemonic_matching()
            .diff_functions(std::slice::from_ref(&a), std::slice::from_ref(&b))
            .unwrap();
        assert!(res.structural_matches.is_empty());
        assert_eq!(res.stats.matched_by_structure, 0);
        assert_eq!(res.stats.average_structural_score, 0.0);

        // Legacy serialized descriptors (no `callees` key) deserialize fine.
        let legacy: DiffFunction = serde_json::from_str(
            r#"{"address": 7, "name": "old_func", "size": 32, "code_bytes": null}"#,
        )
        .unwrap();
        assert_eq!(legacy.callees, None);
    }
}


