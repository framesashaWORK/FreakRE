//! Intra-binary callgraph construction for topology-aware diffing (Phase 4).
//!
//! The graph is built from the optional `callees` lists carried on
//! [`DiffFunction`]. Only intra-binary edges are kept: a callee address that
//! does not resolve to a known function on the same side is ignored, and
//! self-edges are dropped.
//!
//! Determinism: node indices follow the address-sorted function slice, and
//! every adjacency list is sorted + deduplicated before use, so no HashMap
//! iteration order can influence scoring. Fan-out hubs are capped by
//! truncating each adjacency list to the lowest-address `MAX_STORED_NEIGHBORS`
//! entries, which bounds refinement work and prevents a single hub from
//! dominating the neighbor signal.

use std::collections::BTreeMap;

use crate::DiffFunction;

/// Maximum neighbors retained per node (hub fan-out cap).
pub(crate) const MAX_STORED_NEIGHBORS: usize = 32;

/// Undirected view of the intra-binary callgraph: `neighbors[i]` holds the
/// sorted, deduplicated indices of callees *and* callers of function `i`.
///
/// Callers are folded in because similarity propagates over call relations
/// in both directions (a callee of a matched pair is evidence, and so is a
/// caller), mirroring BinDiff-lite structural scoring.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallGraph {
    pub neighbors: Vec<Vec<usize>>,
}

impl CallGraph {
    /// Build the graph for an address-sorted function slice. Empty input
    /// yields an empty graph; refinement treats missing neighbors as a
    /// zero contribution rather than an error.
    pub fn build(funcs: &[DiffFunction]) -> Self {
        let index: BTreeMap<u64, usize> = funcs
            .iter()
            .enumerate()
            .map(|(i, f)| (f.address, i))
            .collect();

        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); funcs.len()];
        for (i, f) in funcs.iter().enumerate() {
            let Some(callees) = f.callees.as_deref() else {
                continue;
            };
            for &callee in callees {
                if let Some(&j) = index.get(&callee) {
                    if j != i {
                        // Undirected: record the edge on both endpoints.
                        adj[i].push(j);
                        adj[j].push(i);
                    }
                }
            }
        }

        for list in &mut adj {
            list.sort_unstable();
            list.dedup();
            list.truncate(MAX_STORED_NEIGHBORS);
        }

        Self { neighbors: adj }
    }
}
