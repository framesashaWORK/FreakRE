//! Worklist algorithm infrastructure for monotone data flow frameworks.
//!
//! All analyses use iterative fixed-point computation with a worklist
//! to efficiently propagate information through the CFG.

use std::collections::BTreeSet;

/// A monotone framework fact — a set of elements that grows monotonically.
pub type Fact<T> = BTreeSet<T>;
type Facts<T> = Vec<Fact<T>>;

/// Direction of analysis: forward or backward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Forward analysis: information flows from predecessors.
    /// Examples: reaching definitions, available expressions.
    Forward,
    /// Backward analysis: information flows from successors.
    /// Examples: live variables, very busy expressions.
    Backward,
}

/// A monotone data flow analysis framework.
///
/// The framework computes fixed-point solutions using the worklist algorithm.
/// Users implement the `Framework` trait to define:
/// - The set of "elements" in each fact
/// - The transfer function (how facts change at each block)
/// - The confluence operator (how facts merge at join points)
pub trait Framework {
    /// The type of individual elements in a fact.
    type Element: Ord + Clone + std::fmt::Debug;

    /// Analysis direction.
    fn direction(&self) -> Direction;

    /// Initial fact for the entry (forward) or exit (backward) block.
    /// Usually empty set or a set of boundary conditions.
    fn boundary_fact(&self) -> Fact<Self::Element>;

    /// Transfer function: given input fact and block index, produce output fact.
    fn transfer(&self, block_idx: usize, input: &Fact<Self::Element>) -> Fact<Self::Element>;

    /// Confluence: merge facts from multiple predecessors/successors.
    /// Typically union (∪) for may-analyses, intersection (∩) for must-analyses.
    fn confluence(&self, facts: &[&Fact<Self::Element>]) -> Fact<Self::Element>;

    /// Initial fact for all non-boundary blocks. Typically empty set.
    fn initial_fact(&self) -> Fact<Self::Element> {
        Fact::new()
    }
}

/// Worklist-based fixed-point solver.
pub struct WorklistSolver<F: Framework> {
    framework: F,
    /// Number of blocks in the CFG.
    num_blocks: usize,
    /// Predecessor indices for each block (forward) or successor indices (backward).
    deps: Vec<Vec<usize>>,
    /// Reverse adjacency list: successors for forward analysis, predecessors for backward.
    /// FIXED: Precomputed to avoid O(n²) linear scan when finding successors/predecessors.
    reverse_deps: Vec<Vec<usize>>,
    /// IN facts for each block.
    in_facts: Vec<Fact<F::Element>>,
    /// OUT facts for each block.
    out_facts: Vec<Fact<F::Element>>,
    /// Maximum iterations before giving up.
    max_iterations: usize,
    /// Number of iterations actually performed.
    iterations: usize,
}

impl<F: Framework> WorklistSolver<F> {
    /// Create a new solver for the given framework and CFG size.
    ///
    /// `deps` maps each block index to its predecessors (forward)
    /// or successors (backward).
    pub fn new(framework: F, num_blocks: usize, deps: Vec<Vec<usize>>) -> Self {
        let initial = framework.initial_fact();
        let in_facts = vec![initial.clone(); num_blocks];
        let out_facts = vec![initial; num_blocks];

        // FIXED: Precompute reverse adjacency list to avoid O(n²) successor lookup
        // in forward analysis. For forward: deps[i] = predecessors of i,
        // so reverse_deps[i] = successors of i (blocks that have i in their deps).
        // For backward: deps[i] = successors of i,
        // so reverse_deps[i] = predecessors of i (same as deps[i]).
        let mut reverse_deps = vec![Vec::new(); num_blocks];
        match framework.direction() {
            Direction::Forward => {
                for (block, preds) in deps.iter().enumerate() {
                    for &pred in preds {
                        if pred < num_blocks {
                            reverse_deps[pred].push(block);
                        }
                    }
                }
            }
            Direction::Backward => {
                // For backward analysis, deps already contains successors,
                // and we need predecessors (which are the blocks whose deps contain us).
                // But actually for backward, the worklist adds deps[block_idx] directly,
                // so reverse_deps is not needed. We still build it for consistency.
                for (block, succs) in deps.iter().enumerate() {
                    for &succ in succs {
                        if succ < num_blocks {
                            reverse_deps[succ].push(block);
                        }
                    }
                }
            }
        }

        WorklistSolver {
            framework,
            num_blocks,
            deps,
            reverse_deps,
            in_facts,
            out_facts,
            max_iterations: num_blocks.saturating_mul(50).max(1000),
            iterations: 0,
        }
    }

    /// Set maximum iterations (default: 1000).
    pub fn set_max_iterations(&mut self, max: usize) {
        self.max_iterations = max;
    }

    /// Solve the framework equations to fixed point.
    ///
    /// Returns `true` if convergence was reached within `max_iterations`.
    pub fn solve(&mut self) -> bool {
        // Guard: a function may contain zero blocks; nothing to solve.
        if self.num_blocks == 0 {
            return true;
        }

        // Set boundary condition
        let boundary = self.framework.boundary_fact();
        match self.framework.direction() {
            Direction::Forward => {
                self.in_facts[0] = boundary;
                self.out_facts[0] = self.framework.transfer(0, &self.in_facts[0]);
            }
            Direction::Backward => {
                // For backward, boundary is at exit blocks (blocks with no successors)
                for i in 0..self.num_blocks {
                    if self.deps[i].is_empty() {
                        self.out_facts[i] = boundary.clone();
                        self.in_facts[i] = self.framework.transfer(i, &self.out_facts[i]);
                    }
                }
            }
        }

        // Initialise worklist with all blocks
        let mut worklist: BTreeSet<usize> = (0..self.num_blocks).collect();
        let direction = self.framework.direction();

        while let Some(block_idx) = worklist.pop_first() {
            self.iterations += 1;
            if self.iterations > self.max_iterations {
                return false;
            }

            // Compute new IN fact (forward) or OUT fact (backward) from dependencies.
            // Forward: IN[b] = ⋃ OUT[pred]; Backward: OUT[b] = ⋃ IN[succ].
            let dep_facts: Vec<&Fact<F::Element>> = self.deps[block_idx]
                .iter()
                .map(|&dep| match direction {
                    Direction::Forward => &self.out_facts[dep],
                    Direction::Backward => &self.in_facts[dep],
                })
                .collect();

            let new_fact = if dep_facts.is_empty() {
                // Entry block (forward) or exit block (backward): boundary condition
                self.framework.boundary_fact()
            } else {
                self.framework.confluence(&dep_facts)
            };

            // Store the merged fact, then ALWAYS apply the transfer function to
            // get the opposite-side fact (OUT for forward, IN for backward).
            // Facts start at the initial (usually empty) state, so a confluence
            // result equal to the current fact does not imply that transfer has
            // ever run for this block; skipping it would leave OUT/IN stale.
            let changed = match direction {
                Direction::Forward => {
                    let old = std::mem::replace(&mut self.in_facts[block_idx], new_fact);
                    self.out_facts[block_idx] = self
                        .framework
                        .transfer(block_idx, &self.in_facts[block_idx]);
                    self.in_facts[block_idx] != old
                }
                Direction::Backward => {
                    let old = std::mem::replace(&mut self.out_facts[block_idx], new_fact);
                    self.in_facts[block_idx] = self
                        .framework
                        .transfer(block_idx, &self.out_facts[block_idx]);
                    self.out_facts[block_idx] != old
                }
            };

            if changed {
                // Add successors (forward) or predecessors (backward) to worklist
                for &next in &self.reverse_deps[block_idx] {
                    worklist.insert(next);
                }
            }
        }

        true
    }

    /// Get the IN fact for a block.
    pub fn in_fact(&self, block_idx: usize) -> &Fact<F::Element> {
        &self.in_facts[block_idx]
    }

    /// Get the OUT fact for a block.
    pub fn out_fact(&self, block_idx: usize) -> &Fact<F::Element> {
        &self.out_facts[block_idx]
    }

    /// Number of iterations performed.
    pub fn iterations(&self) -> usize {
        self.iterations
    }

    /// Consume solver and return (in_facts, out_facts).
    pub fn into_facts(self) -> (Facts<F::Element>, Facts<F::Element>) {
        (self.in_facts, self.out_facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test: count blocks reachable from entry.
    struct ReachabilityFramework;

    impl Framework for ReachabilityFramework {
        type Element = usize;

        fn direction(&self) -> Direction {
            Direction::Forward
        }

        fn boundary_fact(&self) -> Fact<usize> {
            let mut f = Fact::new();
            f.insert(0); // Entry block is reachable
            f
        }

        fn transfer(&self, block_idx: usize, input: &Fact<usize>) -> Fact<usize> {
            let mut out = input.clone();
            out.insert(block_idx);
            out
        }

        fn confluence(&self, facts: &[&Fact<usize>]) -> Fact<usize> {
            let mut result = Fact::new();
            for f in facts {
                result.extend(f.iter().cloned());
            }
            result
        }
    }

    #[test]
    fn test_worklist_solver() {
        // Simple CFG: 0 → 1 → 2
        let deps = vec![
            vec![],  // block 0: no predecessors
            vec![0], // block 1: predecessor 0
            vec![1], // block 2: predecessor 1
        ];

        let mut solver = WorklistSolver::new(ReachabilityFramework, 3, deps);
        assert!(solver.solve());
        assert!(solver.iterations() > 0);

        // All blocks should be reachable
        assert!(solver.out_fact(0).contains(&0));
        assert!(solver.out_fact(1).contains(&0));
        assert!(solver.out_fact(1).contains(&1));
        assert!(solver.out_fact(2).contains(&0));
        assert!(solver.out_fact(2).contains(&1));
        assert!(solver.out_fact(2).contains(&2));
    }
}
