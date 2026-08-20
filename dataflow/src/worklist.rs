//! Worklist algorithm infrastructure for monotone data flow frameworks.
//!
//! All analyses use iterative fixed-point computation with a worklist
//! to efficiently propagate information through the CFG.

use std::collections::BTreeSet;

/// A monotone framework fact — a set of elements that grows monotonically.
pub type Fact<T> = BTreeSet<T>;

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

        WorklistSolver {
            framework,
            num_blocks,
            deps,
            in_facts,
            out_facts,
            max_iterations: 1000,
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

        while let Some(block_idx) = worklist.pop_first() {
            self.iterations += 1;
            if self.iterations > self.max_iterations {
                return false;
            }

            // Compute new IN fact from dependencies
            let dep_facts: Vec<&Fact<F::Element>> = self.deps[block_idx]
                .iter()
                .map(|&dep| match self.framework.direction() {
                    Direction::Forward => &self.out_facts[dep],
                    Direction::Backward => &self.in_facts[dep],
                })
                .collect();

            let new_in = if dep_facts.is_empty() {
                // Entry block (forward) or exit block (backward)
                match self.framework.direction() {
                    Direction::Forward => self.in_facts[block_idx].clone(),
                    Direction::Backward => self.out_facts[block_idx].clone(),
                }
            } else {
                self.framework.confluence(&dep_facts)
            };

            // Check if IN changed
            let old_in = std::mem::replace(&mut self.in_facts[block_idx], new_in);
            if self.in_facts[block_idx] != old_in {
                // Recompute OUT
                let new_out = self.framework.transfer(block_idx, &self.in_facts[block_idx]);
                if new_out != self.out_facts[block_idx] {
                    self.out_facts[block_idx] = new_out;
                    // Add successors (forward) or predecessors (backward) to worklist
                    match self.framework.direction() {
                        Direction::Forward => {
                            // Successors = blocks that have block_idx in their deps
                            for (other, deps) in self.deps.iter().enumerate() {
                                if deps.contains(&block_idx) {
                                    worklist.insert(other);
                                }
                            }
                        }
                        Direction::Backward => {
                            // Predecessors = deps of this block
                            for &dep in &self.deps[block_idx] {
                                worklist.insert(dep);
                            }
                        }
                    }
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
    pub fn into_facts(self) -> (Vec<Fact<F::Element>>, Vec<Fact<F::Element>>) {
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
            vec![],    // block 0: no predecessors
            vec![0],   // block 1: predecessor 0
            vec![1],   // block 2: predecessor 1
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
