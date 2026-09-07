use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Cross-reference type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum XrefType {
    /// Function call
    Call,
    /// Unconditional jump
    Jump,
    /// Conditional jump
    ConditionalJump,
    /// Data read
    DataRead,
    /// Data write
    DataWrite,
    /// Instruction pointer (e.g., LEA)
    InstructionPointer,
    /// Offset in data
    Offset,
}

impl std::fmt::Display for XrefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefType::Call => write!(f, "CALL"),
            XrefType::Jump => write!(f, "JUMP"),
            XrefType::ConditionalJump => write!(f, "CJUMP"),
            XrefType::DataRead => write!(f, "READ"),
            XrefType::DataWrite => write!(f, "WRITE"),
            XrefType::InstructionPointer => write!(f, "PTR"),
            XrefType::Offset => write!(f, "OFF"),
        }
    }
}

/// A cross-reference from one address to another
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub xref_type: XrefType,
    pub in_function: Option<u64>, // function containing 'from'
}

impl Xref {
    pub fn new(from: u64, to: u64, xref_type: XrefType) -> Self {
        Self {
            from,
            to,
            xref_type,
            in_function: None,
        }
    }

    pub fn with_function(mut self, func_addr: u64) -> Self {
        self.in_function = Some(func_addr);
        self
    }

    pub fn is_call(&self) -> bool {
        self.xref_type == XrefType::Call
    }

    pub fn is_jump(&self) -> bool {
        matches!(self.xref_type, XrefType::Jump | XrefType::ConditionalJump)
    }

    pub fn is_data(&self) -> bool {
        matches!(
            self.xref_type,
            XrefType::DataRead | XrefType::DataWrite | XrefType::Offset
        )
    }
}

/// Index for fast xref lookups
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct XrefIndex {
    /// from_addr -> list of xrefs from this address
    forward: HashMap<u64, Vec<Xref>>,
    /// to_addr -> list of xrefs to this address
    backward: HashMap<u64, Vec<Xref>>,
}

impl XrefIndex {
    pub fn new() -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
        }
    }

    /// Add a cross-reference
    pub fn add(&mut self, xref: Xref) {
        self.forward
            .entry(xref.from)
            .or_default()
            .push(xref.clone());
        self.backward.entry(xref.to).or_default().push(xref);
    }

    /// Get all xrefs FROM a given address
    pub fn xrefs_from(&self, address: u64) -> &[Xref] {
        self.forward
            .get(&address)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all xrefs TO a given address
    pub fn xrefs_to(&self, address: u64) -> &[Xref] {
        self.backward
            .get(&address)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all addresses that reference the given address
    pub fn callers(&self, address: u64) -> Vec<u64> {
        self.xrefs_to(address)
            .iter()
            .filter(|x| x.is_call())
            .map(|x| x.from)
            .collect()
    }

    /// Get all addresses that the given address calls
    pub fn callees(&self, address: u64) -> Vec<u64> {
        self.xrefs_from(address)
            .iter()
            .filter(|x| x.is_call())
            .map(|x| x.to)
            .collect()
    }

    /// Get all functions that call the given function
    pub fn calling_functions(&self, func_addr: u64) -> HashSet<u64> {
        self.xrefs_to(func_addr)
            .iter()
            .filter(|x| x.is_call())
            .filter_map(|x| x.in_function)
            .collect()
    }

    /// Get all functions called by the given function
    pub fn called_functions(&self, func_addr: u64) -> HashSet<u64> {
        let mut result = HashSet::new();
        // Find all addresses within the function
        // This requires knowing function bounds, so we use in_function
        for xrefs in self.forward.values() {
            for xref in xrefs {
                if xref.in_function == Some(func_addr) && xref.is_call() {
                    result.insert(xref.to);
                }
            }
        }
        result
    }

    /// Remove all xrefs from a given address
    pub fn remove_from(&mut self, address: u64) -> Vec<Xref> {
        if let Some(removed) = self.forward.remove(&address) {
            for xref in &removed {
                if let Some(backward_list) = self.backward.get_mut(&xref.to) {
                    backward_list.retain(|x| x.from != address);
                }
            }
            removed
        } else {
            Vec::new()
        }
    }

    /// Remove all xrefs to a given address
    pub fn remove_to(&mut self, address: u64) -> Vec<Xref> {
        if let Some(removed) = self.backward.remove(&address) {
            for xref in &removed {
                if let Some(forward_list) = self.forward.get_mut(&xref.from) {
                    forward_list.retain(|x| x.to != address);
                }
            }
            removed
        } else {
            Vec::new()
        }
    }

    /// Get total number of xrefs
    pub fn count(&self) -> usize {
        self.forward.values().map(|v| v.len()).sum()
    }

    /// Get all addresses that have outgoing xrefs
    pub fn addresses_with_outgoing(&self) -> Vec<u64> {
        self.forward.keys().copied().collect()
    }

    /// Get all addresses that have incoming xrefs
    pub fn addresses_with_incoming(&self) -> Vec<u64> {
        self.backward.keys().copied().collect()
    }

    /// Find call chains from source to target (BFS, limited depth).
    ///
    /// A global per-node visited set keeps the search from re-expanding a
    /// node across different paths (which would blow up exponentially on
    /// diamond-shaped call graphs), while the per-path check still guarantees
    /// every returned chain is a simple path. The number of reported chains
    /// is capped defensively.
    pub fn find_call_chains(&self, source: u64, target: u64, max_depth: usize) -> Vec<Vec<u64>> {
        const MAX_CHAINS: usize = 256;

        let mut chains = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((source, vec![source]));
        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(source);

        while let Some((current, path)) = queue.pop_front() {
            if current == target && path.len() > 1 {
                chains.push(path);
                if chains.len() >= MAX_CHAINS {
                    break;
                }
                continue;
            }

            if path.len() > max_depth + 1 {
                continue;
            }

            for callee in self.called_functions(current) {
                if !path.contains(&callee) && !visited.contains(&callee) {
                    visited.insert(callee);
                    let mut new_path = path.clone();
                    new_path.push(callee);
                    queue.push_back((callee, new_path));
                }
            }
        }

        chains
    }

    /// Build call graph as adjacency list
    pub fn call_graph(&self) -> HashMap<u64, HashSet<u64>> {
        let mut graph: HashMap<u64, HashSet<u64>> = HashMap::new();

        for (from_addr, xrefs) in &self.forward {
            for xref in xrefs {
                if xref.is_call() {
                    if let Some(func_from) = xref.in_function {
                        graph.entry(func_from).or_default().insert(xref.to);
                    } else {
                        graph.entry(*from_addr).or_default().insert(xref.to);
                    }
                }
            }
        }

        graph
    }

    /// Find functions with no callers (potential entry points or dead code)
    pub fn orphan_functions(&self, all_functions: &[u64]) -> Vec<u64> {
        all_functions
            .iter()
            .filter(|&&addr| self.xrefs_to(addr).iter().all(|x| !x.is_call()))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xref_add_and_query() {
        let mut index = XrefIndex::new();

        let xref = Xref::new(0x1000, 0x2000, XrefType::Call).with_function(0x1000);
        index.add(xref);

        assert_eq!(index.xrefs_from(0x1000).len(), 1);
        assert_eq!(index.xrefs_to(0x2000).len(), 1);
        assert_eq!(index.callers(0x2000), vec![0x1000]);
    }

    #[test]
    fn test_multiple_xrefs() {
        let mut index = XrefIndex::new();

        // Function at 0x1000 calls 0x2000 and 0x3000
        index.add(Xref::new(0x1010, 0x2000, XrefType::Call).with_function(0x1000));
        index.add(Xref::new(0x1020, 0x3000, XrefType::Call).with_function(0x1000));

        // Note: callees looks at xrefs_from the function address, not within it
        // We need to check called_functions instead
        let called = index.called_functions(0x1000);
        assert!(called.contains(&0x2000));
        assert!(called.contains(&0x3000));
    }

    #[test]
    fn test_call_graph() {
        let mut index = XrefIndex::new();

        // main -> foo -> bar
        index.add(Xref::new(0x1010, 0x2000, XrefType::Call).with_function(0x1000));
        index.add(Xref::new(0x2010, 0x3000, XrefType::Call).with_function(0x2000));

        let graph = index.call_graph();
        assert!(graph.get(&0x1000).unwrap().contains(&0x2000));
        assert!(graph.get(&0x2000).unwrap().contains(&0x3000));
    }

    #[test]
    fn test_find_call_chains() {
        let mut index = XrefIndex::new();

        // A -> B -> C -> D
        index.add(Xref::new(0xA, 0xB, XrefType::Call).with_function(0xA));
        index.add(Xref::new(0xB, 0xC, XrefType::Call).with_function(0xB));
        index.add(Xref::new(0xC, 0xD, XrefType::Call).with_function(0xC));

        let chains = index.find_call_chains(0xA, 0xD, 5);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0], vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_find_call_chains_diamond_terminates_and_finds_chain() {
        let mut index = XrefIndex::new();

        // Layered diamond: each layer function n_i calls two helpers, both of
        // which call the next layer's function. A path-enumerating search
        // yields 2^LAYERS chains; the visited-set search must terminate
        // quickly and still report a valid chain.
        const LAYERS: u64 = 12;
        let n = |i: u64| 0x1000 + i * 0x100;
        let m = |i: u64, branch: u64| 0x1000 + i * 0x100 + 0x10 + branch;

        for i in 0..LAYERS {
            index.add(Xref::new(n(i), m(i, 0), XrefType::Call).with_function(n(i)));
            index.add(Xref::new(n(i), m(i, 1), XrefType::Call).with_function(n(i)));
            index.add(Xref::new(m(i, 0), n(i + 1), XrefType::Call).with_function(m(i, 0)));
            index.add(Xref::new(m(i, 1), n(i + 1), XrefType::Call).with_function(m(i, 1)));
        }

        let chains = index.find_call_chains(n(0), n(LAYERS), 128);

        assert!(!chains.is_empty(), "at least one chain must be found");
        assert!(chains.len() <= 256, "path cap respected");
        let chain = &chains[0];
        assert_eq!(chain.first(), Some(&n(0)));
        assert_eq!(chain.last(), Some(&n(LAYERS)));
        // Every returned chain is a simple path.
        for chain in &chains {
            let mut seen = std::collections::HashSet::new();
            assert!(chain.iter().all(|a| seen.insert(*a)));
        }
    }
}
