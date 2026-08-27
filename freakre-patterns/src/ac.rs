//! Aho-Corasick multi-pattern string matcher. O(n + m + z) guaranteed.

use crate::{Match, Searcher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyPatternError;

impl core::fmt::Display for EmptyPatternError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AhoCorasick: zero-length patterns are not supported")
    }
}

impl std::error::Error for EmptyPatternError {}

#[derive(Clone)]
struct Node {
    children: [u32; 256], // 0 = no edge (node 0 is root, so we use u32::MAX as sentinel)
    fail: u32,
    output: Vec<usize>,   // pattern indices that end here
}

impl Node {
    fn new() -> Self {
        Self {
            children: [u32::MAX; 256],
            fail: 0,
            output: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct AhoCorasick {
    nodes: Vec<Node>,
    patterns: Vec<Vec<u8>>,
}

impl AhoCorasick {
    /// Build automaton from a list of byte patterns.
    pub fn build(patterns: &[&[u8]]) -> Result<Self, EmptyPatternError> {
        if patterns.iter().any(|p| p.is_empty()) {
            return Err(EmptyPatternError);
        }
        let mut nodes = vec![Node::new()];
        let owned: Vec<Vec<u8>> = patterns.iter().map(|p| p.to_vec()).collect();

        // Insert patterns into trie
        for (pid, pat) in owned.iter().enumerate() {
            let mut cur = 0u32;
            for &byte in pat {
                let b = byte as usize;
                if nodes[cur as usize].children[b] == u32::MAX {
                    nodes.push(Node::new());
                    nodes[cur as usize].children[b] = (nodes.len() - 1) as u32;
                }
                cur = nodes[cur as usize].children[b];
            }
            nodes[cur as usize].output.push(pid);
        }

        // Build failure links via BFS
        let mut queue = std::collections::VecDeque::new();
        // Depth-1 nodes: fail to root
        for b in 0..256usize {
            let child = nodes[0].children[b];
            if child != u32::MAX {
                nodes[child as usize].fail = 0;
                queue.push_back(child);
            } else {
                nodes[0].children[b] = 0; // point missing edges to root
            }
        }

        while let Some(u) = queue.pop_front() {
            for b in 0..256usize {
                let v = nodes[u as usize].children[b];
                if v == u32::MAX {
                    // Set goto to follow fail chain
                    nodes[u as usize].children[b] = nodes[nodes[u as usize].fail as usize].children[b];
                    continue;
                }
                queue.push_back(v);
                let mut f = nodes[u as usize].fail;
                while nodes[f as usize].children[b] == u32::MAX || nodes[f as usize].children[b] == v {
                    f = nodes[f as usize].fail;
                }
                nodes[v as usize].fail = nodes[f as usize].children[b];
                // Merge outputs from fail chain
                let fail_outputs = nodes[nodes[v as usize].fail as usize].output.clone();
                nodes[v as usize].output.extend(fail_outputs);
            }
        }

        Ok(Self { nodes, patterns: owned })
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Streaming overlapping-match iterator: O(1) memory, no upfront Vec.
    pub fn iter_overlapping<'a>(&'a self, haystack: &'a [u8]) -> AcIter<'a> {
        AcIter {
            ac: self,
            haystack,
            pos: 0,
            state: 0,
            pending: Vec::new(),
            pending_idx: 0,
        }
    }

    /// Allocation-free streaming scan: invokes `on_hit(pattern_id, end)` for
    /// every overlapping occurrence, with `end` = exclusive end offset of the
    /// matched literal in `haystack`. Hits are emitted in ascending end order.
    /// Used by the regex prefilter, which needs raw end positions without
    /// per-hit `Match` construction overhead.
    pub fn scan_overlapping<F: FnMut(usize, usize)>(&self, haystack: &[u8], mut on_hit: F) {
        let mut state = 0u32;
        for (i, &byte) in haystack.iter().enumerate() {
            state = self.nodes[state as usize].children[byte as usize];
            let outs = &self.nodes[state as usize].output;
            for &pid in outs {
                on_hit(pid, i + 1);
            }
        }
    }
}

pub struct AcIter<'a> {
    ac: &'a AhoCorasick,
    haystack: &'a [u8],
    pos: usize,
    state: u32,
    pending: Vec<Match>,
    pending_idx: usize,
}

impl<'a> Iterator for AcIter<'a> {
    type Item = Match;

    fn next(&mut self) -> Option<Match> {
        loop {
            if self.pending_idx < self.pending.len() {
                let m = self.pending[self.pending_idx];
                self.pending_idx += 1;
                return Some(m);
            }
            if self.pos >= self.haystack.len() {
                return None;
            }
            let byte = self.haystack[self.pos];
            self.state = self.ac.nodes[self.state as usize].children[byte as usize];
            self.pos += 1;
            let outs = &self.ac.nodes[self.state as usize].output;
            if !outs.is_empty() {
                self.pending = outs
                    .iter()
                    .map(|&pid| {
                        let pat_len = self.ac.patterns[pid].len();
                        Match {
                            pattern_id: pid,
                            start: self.pos - pat_len,
                            end: self.pos,
                        }
                    })
                    .collect();
                self.pending_idx = 0;
            }
        }
    }
}

impl Searcher for AhoCorasick {
    fn find_all(&self, haystack: &[u8]) -> Vec<Match> {
        let mut results = Vec::new();
        let mut state = 0u32;

        for (i, &byte) in haystack.iter().enumerate() {
            state = self.nodes[state as usize].children[byte as usize];
            if !self.nodes[state as usize].output.is_empty() {
                for &pid in &self.nodes[state as usize].output {
                    let pat_len = self.patterns[pid].len();
                    results.push(Match {
                        pattern_id: pid,
                        start: i + 1 - pat_len,
                        end: i + 1,
                    });
                }
            }
        }
        results
    }

    fn is_match(&self, haystack: &[u8]) -> bool {
        let mut state = 0u32;
        for &byte in haystack {
            state = self.nodes[state as usize].children[byte as usize];
            if !self.nodes[state as usize].output.is_empty() {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_search() {
        let ac = AhoCorasick::build(&[b"he", b"she", b"his", b"hers"]).unwrap();
        let matches = ac.find_all(b"ushers");
        assert!(matches.iter().any(|m| m.pattern_id == 1 && m.start == 1)); // "she"
        assert!(matches.iter().any(|m| m.pattern_id == 0 && m.start == 2)); // "he"
        assert!(matches.iter().any(|m| m.pattern_id == 3 && m.start == 2)); // "hers"
    }

    #[test]
    fn test_no_match() {
        let ac = AhoCorasick::build(&[b"xyz"]).unwrap();
        assert!(!ac.is_match(b"abcdef"));
    }

    #[test]
    fn test_binary_patterns() {
        let ac = AhoCorasick::build(&[b"\x90\x90\x90", b"\xCC\xCC"]).unwrap();
        let data = b"\x00\x90\x90\x90\xFF\xCC\xCC";
        let matches = ac.find_all(data);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_empty_pattern_rejected() {
        assert!(AhoCorasick::build(&[b""]).is_err());
        assert!(AhoCorasick::build(&[b"ok", b""]).is_err());
        assert!(AhoCorasick::build(&[]).is_ok());
    }
}
