#![allow(dead_code, unused_assignments)]
//! # xrefs — Cross-Reference Engine
//!
//! Builds and queries cross-references between code locations and data targets
//! (strings, imports, addresses) within a binary. This is the foundation for
//! answering "which function references this suspicious string/API?" — a core
//! capability in IDA Pro and Ghidra.
//!
//! ## Design
//! - **Zero-copy target registration**: targets reference the original buffer
//! - **Fast lookup**: HashMap-based index from target → set of source offsets
//! - **Correlation API**: combine string xrefs + import xrefs to find functions
//!   that reference *both* a suspicious string AND a dangerous API

use serde::Serialize;
use std::collections::HashMap;

// ─── Types ────────────────────────────────────────────────────────────

/// What kind of entity is being referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum XrefTargetKind {
    /// An extracted ASCII/UTF-16 string.
    String,
    /// An imported function name.
    Import,
    /// A raw byte pattern (e.g., magic bytes, shellcode signature).
    Pattern,
    /// A virtual address or RVA.
    Address,
}

impl std::fmt::Display for XrefTargetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Import => write!(f, "import"),
            Self::Pattern => write!(f, "pattern"),
            Self::Address => write!(f, "address"),
        }
    }
}

/// A single cross-reference: "source at offset X references target Y".
#[derive(Debug, Clone, Serialize)]
pub struct Xref {
    /// Byte offset in the binary where the reference occurs.
    pub source_offset: usize,
    /// Optional section name containing the source (if known).
    pub source_section: Option<String>,
    /// The target being referenced.
    pub target: XrefTarget,
}

/// Identifies what is being referenced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct XrefTarget {
    /// Kind of target.
    pub kind: XrefTargetKind,
    /// Human-readable label (string value, import name, hex pattern, etc.).
    pub label: String,
    /// Byte offset of the target data within the binary (for strings/patterns).
    pub target_offset: Option<usize>,
}

impl std::fmt::Display for XrefTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.kind, self.label)?;
        if let Some(off) = self.target_offset {
            write!(f, " @ 0x{:X}", off)?;
        }
        Ok(())
    }
}

/// Result of correlating multiple xref sets.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedXref {
    /// Source offset that references ALL queried targets.
    pub source_offset: usize,
    /// Section containing this source (if known).
    pub source_section: Option<String>,
    /// All targets matched at this location.
    pub targets: Vec<XrefTarget>,
}

/// Summary statistics for an xref database.
#[derive(Debug, Clone, Serialize)]
pub struct XrefSummary {
    pub total_xrefs: usize,
    pub unique_targets: usize,
    pub string_xrefs: usize,
    pub import_xrefs: usize,
    pub pattern_xrefs: usize,
    pub address_xrefs: usize,
}

// ─── XrefDatabase ─────────────────────────────────────────────────────

/// In-memory cross-reference database.
///
/// Internally stores xrefs indexed by target label for O(1) lookup.
#[derive(Debug, Clone)]
pub struct XrefDatabase {
    /// Primary index: target label → list of xrefs pointing to it.
    by_target: HashMap<String, Vec<Xref>>,
    /// Reverse index: source offset → list of targets referenced from there.
    by_source: HashMap<usize, Vec<XrefTarget>>,
    /// Total xref count.
    total: usize,
}

impl XrefDatabase {
    /// Create an empty xref database.
    pub fn new() -> Self {
        Self {
            by_target: HashMap::new(),
            by_source: HashMap::new(),
            total: 0,
        }
    }

    /// Add a single cross-reference.
    pub fn add(&mut self, xref: Xref) {
        let key = xref.target.label.clone();
        self.by_target
            .entry(key)
            .or_default()
            .push(xref.clone());
        self.by_source
            .entry(xref.source_offset)
            .or_default()
            .push(xref.target);
        self.total += 1;
    }

    /// Batch-add xrefs.
    pub fn add_all(&mut self, xrefs: impl IntoIterator<Item = Xref>) {
        for xref in xrefs {
            self.add(xref);
        }
    }

    /// Find all xrefs TO a specific target label.
    pub fn xrefs_to(&self, target_label: &str) -> &[Xref] {
        self.by_target
            .get(target_label)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Find all targets referenced FROM a specific source offset.
    pub fn xrefs_from(&self, source_offset: usize) -> &[XrefTarget] {
        self.by_source
            .get(&source_offset)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Find all xrefs whose target label contains the given substring (case-insensitive).
    pub fn xrefs_to_containing(&self, substring: &str) -> Vec<&Xref> {
        let sub_lower = substring.to_lowercase();
        self.by_target
            .iter()
            .filter(|(key, _)| key.to_lowercase().contains(&sub_lower))
            .flat_map(|(_, xrefs)| xrefs.iter())
            .collect()
    }

    /// Find all xrefs of a specific kind.
    pub fn xrefs_by_kind(&self, kind: XrefTargetKind) -> Vec<&Xref> {
        self.by_target
            .values()
            .flat_map(|xrefs| xrefs.iter())
            .filter(|x| x.target.kind == kind)
            .collect()
    }

    /// Correlate: find source offsets that reference ALL of the given target labels.
    ///
    /// This is the key malware analysis query: "find code locations that reference
    /// both 'cmd.exe' AND 'CreateProcessA'" → likely reverse shell.
    pub fn correlate(&self, target_labels: &[&str]) -> Vec<CorrelatedXref> {
        if target_labels.is_empty() {
            return Vec::new();
        }

        // Collect source offsets for each target
        let mut source_sets: Vec<std::collections::HashSet<usize>> = Vec::with_capacity(target_labels.len());
        for label in target_labels {
            let xrefs = self.xrefs_to(label);
            let set: std::collections::HashSet<usize> = xrefs.iter().map(|x| x.source_offset).collect();
            source_sets.push(set);
        }

        // Intersect all sets
        let mut intersection = source_sets[0].clone();
        for set in &source_sets[1..] {
            intersection = intersection.intersection(set).copied().collect();
        }

        // Build correlated results
        let mut results: Vec<CorrelatedXref> = intersection
            .into_iter()
            .map(|offset| {
                let targets: Vec<XrefTarget> = target_labels
                    .iter()
                    .filter_map(|label| {
                        self.xrefs_to(label)
                            .iter()
                            .find(|x| x.source_offset == offset)
                            .map(|x| x.target.clone())
                    })
                    .collect();

                let section = self
                    .by_source
                    .get(&offset)
                    .and_then(|_| None); // Section info would come from PE/ELF context

                CorrelatedXref {
                    source_offset: offset,
                    source_section: section,
                    targets,
                }
            })
            .collect();

        results.sort_by_key(|c| c.source_offset);
        results
    }

    /// Get summary statistics.
    pub fn summary(&self) -> XrefSummary {
        let all_xrefs: Vec<&Xref> = self.by_target.values().flat_map(|v| v.iter()).collect();
        XrefSummary {
            total_xrefs: self.total,
            unique_targets: self.by_target.len(),
            string_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::String).count(),
            import_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Import).count(),
            pattern_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Pattern).count(),
            address_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Address).count(),
        }
    }

    /// Number of xrefs in the database.
    pub fn len(&self) -> usize {
        self.total
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl Default for XrefDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Builder helpers ──────────────────────────────────────────────────

/// Build xrefs from extracted strings by scanning the binary for each string's
/// raw bytes appearing at non-string locations (i.e., code/data referencing the string).
///
/// Uses `memchr::memmem` for O(n+m) substring search instead of naive O(n*m).
pub fn build_string_xrefs(
    data: &[u8],
    strings: &[str_extract::ExtractedString<'_>],
) -> Vec<Xref> {
    let mut xrefs = Vec::new();

    // Build a single multi-pattern finder for all strings at once.
    // Fall back to per-string search if Aho-Corasick isn't available here.
    for s in strings {
        let needle = s.raw_bytes;
        if needle.is_empty() || needle.len() > data.len() {
            continue;
        }

        let finder = memchr::memmem::Finder::new(needle);
        for abs_pos in finder.find_iter(data) {
            // Skip the string's own location (a string doesn't xref itself)
            if abs_pos == s.offset {
                continue;
            }

            xrefs.push(Xref {
                source_offset: abs_pos,
                source_section: None,
                target: XrefTarget {
                    kind: XrefTargetKind::String,
                    label: s.value.clone(),
                    target_offset: Some(s.offset),
                },
            });
        }
    }

    xrefs
}

/// Build xrefs from import names by scanning for their ASCII representation
/// in the binary (IAT entries, string references in code, etc.).
///
/// Uses `memchr::memmem` for efficient O(n+m) search per import name.
pub fn build_import_xrefs(data: &[u8], import_names: &[String]) -> Vec<Xref> {
    let mut xrefs = Vec::new();

    for name in import_names {
        let needle = name.as_bytes();
        if needle.is_empty() || needle.len() > data.len() {
            continue;
        }

        let finder = memchr::memmem::Finder::new(needle);
        for abs_pos in finder.find_iter(data) {
            xrefs.push(Xref {
                source_offset: abs_pos,
                source_section: None,
                target: XrefTarget {
                    kind: XrefTargetKind::Import,
                    label: name.clone(),
                    target_offset: Some(abs_pos),
                },
            });
        }
    }

    xrefs
}

/// Build xrefs for a specific byte pattern across the entire binary.
///
/// Uses `memchr::memmem` for efficient substring search.
pub fn build_pattern_xrefs(
    data: &[u8],
    pattern_name: &str,
    pattern: &[u8],
) -> Vec<Xref> {
    let mut xrefs = Vec::new();

    if pattern.is_empty() || pattern.len() > data.len() {
        return xrefs;
    }

    let finder = memchr::memmem::Finder::new(pattern);
    for abs_pos in finder.find_iter(data) {
        xrefs.push(Xref {
            source_offset: abs_pos,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Pattern,
                label: pattern_name.to_string(),
                target_offset: Some(abs_pos),
            },
        });
    }

    xrefs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_query() {
        let mut db = XrefDatabase::new();
        db.add(Xref {
            source_offset: 0x100,
            source_section: Some(".text".into()),
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: "cmd.exe".into(),
                target_offset: Some(0x2000),
            },
        });
        db.add(Xref {
            source_offset: 0x200,
            source_section: Some(".text".into()),
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "CreateProcessA".into(),
                target_offset: None,
            },
        });

        assert_eq!(db.len(), 2);
        assert_eq!(db.xrefs_to("cmd.exe").len(), 1);
        assert_eq!(db.xrefs_to("CreateProcessA").len(), 1);
        assert_eq!(db.xrefs_to("nonexistent").len(), 0);
    }

    #[test]
    fn test_xrefs_from() {
        let mut db = XrefDatabase::new();
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: "hello".into(),
                target_offset: Some(0x500),
            },
        });
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "printf".into(),
                target_offset: None,
            },
        });

        let from_100 = db.xrefs_from(0x100);
        assert_eq!(from_100.len(), 2);
    }

    #[test]
    fn test_correlate() {
        let mut db = XrefDatabase::new();

        // Offset 0x100 references both cmd.exe and CreateProcessA
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: "cmd.exe".into(),
                target_offset: Some(0x2000),
            },
        });
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "CreateProcessA".into(),
                target_offset: None,
            },
        });

        // Offset 0x300 only references cmd.exe
        db.add(Xref {
            source_offset: 0x300,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: "cmd.exe".into(),
                target_offset: Some(0x2000),
            },
        });

        let correlated = db.correlate(&["cmd.exe", "CreateProcessA"]);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].source_offset, 0x100);
        assert_eq!(correlated[0].targets.len(), 2);
    }

    #[test]
    fn test_xrefs_to_containing() {
        let mut db = XrefDatabase::new();
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "VirtualAlloc".into(),
                target_offset: None,
            },
        });
        db.add(Xref {
            source_offset: 0x200,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "VirtualProtect".into(),
                target_offset: None,
            },
        });
        db.add(Xref {
            source_offset: 0x300,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "CreateThread".into(),
                target_offset: None,
            },
        });

        let virtual_refs = db.xrefs_to_containing("virtual");
        assert_eq!(virtual_refs.len(), 2);
    }

    #[test]
    fn test_summary() {
        let mut db = XrefDatabase::new();
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: "test".into(),
                target_offset: Some(0x500),
            },
        });
        db.add(Xref {
            source_offset: 0x200,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "Sleep".into(),
                target_offset: None,
            },
        });

        let summary = db.summary();
        assert_eq!(summary.total_xrefs, 2);
        assert_eq!(summary.unique_targets, 2);
        assert_eq!(summary.string_xrefs, 1);
        assert_eq!(summary.import_xrefs, 1);
    }

    #[test]
    fn test_build_pattern_xrefs() {
        let data = vec![0x00, 0x4D, 0x5A, 0x00, 0x4D, 0x5A, 0xFF];
        let xrefs = build_pattern_xrefs(&data, "MZ_HEADER", &[0x4D, 0x5A]);
        assert_eq!(xrefs.len(), 2);
        assert_eq!(xrefs[0].source_offset, 1);
        assert_eq!(xrefs[1].source_offset, 4);
    }
}


