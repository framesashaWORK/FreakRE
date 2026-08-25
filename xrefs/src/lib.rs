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

/// Safety budget on collected xref matches: prevents multi-GB allocations
/// when millions of needles match a large binary.
pub const MAX_XREF_RESULTS: usize = 250_000;

/// Hard budget on examined candidate matches (collected or not): bounds
/// scan time when common short strings produce billions of raw hits.
pub const MAX_XREF_SCANNED: usize = 20_000_000;

/// Strings shorter than this are noise for xref purposes (they match
/// everywhere) and blow up automaton construction on big binaries.
/// Import-name needles are held to the same threshold: short API names
/// like "sin"/"atoi" match all over a binary and produce garbage xrefs.
const MIN_XREF_STRING_LEN: usize = 8;

/// Cap on distinct needles fed into the automaton; the longest win.
const MAX_XREF_NEEDLES: usize = 50_000;

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
/// Duplicate xrefs (same source offset AND same target) are rejected on
/// insert so totals and correlation results are never inflated.
#[derive(Debug, Clone)]
pub struct XrefDatabase {
    /// Primary index: target label → list of xrefs pointing to it.
    by_target: HashMap<String, Vec<Xref>>,
    /// Reverse index: source offset → list of targets referenced from there.
    by_source: HashMap<usize, Vec<XrefTarget>>,
    /// Insertion guard: (source_offset, target) pairs already stored.
    seen: std::collections::HashSet<(usize, XrefTarget)>,
}

impl XrefDatabase {
    /// Create an empty xref database.
    pub fn new() -> Self {
        Self {
            by_target: HashMap::new(),
            by_source: HashMap::new(),
            seen: std::collections::HashSet::new(),
        }
    }

    /// Add a single cross-reference.
    ///
    /// Identical xrefs (same source offset and target) are deduplicated:
    /// a re-insert is a no-op, keeping counts and indexes consistent.
    pub fn add(&mut self, xref: Xref) {
        let key = xref.target.label.clone();
        if !self.seen.insert((xref.source_offset, xref.target.clone())) {
            return;
        }
        self.by_target
            .entry(key)
            .or_default()
            .push(xref.clone());
        self.by_source
            .entry(xref.source_offset)
            .or_default()
            .push(xref.target);
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
                // Section info, when known, lives on the stored xrefs
                // themselves; take the first non-None section among the
                // xrefs matching this source offset.
                let mut section: Option<String> = None;
                let targets: Vec<XrefTarget> = target_labels
                    .iter()
                    .filter_map(|label| {
                        self.xrefs_to(label)
                            .iter()
                            .find(|x| x.source_offset == offset)
                            .map(|x| {
                                if section.is_none() {
                                    section = x.source_section.clone();
                                }
                                x.target.clone()
                            })
                    })
                    .collect();

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
    ///
    /// All counts are derived from the indexes on each call, so they always
    /// reflect exactly what `xrefs_to`/`xrefs_from` will return (no stale
    /// stored counters, even across future index mutations).
    pub fn summary(&self) -> XrefSummary {
        let all_xrefs: Vec<&Xref> = self.by_target.values().flat_map(|v| v.iter()).collect();
        XrefSummary {
            total_xrefs: all_xrefs.len(),
            unique_targets: self.by_target.len(),
            string_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::String).count(),
            import_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Import).count(),
            pattern_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Pattern).count(),
            address_xrefs: all_xrefs.iter().filter(|x| x.target.kind == XrefTargetKind::Address).count(),
        }
    }

    /// Number of xrefs in the database.
    pub fn len(&self) -> usize {
        self.by_target.values().map(|v| v.len()).sum()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.by_target.values().all(|v| v.is_empty())
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
/// All needles are searched in a single Aho-Corasick pass (O(n + m + z)), so the
/// cost is independent of how many strings the binary contains — critical for
/// system libraries that embed thousands of strings.
pub fn build_string_xrefs(
    data: &[u8],
    strings: &[str_extract::ExtractedString<'_>],
) -> Vec<Xref> {
    // Collect non-empty needles, dedupe by bytes, and keep a parallel mapping
    // from pattern index -> (original offset, value).
    let mut needles: Vec<&[u8]> = Vec::new();
    let mut infos: Vec<(usize, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in strings {
        let n = s.raw_bytes;
        if n.len() < MIN_XREF_STRING_LEN || n.len() > data.len() {
            continue;
        }
        if seen.insert(n.to_vec()) {
            needles.push(n);
            infos.push((s.offset, s.value.clone()));
        }
    }
    if needles.is_empty() {
        return Vec::new();
    }
    if needles.len() > MAX_XREF_NEEDLES {
        let mut order: Vec<usize> = (0..needles.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(needles[i].len()));
        order.truncate(MAX_XREF_NEEDLES);
        let kept: std::collections::HashSet<usize> = order.iter().copied().collect();
        let mut new_needles = Vec::with_capacity(MAX_XREF_NEEDLES);
        let mut new_infos = Vec::with_capacity(MAX_XREF_NEEDLES);
        for i in 0..needles.len() {
            if kept.contains(&i) {
                new_needles.push(needles[i]);
                new_infos.push(infos[i].clone());
            }
        }
        needles = new_needles;
        infos = new_infos;
    }

    let ac = match freakre_patterns::AhoCorasick::build(&needles) {
        Ok(ac) => ac,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Xref> = Vec::new();
    let mut scanned = 0usize;
    for m in ac.iter_overlapping(data) {
        scanned += 1;
        if out.len() >= MAX_XREF_RESULTS || scanned >= MAX_XREF_SCANNED {
            eprintln!(
                "[xrefs] string-xref budget reached ({} kept, {} scanned), results truncated",
                out.len(),
                scanned
            );
            break;
        }
        let (off, val) = match infos.get(m.pattern_id) {
            Some(v) => v,
            None => continue,
        };
        // Skip the string's own location (a string doesn't xref itself).
        if m.start == *off {
            continue;
        }
        out.push(Xref {
            source_offset: m.start,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: val.clone(),
                target_offset: Some(*off),
            },
        });
    }
    out
}

/// Build xrefs from import names by scanning for their ASCII representation
/// in the binary (IAT entries, string references in code, etc.).
///
/// Mirrors `build_string_xrefs` filtering: names shorter than
/// `MIN_XREF_STRING_LEN` are skipped (short names like "sin"/"atoi" match
/// everywhere and produce garbage xrefs).
///
/// The first occurrence of a name is treated as the import's canonical
/// location (its definition site) and is not reported as a reference — same
/// self-location rule as strings. Subsequent occurrences are recorded as
/// xrefs whose `target_offset` points at that canonical location, so all
/// refs to one import group under a single stable target.
///
/// Single Aho-Corasick pass over all import names (O(n + m + z)).
pub fn build_import_xrefs(data: &[u8], import_names: &[String]) -> Vec<Xref> {
    let mut needles: Vec<&[u8]> = Vec::new();
    let mut infos: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in import_names {
        let n = name.as_bytes();
        if n.len() < MIN_XREF_STRING_LEN || n.len() > data.len() {
            continue;
        }
        if seen.insert(n.to_vec()) {
            needles.push(n);
            infos.push(name.clone());
        }
    }
    if needles.is_empty() {
        return Vec::new();
    }

    let ac = match freakre_patterns::AhoCorasick::build(&needles) {
        Ok(ac) => ac,
        Err(_) => return Vec::new(),
    };
    // Canonical (first-seen) location per pattern; None until encountered.
    let mut canonical: Vec<Option<usize>> = vec![None; needles.len()];
    let mut out: Vec<Xref> = Vec::new();
    let mut scanned = 0usize;
    for m in ac.iter_overlapping(data) {
        scanned += 1;
        if out.len() >= MAX_XREF_RESULTS || scanned >= MAX_XREF_SCANNED {
            break;
        }
        let pid = m.pattern_id;
        let name = match infos.get(pid) {
            Some(v) => v,
            None => continue,
        };
        let canon = match canonical[pid] {
            Some(off) => off,
            // First occurrence = the import's own site; record it as the
            // canonical target location and do not emit an xref for it.
            None => {
                canonical[pid] = Some(m.start);
                continue;
            }
        };
        out.push(Xref {
            source_offset: m.start,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: name.clone(),
                target_offset: Some(canon),
            },
        });
    }
    out
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

    // ─── Dedup tests ──────────────────────────────────────────────────

    fn string_xref(source_offset: usize, label: &str) -> Xref {
        Xref {
            source_offset,
            source_section: Some(".text".into()),
            target: XrefTarget {
                kind: XrefTargetKind::String,
                label: label.into(),
                target_offset: Some(0x5000),
            },
        }
    }

    #[test]
    fn test_add_dedups_identical_xrefs() {
        let mut db = XrefDatabase::new();
        db.add(string_xref(0x100, "cmd.exe"));
        db.add(string_xref(0x100, "cmd.exe"));
        db.add(string_xref(0x100, "cmd.exe"));

        assert_eq!(db.len(), 1);
        assert_eq!(db.xrefs_to("cmd.exe").len(), 1);
        assert_eq!(db.xrefs_from(0x100).len(), 1);

        let summary = db.summary();
        assert_eq!(summary.total_xrefs, 1);
        assert_eq!(summary.unique_targets, 1);
        assert_eq!(summary.string_xrefs, 1);
    }

    #[test]
    fn test_add_dedup_keeps_distinct_xrefs() {
        let mut db = XrefDatabase::new();
        // Same source, different target → kept.
        db.add(string_xref(0x100, "cmd.exe"));
        db.add(string_xref(0x100, "kernel32.dll"));
        // Same target, different source → kept.
        db.add(string_xref(0x200, "cmd.exe"));

        assert_eq!(db.len(), 3);
        assert_eq!(db.xrefs_to("cmd.exe").len(), 2);
        assert_eq!(db.xrefs_from(0x100).len(), 2);
        assert_eq!(db.xrefs_from(0x200).len(), 1);

        let summary = db.summary();
        assert_eq!(summary.total_xrefs, 3);
        assert_eq!(summary.unique_targets, 2);
    }

    #[test]
    fn test_correlate_not_inflated_by_duplicates() {
        let mut db = XrefDatabase::new();
        for _ in 0..3 {
            db.add(string_xref(0x100, "cmd.exe"));
            db.add(Xref {
                source_offset: 0x100,
                source_section: None,
                target: XrefTarget {
                    kind: XrefTargetKind::Import,
                    label: "CreateProcessA".into(),
                    target_offset: None,
                },
            });
        }

        let correlated = db.correlate(&["cmd.exe", "CreateProcessA"]);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].targets.len(), 2);
    }

    #[test]
    fn test_correlate_populates_source_section_from_xrefs() {
        let mut db = XrefDatabase::new();
        db.add(string_xref(0x100, "cmd.exe")); // source_section = Some(".text")
        db.add(Xref {
            source_offset: 0x100,
            source_section: None,
            target: XrefTarget {
                kind: XrefTargetKind::Import,
                label: "CreateProcessA".into(),
                target_offset: None,
            },
        });

        let correlated = db.correlate(&["cmd.exe", "CreateProcessA"]);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].source_section.as_deref(), Some(".text"));
    }

    #[test]
    fn test_summary_matches_xrefs_to_after_dedup() {
        let mut db = XrefDatabase::new();
        db.add(string_xref(0x100, "cmd.exe"));
        db.add(string_xref(0x100, "cmd.exe"));
        db.add(string_xref(0x200, "cmd.exe"));

        let summary = db.summary();
        assert_eq!(summary.total_xrefs, db.len());
        assert_eq!(
            summary.string_xrefs,
            db.xrefs_to("cmd.exe").len()
        );
    }

    // ─── Import xref filtering tests ──────────────────────────────────

    #[test]
    fn test_build_import_xrefs_filters_short_names() {
        // "sin" and "atoi" are below MIN_XREF_STRING_LEN and must be ignored
        // even though they occur multiple times in the data.
        let mut data = b"useless sin(x) calls atoi(y) here sin again".to_vec();
        data.extend_from_slice(b"padding padding");
        let names = vec!["sin".to_string(), "atoi".to_string()];
        let xrefs = build_import_xrefs(&data, &names);
        assert!(xrefs.is_empty());
    }

    #[test]
    fn test_build_import_xrefs_skips_canonical_site_and_groups_target_offset() {
        let name = b"VirtualAlloc";
        let mut data = vec![0x90u8; 8];
        let canonical_off = data.len();
        data.extend_from_slice(name); // definition site (e.g., import table)
        let ref_off = data.len();
        data.extend_from_slice(name); // a second occurrence = a reference

        let names = vec!["VirtualAlloc".to_string()];
        let xrefs = build_import_xrefs(&data, &names);

        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].source_offset, ref_off);
        assert_eq!(xrefs[0].target.label, "VirtualAlloc");
        // All refs to the same import share the canonical location as
        // target_offset (not the per-match position), so grouping works.
        assert_eq!(xrefs[0].target.target_offset, Some(canonical_off));
    }

    #[test]
    fn test_build_import_xrefs_single_occurrence_yields_no_refs() {
        let mut data = vec![0xCCu8; 4];
        data.extend_from_slice(b"VirtualFree");
        let names = vec!["VirtualFree".to_string()];
        // Only the definition site exists → no references to report.
        assert!(build_import_xrefs(&data, &names).is_empty());
    }
}


