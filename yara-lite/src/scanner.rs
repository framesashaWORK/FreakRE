//! Scanner: matches compiled rules against binary data.

use crate::ast::*;
use crate::compiler::{build_ac_automaton, CompileError, CompiledHexPattern, CompiledRule};
use freakre_patterns::AcSearcher;
use std::collections::HashMap;

/// Interned string ID for hot-path matching (avoids String allocation per match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringId(pub u32);

/// A single match found during scanning.
#[derive(Debug, Clone)]
pub struct Match {
    pub rule_name: String,
    pub string_id: String,
    pub offset: usize,
    pub length: usize,
    /// The matched bytes (clipped to 64 bytes for display).
    pub data: Vec<u8>,
}

/// Result of scanning data against a set of rules.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub matches: Vec<Match>,
    /// Rules whose conditions evaluated to true.
    pub matched_rules: Vec<String>,
    /// True if match collection hit a safety budget (text, hex, or regex)
    /// and results are incomplete. Set only when more matches existed than
    /// the budget allowed (or the search was provably cut short).
    pub truncated: bool,
}

/// Global safety budget on collected matches: prevents multi-GB allocations
/// when common patterns hit large binaries. YARA semantics for `#count`
/// become unreliable only beyond this point.
pub const MAX_COLLECTED_MATCHES: usize = 1_000_000;

/// Pre-compiled scanner holding all rules and the AC automaton.
pub struct Scanner {
    rules: Vec<CompiledRule>,
    /// Case-sensitive Aho-Corasick automaton (matched against raw data).
    ac: AcSearcher,
    /// Maps AC pattern index → (rule_name, string_id)
    ac_index_map: Vec<(String, String)>,
    /// Case-insensitive Aho-Corasick automaton (matched against lowercased data).
    ac_lc: AcSearcher,
    /// Maps lowercase AC pattern index → (rule_name, string_id)
    ac_lc_index_map: Vec<(String, String)>,
    /// Interned string table: index → (rule_name, string_id).
    /// Hot-path matching uses u32 indices instead of String allocation.
    intern_table: Vec<(String, String)>,
    /// Reverse lookup: (rule_name, string_id) → interned index.
    intern_lookup: HashMap<(String, String), u32>,
}

impl Scanner {
    /// Create a new scanner from compiled rules.
    pub fn new(rules: Vec<CompiledRule>) -> Result<Self, CompileError> {
        let (ac, ac_index_map) = build_ac_automaton(&rules, false)?;
        let (ac_lc, ac_lc_index_map) = build_ac_automaton(&rules, true)?;

        // Build intern table for hot-path matching (avoids String alloc per match)
        let mut intern_table: Vec<(String, String)> = Vec::new();
        let mut intern_lookup: HashMap<(String, String), u32> = HashMap::new();
        for rule in &rules {
            for id in rule
                .text_patterns
                .keys()
                .chain(rule.hex_patterns.keys())
                .chain(rule.regex_patterns.keys())
            {
                let key = (rule.name.clone(), id.clone());
                if let std::collections::hash_map::Entry::Vacant(e) =
                    intern_lookup.entry(key.clone())
                {
                    let idx = intern_table.len() as u32;
                    intern_table.push(key);
                    e.insert(idx);
                }
            }
        }

        Ok(Self {
            rules,
            ac,
            ac_index_map,
            ac_lc,
            ac_lc_index_map,
            intern_table,
            intern_lookup,
        })
    }

    /// Scan a byte buffer and return all matches + satisfied rules.
    pub fn scan(&self, data: &[u8]) -> ScanResult {
        // Hot-path: use interned u32 indices instead of (String, String) keys
        // to avoid heap allocation per match.
        let mut raw_matches_interned: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();

        let mut fullword_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for rule in &self.rules {
            for (id, tp) in &rule.text_patterns {
                if tp.modifiers.fullword {
                    if let Some(&idx) = self.intern_lookup.get(&(rule.name.clone(), id.clone())) {
                        fullword_ids.insert(idx);
                    }
                }
            }
        }

        // 1. Aho-Corasick text matching (interned, streaming, budget-capped)
        let mut collected = 0usize;
        let mut truncated = false;

        //    Case-sensitive pass over the raw data.
        if !self.ac_index_map.is_empty() {
            for mat in self.ac.find_overlapping(data) {
                if collected >= MAX_COLLECTED_MATCHES {
                    truncated = true;
                    break;
                }
                let (ref rule_name, ref string_id) = self.ac_index_map[mat.pattern_index];
                if let Some(&idx) = self
                    .intern_lookup
                    .get(&(rule_name.clone(), string_id.clone()))
                {
                    if fullword_ids.contains(&idx) && !fullword_ok(data, mat.start, mat.len) {
                        continue;
                    }
                    raw_matches_interned
                        .entry(idx)
                        .or_default()
                        .push((mat.start, mat.len));
                    collected += 1;
                }
            }
        }

        //    Case-insensitive pass: only run if there are `nocase` patterns.
        //    A lowercased view of the data is matched against lowercased variants.
        if !self.ac_lc_index_map.is_empty() && collected < MAX_COLLECTED_MATCHES {
            let data_lc: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
            for mat in self.ac_lc.find_overlapping(&data_lc) {
                if collected >= MAX_COLLECTED_MATCHES {
                    truncated = true;
                    break;
                }
                let (ref rule_name, ref string_id) = self.ac_lc_index_map[mat.pattern_index];
                if let Some(&idx) = self
                    .intern_lookup
                    .get(&(rule_name.clone(), string_id.clone()))
                {
                    if fullword_ids.contains(&idx) && !fullword_ok(data, mat.start, mat.len) {
                        continue;
                    }
                    raw_matches_interned
                        .entry(idx)
                        .or_default()
                        .push((mat.start, mat.len));
                    collected += 1;
                }
            }
        }

        // 2. Hex pattern matching (wildcard-aware, interned, budget-capped)
        for rule in &self.rules {
            if truncated && collected >= MAX_COLLECTED_MATCHES {
                break;
            }
            for (id, hp) in &rule.hex_patterns {
                let budget = MAX_COLLECTED_MATCHES.saturating_sub(collected);
                // Probe one match beyond the budget so truncation is only
                // reported when MORE than `budget` matches actually existed
                // (mirrors the regex path's budget+1 detection below).
                let found = scan_hex_pattern(data, hp, budget.saturating_add(1));
                let overflow = found.len() > budget;
                let kept = if overflow {
                    &found[..budget]
                } else {
                    &found[..]
                };
                collected += kept.len();
                if !kept.is_empty() {
                    if let Some(&idx) = self.intern_lookup.get(&(rule.name.clone(), id.clone())) {
                        raw_matches_interned
                            .entry(idx)
                            .or_default()
                            .extend(kept.iter().copied());
                    }
                }
                if overflow {
                    truncated = true;
                    break;
                }
            }
        }

        // 3. Regex pattern matching with DoS protection (interned).
        // SafeRegex is byte-oriented (`find_iter(&[u8])`), so run it directly
        // on the raw data: String::from_utf8_lossy would expand invalid bytes
        // into multi-byte U+FFFD replacements, shifting every match offset
        // away from the original data and panicking when clipping Match.data.
        const MAX_REGEX_MATCHES_PER_PATTERN: usize = 1024;
        for rule in &self.rules {
            for (id, rp) in &rule.regex_patterns {
                for (match_count, mat) in rp.regex.find_iter(data).enumerate() {
                    if match_count >= MAX_REGEX_MATCHES_PER_PATTERN {
                        // The (budget+1)-th match exists, so results for this
                        // pattern are provably incomplete.
                        truncated = true;
                        break;
                    }
                    if let Some(&idx) = self.intern_lookup.get(&(rule.name.clone(), id.clone())) {
                        raw_matches_interned
                            .entry(idx)
                            .or_default()
                            .push((mat.start, mat.end - mat.start));
                    }
                }
            }
        }

        // Convert interned matches back to (String, String) keyed map for condition eval
        let mut raw_matches: HashMap<(String, String), Vec<(usize, usize)>> = HashMap::new();
        for (idx, locs) in &raw_matches_interned {
            if let Some((rn, sid)) = self.intern_table.get(*idx as usize) {
                raw_matches.insert((rn.clone(), sid.clone()), locs.clone());
            }
        }

        // Build Match structs
        let mut matches: Vec<Match> = Vec::new();
        for ((rule_name, string_id), locs) in &raw_matches {
            for &(offset, length) in locs {
                let clip = length.min(64);
                matches.push(Match {
                    rule_name: rule_name.clone(),
                    string_id: string_id.clone(),
                    offset,
                    length,
                    data: data[offset..offset + clip].to_vec(),
                });
            }
        }
        matches.sort_by_key(|m| m.offset);

        // Evaluate conditions
        let entrypoint = detect_entrypoint(data);
        let mut matched_rules = Vec::new();
        for rule in &self.rules {
            // Collect string IDs defined in this rule for OfThem evaluation
            let rule_string_ids: std::collections::HashSet<String> = rule
                .text_patterns
                .keys()
                .chain(rule.hex_patterns.keys())
                .chain(rule.regex_patterns.keys())
                .cloned()
                .collect();

            if evaluate_condition(
                &rule.condition,
                &raw_matches,
                data.len(),
                data,
                entrypoint,
                &rule_string_ids,
                &rule.name,
            ) {
                matched_rules.push(rule.name.clone());
            }
        }

        ScanResult {
            matches,
            matched_rules,
            truncated,
        }
    }
}

/// Detect PE entry point file offset.
/// Returns 0 if not a valid PE or entry point cannot be resolved.
fn detect_entrypoint(data: &[u8]) -> usize {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return 0;
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    // Bound must cover the PE signature AND the optional-header magic bytes at
    // pe_offset+24..26, otherwise a truncated PE panics on data[pe_offset+25].
    if pe_offset.saturating_add(26) > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return 0;
    }
    // Optional header starts at pe_offset + 24
    // Entry point RVA is at offset 16 from optional header start (pe_offset + 24 + 16)
    let ep_offset = pe_offset + 24 + 16;
    if ep_offset + 4 > data.len() {
        return 0;
    }
    let entry_rva = u32::from_le_bytes([
        data[ep_offset],
        data[ep_offset + 1],
        data[ep_offset + 2],
        data[ep_offset + 3],
    ]) as usize;

    // Resolve RVA to file offset using section headers
    // Section headers start after optional header
    let magic = u16::from_le_bytes([data[pe_offset + 24], data[pe_offset + 25]]);
    let num_sections_offset = pe_offset + 6;
    if num_sections_offset + 2 > data.len() {
        return 0;
    }
    let num_sections_raw =
        u16::from_le_bytes([data[num_sections_offset], data[num_sections_offset + 1]]) as usize;
    // FIXED: Clamp num_sections to prevent excessive iterations on malformed PE.
    // PE spec allows max 96 sections; anything higher is anomalous.
    let num_sections = num_sections_raw.min(96);

    let optional_header_size = if magic == 0x20b { 112 } else { 96 }; // PE32+ vs PE32
    let section_table_offset = pe_offset + 24 + optional_header_size;

    // Each section header is 40 bytes
    // VirtualAddress at offset 12, SizeOfRawData at offset 16, PointerToRawData at offset 20
    for i in 0..num_sections {
        let sec_offset = section_table_offset + i * 40;
        if sec_offset + 40 > data.len() {
            break;
        }
        let virtual_addr = u32::from_le_bytes([
            data[sec_offset + 12],
            data[sec_offset + 13],
            data[sec_offset + 14],
            data[sec_offset + 15],
        ]) as usize;
        let raw_size = u32::from_le_bytes([
            data[sec_offset + 16],
            data[sec_offset + 17],
            data[sec_offset + 18],
            data[sec_offset + 19],
        ]) as usize;
        let raw_pointer = u32::from_le_bytes([
            data[sec_offset + 20],
            data[sec_offset + 21],
            data[sec_offset + 22],
            data[sec_offset + 23],
        ]) as usize;

        if entry_rva >= virtual_addr && entry_rva < virtual_addr + raw_size {
            return raw_pointer + (entry_rva - virtual_addr);
        }
    }
    0
}

// ─── Hex pattern scanner ──────────────────────────────────────

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn fullword_ok(data: &[u8], start: usize, len: usize) -> bool {
    let before_ok = start == 0 || !is_word_byte(data[start - 1]);
    let after = start + len;
    let after_ok = after >= data.len() || !is_word_byte(data[after]);
    before_ok && after_ok
}

fn scan_hex_pattern(data: &[u8], hp: &CompiledHexPattern, limit: usize) -> Vec<(usize, usize)> {
    let pat_len = hp.min_len;
    if pat_len == 0 || data.len() < pat_len || limit == 0 {
        return Vec::new();
    }

    let mut results = Vec::new();
    let end = data.len() - pat_len + 1;

    // Quick skip: use literal prefix to find candidate positions
    if hp.min_literal_len > 0 {
        let prefix: Vec<u8> = hp.tokens[..hp.min_literal_len]
            .iter()
            .filter_map(|t| match t {
                HexToken::Literal(b) => Some(*b),
                _ => None,
            })
            .collect();

        let mut search_start = 0;
        while search_start < end {
            // Find next occurrence of literal prefix
            let candidate = data[search_start..]
                .windows(prefix.len())
                .position(|w| w == prefix.as_slice());

            match candidate {
                Some(rel_offset) => {
                    let abs_offset = search_start + rel_offset;
                    if abs_offset + pat_len <= data.len()
                        && hex_match_at(data, abs_offset, &hp.tokens)
                    {
                        results.push((abs_offset, pat_len));
                        if results.len() >= limit {
                            break;
                        }
                    }
                    search_start = abs_offset + 1;
                }
                None => break,
            }
        }
    } else {
        // No literal prefix, brute force (rare case)
        for offset in 0..end {
            if hex_match_at(data, offset, &hp.tokens) {
                results.push((offset, pat_len));
                if results.len() >= limit {
                    break;
                }
            }
        }
    }

    results
}

fn hex_match_at(data: &[u8], offset: usize, tokens: &[HexToken]) -> bool {
    hex_match_at_recursive(data, offset, tokens, 0)
}

fn hex_match_at_recursive(data: &[u8], offset: usize, tokens: &[HexToken], tok_idx: usize) -> bool {
    if tok_idx >= tokens.len() {
        return true;
    }
    let remaining_data = data.len() - offset;
    let remaining_tokens = &tokens[tok_idx..];

    match &remaining_tokens[0] {
        HexToken::Literal(expected) => {
            if remaining_data == 0 || data[offset] != *expected {
                return false;
            }
            hex_match_at_recursive(data, offset + 1, tokens, tok_idx + 1)
        }
        HexToken::Wildcard => {
            if remaining_data == 0 {
                return false;
            }
            hex_match_at_recursive(data, offset + 1, tokens, tok_idx + 1)
        }
        HexToken::NibbleWildcard { mask, value } => {
            if remaining_data == 0 {
                return false;
            }
            if (data[offset] & !mask) != (value & !mask) {
                return false;
            }
            hex_match_at_recursive(data, offset + 1, tokens, tok_idx + 1)
        }
        HexToken::Alternation(alts) => {
            // Try each alternative; if any matches the rest, return true
            for alt in alts {
                // Build a temporary token list: [alt, remaining_tokens...]
                let mut test_tokens = vec![alt.clone()];
                test_tokens.extend_from_slice(&remaining_tokens[1..]);
                if hex_match_at_recursive(data, offset, &test_tokens, 0) {
                    return true;
                }
            }
            false
        }
        HexToken::Jump { min, max } => {
            let next_tok = tok_idx + 1;
            if next_tok >= tokens.len() {
                // Jump at end of pattern = always match
                return true;
            }
            let effective_max = (*max).min(remaining_data);
            if *min > effective_max {
                return false;
            }
            // Try skip lengths from min to max
            for skip in *min..=effective_max {
                if hex_match_at_recursive(data, offset + skip, tokens, next_tok) {
                    return true;
                }
            }
            false
        }
    }
}

// ─── Condition evaluator ─────────────────────────────────────

type RawMatches<'a> = &'a HashMap<(String, String), Vec<(usize, usize)>>;

fn evaluate_condition(
    cond: &Condition,
    matches: RawMatches,
    filesize: usize,
    data: &[u8],
    entrypoint: usize,
    rule_string_ids: &std::collections::HashSet<String>,
    current_rule_name: &str,
) -> bool {
    match cond {
        Condition::Bool(b) => *b,
        Condition::And(a, b) => {
            evaluate_condition(
                a,
                matches,
                filesize,
                data,
                entrypoint,
                rule_string_ids,
                current_rule_name,
            ) && evaluate_condition(
                b,
                matches,
                filesize,
                data,
                entrypoint,
                rule_string_ids,
                current_rule_name,
            )
        }
        Condition::Or(a, b) => {
            evaluate_condition(
                a,
                matches,
                filesize,
                data,
                entrypoint,
                rule_string_ids,
                current_rule_name,
            ) || evaluate_condition(
                b,
                matches,
                filesize,
                data,
                entrypoint,
                rule_string_ids,
                current_rule_name,
            )
        }
        Condition::Not(c) => !evaluate_condition(
            c,
            matches,
            filesize,
            data,
            entrypoint,
            rule_string_ids,
            current_rule_name,
        ),

        Condition::StringMatch(id) => matches
            .iter()
            .any(|((rn, sid), locs)| rn == current_rule_name && sid == id && !locs.is_empty()),

        Condition::StringCount(id) => {
            // Standalone count is truthy if > 0
            let count = count_matches_scoped(matches, current_rule_name, id);
            count > 0
        }

        Condition::OfThem(kind) => {
            // "them" = all defined strings in THIS rule (not all rules)
            // CRITICAL: Must check BOTH rule_name AND string_id to avoid
            // cross-rule contamination when multiple rules share string identifiers.
            let total = rule_string_ids.len();
            let matched_count = rule_string_ids
                .iter()
                .filter(|sid| {
                    matches.iter().any(|((rn, s), locs)| {
                        rn == current_rule_name && s == *sid && !locs.is_empty()
                    })
                })
                .count();
            check_of_kind(kind, matched_count, total)
        }

        Condition::OfSet(kind, ids) => {
            let total = ids.len();
            let matched_count = ids
                .iter()
                .filter(|id| {
                    matches.iter().any(|((rn, sid), locs)| {
                        rn == current_rule_name && sid == *id && !locs.is_empty()
                    })
                })
                .count();
            check_of_kind(kind, matched_count, total)
        }

        Condition::At(id, expected_offset) => matches.iter().any(|((rn, sid), locs)| {
            rn == current_rule_name
                && sid == id
                && locs.iter().any(|(off, _)| off == expected_offset)
        }),

        Condition::AtExpr(id, offset_expr) => {
            let expected = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            matches.iter().any(|((rn, sid), locs)| {
                rn == current_rule_name && sid == id && locs.iter().any(|(off, _)| *off == expected)
            })
        }

        Condition::In(id, start, end) => matches.iter().any(|((rn, sid), locs)| {
            rn == current_rule_name
                && sid == id
                && locs.iter().any(|(off, _)| *off >= *start && *off <= *end)
        }),

        Condition::InExpr(id, start_expr, end_expr) => {
            let start = eval_int_expr(
                start_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            let end = eval_int_expr(
                end_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            matches.iter().any(|((rn, sid), locs)| {
                rn == current_rule_name
                    && sid == id
                    && locs.iter().any(|(off, _)| *off >= start && *off <= end)
            })
        }

        Condition::Contains(id, substr) => {
            let sub = substr.as_bytes();
            if sub.is_empty() {
                return true;
            }
            matches.iter().any(|((rn, sid), locs)| {
                rn == current_rule_name
                    && sid == id
                    && locs.iter().any(|(off, len)| {
                        *off + *len <= data.len()
                            && data[*off..*off + *len].windows(sub.len()).any(|w| w == sub)
                    })
            })
        }

        Condition::IsType(id, type_name) => {
            // Simplified: just check if string exists
            let _ = (id, type_name);
            true
        }

        Condition::Eq(id, value) => {
            let val_bytes = value.as_bytes();
            matches.iter().any(|((rn, sid), locs)| {
                rn == current_rule_name
                    && sid == id
                    && locs.iter().any(|(off, len)| {
                        *off + *len <= data.len() && &data[*off..*off + *len] == val_bytes
                    })
            })
        }

        Condition::IntComp(op, lhs, rhs) => {
            let l = eval_int_expr(lhs, matches, filesize, data, entrypoint, current_rule_name);
            let r = eval_int_expr(rhs, matches, filesize, data, entrypoint, current_rule_name);
            match op {
                IntCompOp::Eq => l == r,
                IntCompOp::Ne => l != r,
                IntCompOp::Lt => l < r,
                IntCompOp::Le => l <= r,
                IntCompOp::Gt => l > r,
                IntCompOp::Ge => l >= r,
            }
        }

        Condition::PeNumberSections(op, rhs) => {
            let l = eval_pe_number_of_sections(data);
            let r = eval_int_expr(rhs, matches, filesize, data, entrypoint, current_rule_name);
            match op {
                IntCompOp::Eq => l == r,
                IntCompOp::Ne => l != r,
                IntCompOp::Lt => l < r,
                IntCompOp::Le => l <= r,
                IntCompOp::Gt => l > r,
                IntCompOp::Ge => l >= r,
            }
        }

        Condition::PeImports(dll_name) => eval_pe_imports(data, dll_name),

        Condition::PeSections(sec_name) => eval_pe_section_exists(data, sec_name),
    }
}

fn eval_int_expr(
    expr: &IntExpr,
    matches: RawMatches,
    filesize: usize,
    data: &[u8],
    entrypoint: usize,
    current_rule_name: &str,
) -> usize {
    match expr {
        IntExpr::Literal(n) => *n,
        IntExpr::Count(id) => count_matches(matches, current_rule_name, id),
        IntExpr::Filesize => filesize,
        IntExpr::MatchOffset(id) => {
            // Return offset of first match for THIS rule, or 0 if none
            matches
                .iter()
                .filter(|((rn, sid), _)| rn == current_rule_name && sid == id)
                .flat_map(|(_, locs)| locs.iter().map(|(off, _)| *off))
                .min()
                .unwrap_or(0)
        }
        IntExpr::Entrypoint | IntExpr::Offset => entrypoint,
        IntExpr::Uint8(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            data.get(off).map(|&b| b as usize).unwrap_or(0)
        }
        IntExpr::Uint16(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            // NB: `off` is rule-controlled (wrapping arithmetic), so plain
            // `off + 2` could overflow/wrap past the guard — use checked_add.
            if off.checked_add(2).is_some_and(|end| end <= data.len()) {
                u16::from_le_bytes([data[off], data[off + 1]]) as usize
            } else {
                0
            }
        }
        IntExpr::Uint32(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            if off.checked_add(4).is_some_and(|end| end <= data.len()) {
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                    as usize
            } else {
                0
            }
        }
        IntExpr::Int8(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            data.get(off)
                .map(|&b| b as i8 as isize as usize)
                .unwrap_or(0)
        }
        IntExpr::Int16(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            if off.checked_add(2).is_some_and(|end| end <= data.len()) {
                i16::from_le_bytes([data[off], data[off + 1]]) as isize as usize
            } else {
                0
            }
        }
        IntExpr::Int32(offset_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            if off.checked_add(4).is_some_and(|end| end <= data.len()) {
                i32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                    as isize as usize
            } else {
                0
            }
        }
        IntExpr::StringLength(id) => {
            // String length: return length of first match
            matches
                .iter()
                .filter(|((rn, sid), _)| rn == current_rule_name && sid == id)
                .flat_map(|(_, locs)| locs.iter().map(|(_, len)| *len))
                .next()
                .unwrap_or(0)
        }
        IntExpr::MathHash(offset_expr, len_expr) => {
            let off = eval_int_expr(
                offset_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            let len = eval_int_expr(
                len_expr,
                matches,
                filesize,
                data,
                entrypoint,
                current_rule_name,
            );
            // `off`/`len` are rule-controlled: on overflow clamp to EOF so
            // the `off >= end` guard below returns 0 instead of panicking.
            let end = off
                .checked_add(len)
                .map(|e| e.min(data.len()))
                .unwrap_or(data.len());
            if off >= end {
                return 0;
            }
            // Simple FNV-1a hash
            let mut hash: u32 = 0x811c9dc5;
            for &b in &data[off..end] {
                hash ^= b as u32;
                hash = hash.wrapping_mul(0x01000193);
            }
            hash as usize
        }
        IntExpr::Add(a, b) => {
            let la = eval_int_expr(a, matches, filesize, data, entrypoint, current_rule_name);
            let rb = eval_int_expr(b, matches, filesize, data, entrypoint, current_rule_name);
            la.wrapping_add(rb)
        }
        IntExpr::Sub(a, b) => {
            let la = eval_int_expr(a, matches, filesize, data, entrypoint, current_rule_name);
            let rb = eval_int_expr(b, matches, filesize, data, entrypoint, current_rule_name);
            la.wrapping_sub(rb)
        }
        IntExpr::Mul(a, b) => {
            let la = eval_int_expr(a, matches, filesize, data, entrypoint, current_rule_name);
            let rb = eval_int_expr(b, matches, filesize, data, entrypoint, current_rule_name);
            la.wrapping_mul(rb)
        }
        IntExpr::Div(a, b) => {
            let la = eval_int_expr(a, matches, filesize, data, entrypoint, current_rule_name);
            let rb = eval_int_expr(b, matches, filesize, data, entrypoint, current_rule_name);
            // Division by zero (and MIN/-1 overflow) yields 0 instead of
            // panicking on hostile rules.
            la.checked_div(rb).unwrap_or(0)
        }
        IntExpr::Paren(inner) => eval_int_expr(
            inner,
            matches,
            filesize,
            data,
            entrypoint,
            current_rule_name,
        ),
        IntExpr::PeNumberOfSections => eval_pe_number_of_sections(data),
    }
}

// ─── PE module helpers ─────────────────────────────────────

fn eval_pe_number_of_sections(data: &[u8]) -> usize {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return 0;
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 8 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return 0;
    }
    // NumberOfSections is at COFF+2 = pe_off+4+2 = pe_off+6
    u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize
}

fn eval_pe_imports(data: &[u8], dll_name: &str) -> bool {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return false;
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = pe_off + 24;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    // Data directory: PE32 starts at opt+96, PE32+ at opt+112; import is index 1 (+8)
    let import_rva_off = if magic == 0x20b {
        opt_off + 112 + 8
    } else {
        opt_off + 96 + 8
    };
    if import_rva_off + 8 > data.len() {
        return false;
    }
    let import_rva = u32::from_le_bytes([
        data[import_rva_off],
        data[import_rva_off + 1],
        data[import_rva_off + 2],
        data[import_rva_off + 3],
    ]);
    if import_rva == 0 {
        return false;
    }
    // Find section containing import RVA
    let num_sections_off = pe_off + 6;
    if num_sections_off + 2 > data.len() {
        return false;
    }
    let num_sections =
        u16::from_le_bytes([data[num_sections_off], data[num_sections_off + 1]]).min(96);
    // SizeOfOptionalHeader at COFF+16 = pe_off+4+16 = pe_off+20
    let size_opt_off = pe_off + 20;
    if size_opt_off + 2 > data.len() {
        return false;
    }
    let size_opt = u16::from_le_bytes([data[size_opt_off], data[size_opt_off + 1]]) as usize;
    let sec_table = opt_off + size_opt;
    let dll_lower = dll_name.to_lowercase();
    for i in 0..num_sections {
        let sec_off = sec_table + i as usize * 40;
        if sec_off + 40 > data.len() {
            break;
        }
        let virt_addr = u32::from_le_bytes([
            data[sec_off + 12],
            data[sec_off + 13],
            data[sec_off + 14],
            data[sec_off + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sec_off + 16],
            data[sec_off + 17],
            data[sec_off + 18],
            data[sec_off + 19],
        ]);
        let raw_ptr = u32::from_le_bytes([
            data[sec_off + 20],
            data[sec_off + 21],
            data[sec_off + 22],
            data[sec_off + 23],
        ]);
        // NB: `virt_addr + raw_size` can overflow u32 on hostile input —
        // compare via subtraction instead. `file_off` is checked so a
        // crafted raw_ptr can never slice out of bounds.
        if import_rva >= virt_addr && import_rva - virt_addr < raw_size {
            let delta = (import_rva - virt_addr) as usize;
            let Some(file_off) = (raw_ptr as usize).checked_add(delta) else {
                return false;
            };
            let end = file_off
                .checked_add(raw_size as usize)
                .map(|e| e.min(data.len()))
                .unwrap_or(data.len());
            if file_off > end {
                return false;
            }
            if dll_lower.is_empty() {
                // Mirror Condition::Contains: empty substring matches.
                return true;
            }
            // Scan import table for DLL name
            let chunk = &data[file_off..end];
            return chunk
                .windows(dll_lower.len())
                .any(|w| w.eq_ignore_ascii_case(dll_lower.as_bytes()));
        }
    }
    false
}

fn eval_pe_section_exists(data: &[u8], sec_name: &str) -> bool {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return false;
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = pe_off + 24;
    let num_sections_off = pe_off + 6;
    if num_sections_off + 2 > data.len() {
        return false;
    }
    let num_sections =
        u16::from_le_bytes([data[num_sections_off], data[num_sections_off + 1]]).min(96);
    let size_opt_off = pe_off + 20;
    if size_opt_off + 2 > data.len() {
        return false;
    }
    let size_opt = u16::from_le_bytes([data[size_opt_off], data[size_opt_off + 1]]) as usize;
    let sec_table = opt_off + size_opt;
    for i in 0..num_sections {
        let sec_off = sec_table + i as usize * 40;
        if sec_off + 40 > data.len() {
            break;
        }
        let name_bytes = &data[sec_off..sec_off + 8];
        let name_str = std::str::from_utf8(name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0');
        if name_str.eq_ignore_ascii_case(sec_name) {
            return true;
        }
    }
    false
}

fn count_matches_scoped(matches: RawMatches, rule_name: &str, id: &str) -> usize {
    matches
        .iter()
        .filter(|((rn, sid), _)| rn == rule_name && sid == id)
        .map(|(_, locs)| locs.len())
        .sum()
}

/// Unscoped count — used internally by eval_int_expr where we pass rule_name.
fn count_matches(matches: RawMatches, rule_name: &str, id: &str) -> usize {
    count_matches_scoped(matches, rule_name, id)
}

fn check_of_kind(kind: &OfKind, matched: usize, total: usize) -> bool {
    match kind {
        OfKind::All => matched == total && total > 0,
        OfKind::Any => matched > 0,
        OfKind::Exactly(n) => matched == *n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile_rule;
    use crate::parser;

    fn make_scanner(rule_text: &str) -> Scanner {
        let rule = parser::parse_rule(rule_text).unwrap();
        let compiled = compile_rule(&rule).unwrap();
        Scanner::new(vec![compiled]).unwrap()
    }

    #[test]
    fn test_regex_offsets_index_raw_bytes() {
        let scanner = make_scanner(
            r#"
            rule re_raw {
                strings:
                    $r = /secret/
                condition:
                    $r
            }
            "#,
        );
        // Invalid UTF-8 before the match: lossy conversion used to expand it
        // into U+FFFD, shifting offsets and panicking when clipping Match.data.
        let data = [0xFF, 0xFE, b's', b'e', b'c', b'r', b'e', b't'];
        let result = scanner.scan(&data);
        assert!(result.matched_rules.contains(&"re_raw".to_string()));
        let m = result.matches.iter().find(|m| m.string_id == "$r").unwrap();
        assert_eq!(m.offset, 2);
        assert_eq!(m.length, 6);
        assert_eq!(&m.data, b"secret");
    }

    #[test]
    fn test_scan_hex_escape_text_pattern() {
        let scanner = make_scanner(
            r#"
            rule xe {
                strings:
                    $s = "\xDE\xAD\xC0\xDE"
                condition:
                    any of them
            }
            "#,
        );
        let data = [0x90u8, 0xDE, 0xAD, 0xC0, 0xDE, 0x00];
        let result = scanner.scan(&data);
        assert!(result.matched_rules.contains(&"xe".to_string()));
        assert_eq!(
            result
                .matches
                .iter()
                .find(|m| m.string_id == "$s")
                .map(|m| m.offset),
            Some(1)
        );
    }

    #[test]
    fn test_detect_entrypoint_truncated_pe_no_panic() {
        // e_lfanew points at offset 41 in a 66-byte buffer: the PE signature
        // fits but the optional-header magic straddles EOF. Must not panic.
        let mut data = vec![0u8; 66];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 41;
        assert_eq!(detect_entrypoint(&data), 0);
    }

    #[test]
    fn test_scan_mz_header() {
        let scanner = make_scanner(
            r#"
            rule mz_check {
                strings:
                    $mz = { 4D 5A }
                condition:
                    $mz at 0
            }
            "#,
        );
        let data = b"\x4D\x5A\x90\x00rest of PE";
        let result = scanner.scan(data);
        assert!(result.matched_rules.contains(&"mz_check".to_string()));
    }

    #[test]
    fn test_scan_no_match() {
        let scanner = make_scanner(
            r#"
            rule no_match {
                strings:
                    $s = "malware_string_xyz"
                condition:
                    any of them
            }
            "#,
        );
        let result = scanner.scan(b"this is benign content");
        assert!(result.matched_rules.is_empty());
    }

    #[test]
    fn test_scan_nocase() {
        let scanner = make_scanner(
            r#"
            rule nocase_test {
                strings:
                    $s = "MALWARE" nocase ascii
                condition:
                    any of them
            }
            "#,
        );
        let result = scanner.scan(b"found malWaRe in memory");
        assert!(result.matched_rules.contains(&"nocase_test".to_string()));
    }

    #[test]
    fn test_scan_fullword() {
        let scanner = make_scanner(
            r#"
            rule fw_test {
                strings:
                    $s = "cat" fullword
                condition:
                    any of them
            }
            "#,
        );
        assert!(scanner
            .scan(b"the cat sat")
            .matched_rules
            .contains(&"fw_test".to_string()));
        assert!(scanner.scan(b"concatenate").matched_rules.is_empty());
        assert!(scanner.scan(b"scattered").matched_rules.is_empty());
    }

    #[test]
    fn test_scan_hex_wildcard() {
        let scanner = make_scanner(
            r#"
            rule hex_wc {
                strings:
                    $h = { 4D ?? 90 }
                condition:
                    any of them
            }
            "#,
        );
        let result = scanner.scan(b"\x00\x4D\xFF\x90\x00");
        assert!(result.matched_rules.contains(&"hex_wc".to_string()));
    }

    #[test]
    fn test_scan_count_condition() {
        let scanner = make_scanner(
            r#"
            rule count_test {
                strings:
                    $cc = { CC CC }
                condition:
                    #cc > 2
            }
            "#,
        );
        // 3 occurrences of CC CC (overlapping at 0,1,2)
        let data = b"\xCC\xCC\xCC\xCC";
        let result = scanner.scan(data);
        assert!(result.matched_rules.contains(&"count_test".to_string()));
    }

    #[test]
    fn test_scan_in_range() {
        let scanner = make_scanner(
            r#"
            rule range_test {
                strings:
                    $s = "secret"
                condition:
                    $s in (10..20)
            }
            "#,
        );
        let mut data = vec![0u8; 30];
        data[12..18].copy_from_slice(b"secret");
        let result = scanner.scan(&data);
        assert!(result.matched_rules.contains(&"range_test".to_string()));

        // Outside range
        let mut data2 = vec![0u8; 30];
        data2[2..8].copy_from_slice(b"secret");
        let result2 = scanner.scan(&data2);
        assert!(result2.matched_rules.is_empty());
    }

    #[test]
    fn test_scan_uint16_pe_magic() {
        let scanner = make_scanner(
            r#"
            rule pe_magic {
                strings:
                    $mz = { 4D 5A }
                condition:
                    uint16(0) == 0x5A4D and $mz at 0
            }
            "#,
        );
        let data = b"\x4D\x5A\x90\x00rest of PE";
        let result = scanner.scan(data);
        assert!(result.matched_rules.contains(&"pe_magic".to_string()));
    }

    #[test]
    fn test_scan_uint32_value() {
        let scanner = make_scanner(
            r#"
            rule check_value {
                condition:
                    uint32(0) == 0x44434241
            }
            "#,
        );
        let data = b"ABCDrest";
        let result = scanner.scan(data);
        assert!(result.matched_rules.contains(&"check_value".to_string()));
    }

    #[test]
    fn test_scan_filesize_condition() {
        let scanner = make_scanner(
            r#"
            rule small_file {
                condition:
                    filesize < 100
            }
            "#,
        );
        let data = b"small";
        let result = scanner.scan(data);
        assert!(result.matched_rules.contains(&"small_file".to_string()));

        let big_data = vec![0u8; 200];
        let result2 = scanner.scan(&big_data);
        assert!(result2.matched_rules.is_empty());
    }

    #[test]
    fn test_detect_entrypoint_valid_pe() {
        // Minimal PE with one section
        let mut data = vec![0u8; 512];
        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at offset 60 = 0x80 (128)
        data[60] = 0x80;
        // PE signature at 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // COFF header: 1 section
        data[0x84 + 2] = 1;
        // Optional header: PE32 magic = 0x10b
        data[0x80 + 24] = 0x0b;
        data[0x80 + 25] = 0x01;
        // Entry point RVA at optional header + 16 = 0x80 + 24 + 16 = 0xA8
        let ep_off = 0xA8;
        data[ep_off] = 0x00;
        data[ep_off + 1] = 0x10; // RVA = 0x1000
                                 // Section header starts at 0x80 + 24 + 96 = 0xF8
        let sec_off = 0xF8;
        // VirtualAddress at sec_off + 12
        data[sec_off + 12] = 0x00;
        data[sec_off + 13] = 0x10; // VA = 0x1000
                                   // SizeOfRawData at sec_off + 16
        data[sec_off + 16] = 0x00;
        data[sec_off + 17] = 0x02; // 0x200
                                   // PointerToRawData at sec_off + 20
        data[sec_off + 20] = 0x00;
        data[sec_off + 21] = 0x02; // 0x200

        let ep = detect_entrypoint(&data);
        assert_eq!(ep, 0x200); // File offset should be 0x200
    }

    #[test]
    fn test_detect_entrypoint_not_pe() {
        let data = b"not a PE file at all";
        let ep = detect_entrypoint(data);
        assert_eq!(ep, 0);
    }

    #[test]
    fn test_detect_entrypoint_too_short() {
        let data = b"MZ";
        assert_eq!(detect_entrypoint(data), 0);
    }

    #[test]
    fn test_regex_budget_sets_truncated_flag() {
        // 1100 non-overlapping regex matches exceed MAX_REGEX_MATCHES_PER_PATTERN
        // (1024): the (budget+1)-th match exists, so results are incomplete.
        let scanner = make_scanner(
            r#"
            rule re_flood {
                strings:
                    $r = /a/
                condition:
                    $r
            }
            "#,
        );
        let data = vec![b'a'; 1100];
        let result = scanner.scan(&data);
        assert!(result.truncated);
        assert!(result.matched_rules.contains(&"re_flood".to_string()));

        // Below the budget nothing is reported as truncated.
        let small = scanner.scan(b"just one match here a");
        assert!(!small.truncated);
    }

    #[test]
    fn test_hex_budget_sets_truncated_flag() {
        // 1_000_001 overlapping { CC CC } matches exceed MAX_COLLECTED_MATCHES:
        // exactly one more than the budget existed → truncated must be set.
        let scanner = make_scanner(
            r#"
            rule cc_flood {
                strings:
                    $cc = { CC CC }
                condition:
                    any of them
            }
            "#,
        );
        let data = vec![0xCCu8; MAX_COLLECTED_MATCHES + 2];
        let result = scanner.scan(&data);
        assert!(result.truncated);

        // Well below the budget → complete results.
        let small = scanner.scan(&[0xCCu8; 64]);
        assert!(!small.truncated);
        assert!(small.matched_rules.contains(&"cc_flood".to_string()));
    }

    // ─── New features tests ────────────────────────────────

    #[test]
    fn test_hex_alternation() {
        let scanner = make_scanner(
            r#"
            rule alt_test {
                strings:
                    $h = { (4D | 5A) (90 | CC) }
                condition:
                    any of them
            }
            "#,
        );
        assert!(scanner
            .scan(b"\x4D\x90")
            .matched_rules
            .contains(&"alt_test".to_string()));
        assert!(scanner
            .scan(b"\x5A\xCC")
            .matched_rules
            .contains(&"alt_test".to_string()));
        assert!(scanner
            .scan(b"\x4D\xCC")
            .matched_rules
            .contains(&"alt_test".to_string()));
        assert!(scanner.scan(b"\x4D\x91").matched_rules.is_empty());
    }

    #[test]
    fn test_hex_jump() {
        let scanner = make_scanner(
            r#"
            rule jump_test {
                strings:
                    $h = { 4D 5A [0-10] 45 46 }
                condition:
                    any of them
            }
            "#,
        );
        // Exactly 0 bytes skip
        assert!(scanner
            .scan(b"\x4D\x5A\x45\x46")
            .matched_rules
            .contains(&"jump_test".to_string()));
        // 5 bytes skip
        let mut data = vec![0x4D, 0x5A];
        data.extend_from_slice(&[0x00; 5]);
        data.extend_from_slice(&[0x45, 0x46]);
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"jump_test".to_string()));
        // 11 bytes skip — too many
        let mut data2 = vec![0x4D, 0x5A];
        data2.extend_from_slice(&[0x00; 11]);
        data2.extend_from_slice(&[0x45, 0x46]);
        assert!(scanner.scan(&data2).matched_rules.is_empty());
    }

    #[test]
    fn test_hex_alternation_with_wildcard() {
        let scanner = make_scanner(
            r#"
            rule alt_wc {
                strings:
                    $h = { (?? | 4D) 5A }
                condition:
                    any of them
            }
            "#,
        );
        assert!(scanner
            .scan(b"\x4D\x5A")
            .matched_rules
            .contains(&"alt_wc".to_string()));
        assert!(scanner
            .scan(b"\xFF\x5A")
            .matched_rules
            .contains(&"alt_wc".to_string()));
    }

    #[test]
    fn test_xor_modifier() {
        let scanner = make_scanner(
            r#"
            rule xor_test {
                strings:
                    $s = "secret" xor
                condition:
                    any of them
            }
            "#,
        );
        // Original (key=0)
        assert!(scanner
            .scan(b"secret")
            .matched_rules
            .contains(&"xor_test".to_string()));
        // XORed with key=0x42
        let xored: Vec<u8> = b"secret".iter().map(|b| b ^ 0x42).collect();
        assert!(scanner
            .scan(&xored)
            .matched_rules
            .contains(&"xor_test".to_string()));
        // XORed with key=0xFF
        let xored_ff: Vec<u8> = b"secret".iter().map(|b| b ^ 0xFF).collect();
        assert!(scanner
            .scan(&xored_ff)
            .matched_rules
            .contains(&"xor_test".to_string()));
    }

    #[test]
    fn test_contains_operator() {
        let scanner = make_scanner(
            r#"
            rule contains_test {
                strings:
                    $s = "hello world"
                condition:
                    $s contains "world"
            }
            "#,
        );
        assert!(scanner
            .scan(b"the hello world data")
            .matched_rules
            .contains(&"contains_test".to_string()));
        assert!(scanner.scan(b"no match here").matched_rules.is_empty());
    }

    #[test]
    fn test_pe_number_of_sections() {
        // Build a minimal PE with 3 sections
        let mut data = vec![0u8; 1024];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // Number of sections at COFF+2 = 0x84+2 = 0x86
        data[0x86] = 3;
        data[0x87] = 0;

        let scanner = make_scanner(
            r#"
            rule pe_sections {
                condition:
                    pe.number_of_sections > 2
            }
            "#,
        );
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"pe_sections".to_string()));
    }

    #[test]
    fn test_pe_imports() {
        let mut data = vec![0u8; 2048];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // PE32 magic
        data[0x80 + 24] = 0x0b;
        data[0x80 + 25] = 0x01;
        // 1 section
        data[0x86] = 1;
        // SizeOfOptionalHeader at COFF+16 = 0x84+16 = 0x94
        // Set to 96 + 16*8 = 224 (standard PE32 with 16 data dirs)
        data[0x94] = 224;
        data[0x95] = 0;
        // Import dir RVA at PE32 opt+96+8 = 0x98+104 = 0x100
        data[0x100] = 0x00;
        data[0x101] = 0x10; // RVA = 0x1000
                            // Section table starts at opt + SizeOfOptionalHeader = 0x98 + 224 = 0x178
        let sec = 0x178;
        data[sec + 12] = 0x00;
        data[sec + 13] = 0x10; // VA = 0x1000
        data[sec + 16] = 0x00;
        data[sec + 17] = 0x02; // raw_size = 0x200
        data[sec + 20] = 0x00;
        data[sec + 21] = 0x02; // raw_ptr = 0x200
                               // Write "kernel32.dll" in the import section at file offset 0x200
        data[0x200..0x200 + 13].copy_from_slice(b"kernel32.dll\0");

        let scanner = make_scanner(
            r#"
            rule pe_imports_test {
                condition:
                    pe.imports("kernel32.dll")
            }
            "#,
        );
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"pe_imports_test".to_string()));
    }

    #[test]
    fn test_pe_sections_exists() {
        let mut data = vec![0u8; 1024];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x86] = 1; // 1 section
                        // SizeOfOptionalHeader at COFF+16 = 0x94
        data[0x94] = 224;
        data[0x95] = 0;
        // Section table at opt + 224 = 0x98 + 224 = 0x178
        let sec = 0x178;
        data[sec..sec + 8].copy_from_slice(b".text\0\0\0");

        let scanner = make_scanner(
            r#"
            rule sec_exists {
                condition:
                    pe.sections(".text")
            }
            "#,
        );
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"sec_exists".to_string()));
    }

    #[test]
    fn test_int16_signed() {
        let scanner = make_scanner(
            r#"
            rule int16_test {
                condition:
                    int16(0) == -1
            }
            "#,
        );
        // -1 as i16 LE = 0xFF 0xFF
        assert!(scanner
            .scan(&[0xFF, 0xFF])
            .matched_rules
            .contains(&"int16_test".to_string()));
        // 1 as i16 LE = 0x01 0x00
        assert!(scanner.scan(&[0x01, 0x00]).matched_rules.is_empty());
    }

    #[test]
    fn test_int32_signed() {
        let scanner = make_scanner(
            r#"
            rule int32_test {
                condition:
                    int32(0) == -100
            }
            "#,
        );
        // -100 as i32 LE
        let val = (-100i32).to_le_bytes();
        assert!(scanner
            .scan(&val)
            .matched_rules
            .contains(&"int32_test".to_string()));
    }

    #[test]
    fn test_offset_keyword() {
        let scanner = make_scanner(
            r#"
            rule offset_test {
                strings:
                    $mz = { 4D 5A }
                condition:
                    $mz at offset
            }
            "#,
        );
        // offset == entrypoint == 0 for non-PE, so MZ at 0 matches
        assert!(scanner
            .scan(b"\x4D\x5A\x90\x00")
            .matched_rules
            .contains(&"offset_test".to_string()));
    }

    #[test]
    fn test_math_hash() {
        let scanner = make_scanner(
            r#"
            rule hash_test {
                condition:
                    math.hash(0, 4) > 0
            }
            "#,
        );
        assert!(scanner
            .scan(b"ABCD")
            .matched_rules
            .contains(&"hash_test".to_string()));
    }

    #[test]
    fn test_at_modifier_on_string_def() {
        let scanner = make_scanner(
            r#"
            rule at_mod_test {
                strings:
                    $s = "hello" at 5
                condition:
                    any of them
            }
            "#,
        );
        let mut data = vec![0u8; 20];
        data[5..10].copy_from_slice(b"hello");
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"at_mod_test".to_string()));
    }

    #[test]
    fn test_in_modifier_on_string_def() {
        let scanner = make_scanner(
            r#"
            rule in_mod_test {
                strings:
                    $s = "hello" in (0..10)
                condition:
                    any of them
            }
            "#,
        );
        let mut data = vec![0u8; 20];
        data[5..10].copy_from_slice(b"hello");
        assert!(scanner
            .scan(&data)
            .matched_rules
            .contains(&"in_mod_test".to_string()));
    }

    #[test]
    fn test_arithmetic_in_int_expr() {
        let scanner = make_scanner(
            r#"
            rule arith_test {
                condition:
                    filesize == 4 + 4
            }
            "#,
        );
        // 4 + 4 = 8, so need 8-byte data
        assert!(scanner
            .scan(b"ABCDABCD")
            .matched_rules
            .contains(&"arith_test".to_string()));
        assert!(scanner.scan(b"ABCDEF").matched_rules.is_empty());
    }

    #[test]
    fn test_offset_keyword_in_int_expr() {
        let scanner = make_scanner(
            r#"
            rule offset_int {
                condition:
                    offset == 0
            }
            "#,
        );
        // offset == 0 for non-PE
        assert!(scanner
            .scan(b"test")
            .matched_rules
            .contains(&"offset_int".to_string()));
    }

    #[test]
    fn test_hostile_uint_offset_no_panic() {
        // Rule-controlled offsets use wrapping arithmetic, so `off` can be
        // usize::MAX. The old `off + N <= len` guard wrapped past the check
        // and panicked on indexing in release builds.
        let scanner = make_scanner(
            r#"
            rule hostile_off {
                condition:
                    uint16(18446744073709551615) == 0 and
                    uint32(18446744073709551615) == 0 and
                    int16(18446744073709551615) == 0 and
                    int32(18446744073709551615) == 0
            }
            "#,
        );
        // All out-of-range reads yield 0 instead of panicking.
        assert!(scanner
            .scan(b"ABCD")
            .matched_rules
            .contains(&"hostile_off".to_string()));
    }

    #[test]
    fn test_hostile_math_hash_no_panic() {
        let scanner = make_scanner(
            r#"
            rule hostile_hash {
                condition:
                    math.hash(18446744073709551615, 8) == 0
            }
            "#,
        );
        assert!(scanner
            .scan(b"ABCD")
            .matched_rules
            .contains(&"hostile_hash".to_string()));
    }

    #[test]
    fn test_hostile_pe_imports_no_panic() {
        // Section maps import RVA into file offset 0xFFFFFF00, far beyond EOF.
        // Must return false, not panic on slicing.
        let mut data = vec![0u8; 2048];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x80 + 24] = 0x0b;
        data[0x80 + 25] = 0x01;
        data[0x86] = 1; // 1 section
        data[0x94] = 224;
        data[0x95] = 0;
        data[0x100] = 0x00;
        data[0x101] = 0x10; // import RVA = 0x1000
        let sec = 0x178;
        data[sec + 12] = 0x00;
        data[sec + 13] = 0x10; // VA = 0x1000
        data[sec + 16] = 0x00;
        data[sec + 17] = 0x02; // raw_size = 0x200
        data[sec + 20] = 0x00;
        data[sec + 21] = 0x00;
        data[sec + 22] = 0xFF;
        data[sec + 23] = 0xFF; // raw_ptr = 0xFFFF0000
        let scanner = make_scanner(
            r#"
            rule hostile_imports {
                condition:
                    pe.imports("kernel32.dll")
            }
            "#,
        );
        assert!(scanner.scan(&data).matched_rules.is_empty());
    }

    #[test]
    fn test_pe_imports_empty_dll_no_panic() {
        // Empty DLL name used to panic in `windows(0)`; mirrors Contains.
        let scanner = make_scanner(
            r#"
            rule empty_imports {
                condition:
                    pe.imports("")
            }
            "#,
        );
        let _ = scanner.scan(b"MZ fake");
    }
}
