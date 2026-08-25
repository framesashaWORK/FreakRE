//! # freakre-symbols
//!
//! Debug symbol loading for freakRE.
//!
//! - PDB (Windows): reads the global symbol stream (`S_PUB32` / `S_GPROC32`),
//!   keeping only publics flagged as functions (`S_PUB32` data/thunk publics are dropped).
//!   Without PE context, addresses are stored as `(section: u16) << 32 | offset: u32`.
//!   A caller that knows the PE image can supply a section→RVA table via
//!   [`SymbolDb::set_section_rvas`] and convert addresses with [`SymbolDb::to_rva`].
//! - DWARF (ELF): walks compilation units via `gimli`, collecting
//!   `DW_TAG_subprogram` entries (DWARF 2–5, little- and big-endian).

use std::fs::File;
use std::path::Path;

use pdb::FallibleIterator as _;
use gimli::Endianity as _;
use gimli::ReaderOffset as _;

/// One function symbol: name plus address and size in whatever address space
/// the source uses (RVA for DWARF ELF, packed section|offset for PDB until converted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

/// Which debug-info format produced a [`SymbolDb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSource {
    Pdb,
    Dwarf,
}

#[derive(Debug, thiserror::Error)]
pub enum SymbolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("no debug information found")]
    NoDebugInfo,
}

/// Address-keyed collection of function symbols from one debug-info source.
///
/// Functions are kept sorted by address so lookups are binary searches.
#[derive(Debug)]
pub struct SymbolDb {
    functions: Vec<SymbolInfo>,
    source: SymbolSource,
    sections_rvas: Vec<u32>,
    /// `max_ends[i]`: the largest function end address among `functions[0..=i]`.
    /// Lets interval lookups prune their backward scan as soon as no earlier
    /// symbol can still reach the queried address.
    max_ends: Vec<u64>,
}

impl SymbolDb {
    /// Load symbols from a PDB file.
    ///
    /// Addresses are packed `section << 32 | offset` values; call
    /// [`set_section_rvas`](Self::set_section_rvas) with the PE section RVA table
    /// (1-based order, index 0 = PE section 1) to enable [`to_rva`](Self::to_rva).
    pub fn load_pdb(path: &Path) -> Result<Self, SymbolError> {
        let file = File::open(path)?;
        let mut pdb = pdb::PDB::open(file)
            .map_err(|e| SymbolError::Parse(format!("PDB open failed: {e}")))?;
        let table = pdb
            .global_symbols()
            .map_err(|e| SymbolError::Parse(format!("PDB global symbols: {e}")))?;

        let mut functions = Vec::new();
        let mut iter = table.iter();
        while let Some(symbol) = iter
            .next()
            .map_err(|e| SymbolError::Parse(format!("PDB symbol iteration: {e}")))?
        {
            let data = match symbol.parse() {
                Ok(d) => d,
                Err(_) => continue,
            };
            match data {
                pdb::SymbolData::Public(p) => {
                    if accept_public_symbol(&p) {
                        functions.push(SymbolInfo {
                            name: p.name.to_string().into_owned(),
                            address: pack_section_offset(p.offset.section, p.offset.offset),
                            size: 0,
                        });
                    }
                }
                pdb::SymbolData::Procedure(f) => functions.push(SymbolInfo {
                    name: f.name.to_string().into_owned(),
                    address: pack_section_offset(f.offset.section, f.offset.offset),
                    size: f.len as u64,
                }),
                _ => {}
            }
        }

        Ok(Self::from_sorted_functions(functions, SymbolSource::Pdb))
    }

    /// Load DWARF symbols from raw ELF file bytes (via `elf-parser` sections + `gimli`).
    ///
    /// Collects `DW_TAG_subprogram` DIEs with `DW_AT_name`/`DW_AT_linkage_name`
    /// and `DW_AT_low_pc`/`DW_AT_high_pc` (absolute-address or constant-size form;
    /// `DW_FORM_addrx` resolved through `.debug_addr`). Supports DWARF4 and DWARF5
    /// (`.debug_line_str` names), both endiannesses.
    pub fn load_dwarf_elf(data: &[u8]) -> Result<Self, SymbolError> {
        let elf = elf_parser::ElfFile::parse(data)
            .map_err(|e| SymbolError::Parse(format!("ELF parse failed: {e}")))?;

        let has_debug_info = elf
            .section_by_name(".debug_info")
            .is_some_and(|s| !s.data.is_empty());
        if !has_debug_info {
            return Err(SymbolError::NoDebugInfo);
        }

        let (unit_count, functions) = match elf.ident.endian {
            elf_parser::ElfEndian::Little => collect_dwarf_functions::<gimli::LittleEndian>(&elf)?,
            elf_parser::ElfEndian::Big => collect_dwarf_functions::<gimli::BigEndian>(&elf)?,
        };

        if unit_count == 0 {
            return Err(SymbolError::NoDebugInfo);
        }

        Ok(Self::from_sorted_functions(functions, SymbolSource::Dwarf))
    }

    /// All function symbols sorted by address.
    pub fn functions(&self) -> &[SymbolInfo] {
        &self.functions
    }

    /// Which format this database came from.
    pub fn source(&self) -> SymbolSource {
        self.source
    }

    /// Supply the PE section RVA table so packed PDB addresses can be converted:
    /// element `i` is the RVA of PE section `i+1`.
    pub fn set_section_rvas(&mut self, rvas: Vec<u32>) {
        self.sections_rvas = rvas;
    }

    /// Convert a packed `section << 32 | offset` address to an RVA using the
    /// section table installed by [`set_section_rvas`](Self::set_section_rvas).
    pub fn to_rva(&self, address: u64) -> Option<u64> {
        let section = (address >> 32) as usize;
        let offset = address & 0xFFFF_FFFF;
        let base = *self.sections_rvas.get(section.checked_sub(1)?)? as u64;
        base.checked_add(offset)
    }

    /// Find the function whose extent contains `address`:
    /// `low <= address < low + size`.
    ///
    /// Symbols recorded without an extent (`size == 0`, e.g. PDB function publics,
    /// which carry no length) match only their exact start address. Overlapping
    /// intervals resolve to the closest preceding start.
    ///
    /// Returns `None` when no function covers `address` — notably in the gaps
    /// between functions. For the previous "nearest symbol at or below" behavior
    /// use [`find_nearest_at_or_below`](Self::find_nearest_at_or_below).
    pub fn find_by_address(&self, address: u64) -> Option<&SymbolInfo> {
        let mut idx = self.functions.partition_point(|f| f.address <= address);
        while idx > 0 {
            // No symbol at or below this index reaches far enough to contain `address`.
            if self.max_ends[idx - 1] <= address {
                return None;
            }
            let cand = &self.functions[idx - 1];
            if cand.contains(address) {
                return Some(cand);
            }
            idx -= 1;
        }
        None
    }

    /// Nearest symbol whose start address is `<= address`, regardless of extent
    /// (the historical behavior of [`find_by_address`](Self::find_by_address)).
    /// Returns `None` when `address` lies below every symbol.
    pub fn find_nearest_at_or_below(&self, address: u64) -> Option<&SymbolInfo> {
        let idx = self.functions.partition_point(|f| f.address <= address);
        self.functions.get(idx.checked_sub(1)?)
    }
}

impl SymbolDb {
    fn from_sorted_functions(mut functions: Vec<SymbolInfo>, source: SymbolSource) -> Self {
        functions.sort_by_key(|f| f.address);
        let mut reach = 0u64;
        let max_ends = functions
            .iter()
            .map(|f| {
                reach = reach.max(f.end());
                reach
            })
            .collect();
        Self {
            functions,
            source,
            sections_rvas: Vec::new(),
            max_ends,
        }
    }
}

impl SymbolInfo {
    /// Extent used for containment: zero-size symbols occupy exactly one byte at
    /// their start address so they remain findable there.
    fn span(&self) -> u64 {
        self.size.max(1)
    }

    /// Exclusive end of [`span`](Self::span).
    fn end(&self) -> u64 {
        self.address.saturating_add(self.span())
    }

    fn contains(&self, address: u64) -> bool {
        self.address <= address && address < self.end()
    }
}

fn pack_section_offset(section: u16, offset: u32) -> u64 {
    ((section as u64) << 32) | offset as u64
}

fn section_slice<'a, E: gimli::Endianity>(
    elf: &'a elf_parser::ElfFile<'a>,
    id: gimli::SectionId,
) -> Result<gimli::EndianSlice<'a, E>, SymbolError> {
    let bytes = elf
        .section_by_name(id.name())
        .map(|s| s.data)
        .unwrap_or(&[]);
    Ok(gimli::EndianSlice::new(bytes, E::default()))
}

fn collect_dwarf_functions<E: gimli::Endianity>(
    elf: &elf_parser::ElfFile<'_>,
) -> Result<(usize, Vec<SymbolInfo>), SymbolError> {
    let dwarf = gimli::Dwarf::load(|id| section_slice::<E>(elf, id))?;
    let mut out = Vec::new();
    let mut units = 0usize;

    let mut headers = dwarf.units();
    while let Some(header) = headers.next().map_err(dwarf_err)? {
        units += 1;
        let unit = dwarf.unit(header).map_err(dwarf_err)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().map_err(dwarf_err)? {
            if entry.tag() != gimli::constants::DW_TAG_subprogram {
                continue;
            }
            let low_pc = entry
                .attr(gimli::constants::DW_AT_low_pc)
                .map_err(dwarf_err)?
                .and_then(|a| attr_addr(&dwarf, &unit, a.value()));
            let low = match low_pc {
                Some(l) => l,
                None => continue,
            };
            let name = match entry_name(&dwarf, &unit, entry) {
                Some(n) => n,
                None => continue,
            };
            let size = entry
                .attr(gimli::constants::DW_AT_high_pc)
                .map_err(dwarf_err)?
                .and_then(|a| high_pc_size(a.value(), low))
                .unwrap_or(0);
            out.push(SymbolInfo { name, address: low, size });
        }
    }
    Ok((units, out))
}

fn entry_name<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
) -> Option<String> {
    for attr in [gimli::constants::DW_AT_name, gimli::constants::DW_AT_linkage_name] {
        let value = entry.attr(attr).ok()??;
        let s = dwarf.attr_string(unit, value.value()).ok()?;
        let cow = s.to_string_lossy().ok()?;
        if !cow.is_empty() {
            return Some(cow.into_owned());
        }
    }
    None
}

fn attr_addr<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: gimli::AttributeValue<R>,
) -> Option<u64> {
    match value {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(i) => dwarf.address(unit, i).ok(),
        _ => None,
    }
}

fn high_pc_size<R: gimli::Reader>(
    value: gimli::AttributeValue<R>,
    low: u64,
) -> Option<u64> {
    match value {
        gimli::AttributeValue::Addr(h) => h.checked_sub(low),
        other => attr_const(&other),
    }
}

/// Only S_PUB32 records flagged as functions describe code entry points;
/// data publics (and thunk publics, which carry no `function` flag) would
/// pollute a function table.
fn accept_public_symbol(p: &pdb::PublicSymbol<'_>) -> bool {
    p.function
}

/// Size of a constant-form `DW_AT_high_pc`: an unsigned/signed offset from
/// `DW_AT_low_pc`. `DW_FORM_data16` arrives from gimli as a 16-byte `Block`.
fn attr_const<R: gimli::Reader>(value: &gimli::AttributeValue<R>) -> Option<u64> {
    match *value {
        gimli::AttributeValue::Udata(v) => Some(v),
        gimli::AttributeValue::Sdata(v) => u64::try_from(v).ok(),
        gimli::AttributeValue::Data1(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data2(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data4(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data8(v) => Some(v),
        gimli::AttributeValue::Block(ref data) if data.len().into_u64() == 16 => block16_as_u64(data),
        _ => None,
    }
}

/// Interpret a 16-byte block as the unit-endian 128-bit constant it encodes,
/// narrowed to `u64` (`None` on overflow).
fn block16_as_u64<R: gimli::Reader>(data: &R) -> Option<u64> {
    let mut buf = [0u8; 16];
    data.clone().read_slice(&mut buf).ok()?;
    let endian = data.endian();
    let (lo, hi) = if endian.is_big_endian() {
        (&buf[8..], &buf[..8])
    } else {
        (&buf[..8], &buf[8..])
    };
    let value = (u128::from(endian.read_u64(hi)) << 64) | u128::from(endian.read_u64(lo));
    u64::try_from(value).ok()
}

fn dwarf_err(e: gimli::Error) -> SymbolError {
    SymbolError::Parse(format!("DWARF: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf_without_debug_info() -> Vec<u8> {
        let mut data = vec![0u8; 128];
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16] = 2;
        data[18] = 0x3E;
        data
    }

    #[test]
    fn dwarf_elf_without_debug_sections_is_no_debug_info() {
        let err = SymbolDb::load_dwarf_elf(&minimal_elf_without_debug_info()).unwrap_err();
        assert!(matches!(err, SymbolError::NoDebugInfo));
    }

    fn two_function_db() -> SymbolDb {
        SymbolDb::from_sorted_functions(
            vec![
                SymbolInfo { name: "a".into(), address: 0x100, size: 0x10 },
                SymbolInfo { name: "b".into(), address: 0x1000, size: 0x40 },
            ],
            SymbolSource::Dwarf,
        )
    }

    #[test]
    fn find_by_address_strict_containment() {
        // NOTE: intentionally changed contract (audit fix). The old implementation
        // returned the nearest symbol at or below any address, so gap addresses
        // like 0x110 or 0x1060 resolved to "b". Containment is now required.
        let db = two_function_db();
        assert_eq!(db.find_by_address(0x50), None);
        assert_eq!(db.find_by_address(0x100).unwrap().name, "a"); // low inclusive
        assert_eq!(db.find_by_address(0x10F).unwrap().name, "a"); // last byte
        assert_eq!(db.find_by_address(0x110), None); // one past end of "a"
        assert_eq!(db.find_by_address(0x800), None); // gap between functions
        assert_eq!(db.find_by_address(0x1000).unwrap().name, "b");
        assert_eq!(db.find_by_address(0x103F).unwrap().name, "b");
        assert_eq!(db.find_by_address(0x1040), None); // high exclusive
        assert_eq!(db.find_by_address(0xDEAD000), None);
    }

    #[test]
    fn zero_size_symbols_match_only_exact_start() {
        let db = SymbolDb::from_sorted_functions(
            vec![SymbolInfo { name: "z".into(), address: 0x2000, size: 0 }],
            SymbolSource::Pdb,
        );
        assert_eq!(db.find_by_address(0x1FFF), None);
        assert_eq!(db.find_by_address(0x2000).unwrap().name, "z");
        assert_eq!(db.find_by_address(0x2001), None);
    }

    #[test]
    fn interval_miss_and_fallback_are_distinct() {
        let db = two_function_db();
        // Misses under containment...
        for miss in [0x110, 0x800, 0x1040] {
            assert_eq!(db.find_by_address(miss), None, "addr {miss:#x}");
            // ...still resolve under the explicit nearest-lower fallback.
            assert_eq!(
                db.find_nearest_at_or_below(miss).unwrap().name,
                if miss < 0x1000 { "a" } else { "b" }
            );
        }
        assert_eq!(db.find_nearest_at_or_below(0x50), None); // below all
        assert_eq!(db.find_nearest_at_or_below(0xDEAD000).unwrap().name, "b");
        // Both agree when the address is inside an extent.
        assert_eq!(db.find_by_address(0x100).unwrap().name, "a");
        assert_eq!(db.find_nearest_at_or_below(0x100).unwrap().name, "a");
    }

    #[test]
    fn overlapping_intervals_resolve_to_enclosing_or_inner_function() {
        let db = SymbolDb::from_sorted_functions(
            vec![
                SymbolInfo { name: "inner".into(), address: 0x180, size: 0x4 },
                SymbolInfo { name: "outer".into(), address: 0x100, size: 0x100 },
            ],
            SymbolSource::Dwarf,
        );
        assert_eq!(db.find_by_address(0x190).unwrap().name, "outer");
        assert_eq!(db.find_by_address(0x181).unwrap().name, "inner");
        assert_eq!(db.find_by_address(0x184).unwrap().name, "outer");
    }

    #[test]
    fn pdb_public_symbols_filtered_to_functions() {
        fn public(function: bool) -> pdb::PublicSymbol<'static> {
            pdb::PublicSymbol {
                code: function,
                function,
                managed: false,
                msil: false,
                offset: pdb::PdbInternalSectionOffset::new(1, 0x10),
                name: pdb::RawString::from("sym"),
            }
        }
        assert!(accept_public_symbol(&public(true)));
        assert!(!accept_public_symbol(&public(false)));
    }

    #[test]
    fn high_pc_constant_forms() {
        const LOW: u64 = 0x1000;
        type Attr<'a> = gimli::AttributeValue<gimli::EndianSlice<'a, gimli::LittleEndian>>;
        type AttrBe<'a> = gimli::AttributeValue<gimli::EndianSlice<'a, gimli::BigEndian>>;
        // Unsigned forms (previously supported).
        assert_eq!(high_pc_size(Attr::Udata(0x20), LOW), Some(0x20));
        assert_eq!(high_pc_size(Attr::Data1(0x10), LOW), Some(0x10));
        assert_eq!(high_pc_size(Attr::Data8(0x30), LOW), Some(0x30));
        // Signed form (DW_FORM_sdata / DW_FORM_implicit_const).
        assert_eq!(high_pc_size(Attr::Sdata(0x40), LOW), Some(0x40));
        assert_eq!(high_pc_size(Attr::Sdata(-5), LOW), None);
        // DW_FORM_data16 arrives as a 16-byte Block.
        let le_block: [u8; 16] = {
            let mut b = [0u8; 16];
            b[0] = 0x80;
            b
        };
        let be_block: [u8; 16] = {
            let mut b = [0u8; 16];
            b[15] = 0x80;
            b
        };
        assert_eq!(
            high_pc_size(
                Attr::Block(gimli::EndianSlice::new(&le_block, gimli::LittleEndian)),
                LOW
            ),
            Some(0x80)
        );
        assert_eq!(
            high_pc_size(
                AttrBe::Block(gimli::EndianSlice::new(&be_block, gimli::BigEndian)),
                LOW
            ),
            Some(0x80)
        );
        // 128-bit overflow cannot be a u64 size.
        let huge: [u8; 16] = [0xFF; 16];
        assert_eq!(
            high_pc_size(
                Attr::Block(gimli::EndianSlice::new(&huge, gimli::LittleEndian)),
                LOW
            ),
            None
        );
        // Non-constant forms yield no size.
        assert_eq!(high_pc_size(Attr::Flag(true), LOW), None);
    }

    #[test]
    fn rva_conversion_via_section_table() {
        let mut db = SymbolDb::from_sorted_functions(Vec::new(), SymbolSource::Pdb);
        assert_eq!(db.to_rva(pack_section_offset(1, 0x10)), None);
        db.set_section_rvas(vec![0x1000, 0x2000]);
        assert_eq!(db.to_rva(pack_section_offset(1, 0x10)), Some(0x1010));
        assert_eq!(db.to_rva(pack_section_offset(2, 0x20)), Some(0x2020));
        assert_eq!(db.to_rva(pack_section_offset(3, 0)), None);
    }

    #[test]
    fn pdb_invalid_file_returns_error_not_panic() {
        let path = std::env::temp_dir().join("freakre_symbols_invalid_test.bin");
        std::fs::write(&path, b"this is definitely not a valid PDB").unwrap();
        let result = SymbolDb::load_pdb(&path);
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn pdb_missing_file_io_error() {
        let result = SymbolDb::load_pdb(Path::new("definitely_missing_freakre.pdb"));
        assert!(matches!(result, Err(SymbolError::Io(_))));
    }
}
