//! ELF symbol table parsing (.symtab and .dynsym).

use crate::error::ElfWarning;
use crate::sections::SectionHeader;

/// Symbol binding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

impl SymbolBinding {
    pub fn from_raw(val: u8) -> Self {
        match val {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            v => Self::Unknown(v),
        }
    }
}

/// Symbol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    Unknown(u8),
}

impl SymbolType {
    pub fn from_raw(val: u8) -> Self {
        match val {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::Tls,
            v => Self::Unknown(v),
        }
    }
}

/// Parsed ELF symbol entry.
#[derive(Debug, Clone)]
pub struct SymbolEntry<'a> {
    /// Symbol name (resolved from strtab). May be None if unresolvable.
    pub name: Option<&'a str>,
    /// Raw name offset in string table.
    pub name_offset: usize,
    /// Symbol value (address).
    pub value: u64,
    /// Symbol size.
    pub size: u64,
    /// Binding (local/global/weak).
    pub binding: SymbolBinding,
    /// Symbol type.
    pub sym_type: SymbolType,
    /// Section header index (0 = undefined/imported).
    pub shndx: u16,
}

/// Resolve a null-terminated string from a string table section.
fn resolve_symbol_name<'a>(_data: &'a [u8], strtab: &SectionHeader<'a>, name_offset: usize) -> Option<&'a str> {
    if strtab.data.is_empty() || name_offset >= strtab.data.len() {
        return None;
    }
    let start = name_offset;
    let end = strtab.data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strtab.data.len());
    std::str::from_utf8(&strtab.data[start..end]).ok()
}

/// Parse all symbol tables (symtab + dynsym) for ELF64.
pub fn parse_all_symbols_64<'a, const BE: bool>(
    data: &'a [u8],
    sections: &[SectionHeader<'a>],
    _warnings: &mut Vec<ElfWarning>,
) -> (Vec<SymbolEntry<'a>>, Vec<SymbolEntry<'a>>) {
    let mut symbols = Vec::new();
    let mut dyn_symbols = Vec::new();

    // SHT_SYMTAB = 2, SHT_DYNSYM = 11
    for (i, sec) in sections.iter().enumerate() {
        if sec.sh_type != 2 && sec.sh_type != 11 {
            continue;
        }

        // Find associated string table (sh_link points to it)
        // For simplicity, we look for the linked section
        // In practice sh_link is at offset 40 in ELF64 section header
        // We'll search by common naming convention as fallback
        let strtab = find_strtab_for_symtab(sections, i, sec.sh_type);

        let entry_size = 24usize; // sizeof(Elf64_Sym)
        if sec.size == 0 || sec.data.is_empty() {
            continue;
        }

        let num_syms = sec.data.len() / entry_size;
        let target = if sec.sh_type == 11 {
            &mut dyn_symbols
        } else {
            &mut symbols
        };

        for j in 0..num_syms {
            let base = j * entry_size;
            if base + entry_size > sec.data.len() {
                break;
            }

            // Read from section data directly
            let st_name = if BE {
                u32::from_be_bytes([
                    sec.data[base],
                    sec.data[base + 1],
                    sec.data[base + 2],
                    sec.data[base + 3],
                ]) as usize
            } else {
                u32::from_le_bytes([
                    sec.data[base],
                    sec.data[base + 1],
                    sec.data[base + 2],
                    sec.data[base + 3],
                ]) as usize
            };

            let st_info = sec.data[base + 4];
            let st_shndx = if BE {
                u16::from_be_bytes([sec.data[base + 6], sec.data[base + 7]])
            } else {
                u16::from_le_bytes([sec.data[base + 6], sec.data[base + 7]])
            };
            let st_value = if BE {
                u64::from_be_bytes([
                    sec.data[base + 8],
                    sec.data[base + 9],
                    sec.data[base + 10],
                    sec.data[base + 11],
                    sec.data[base + 12],
                    sec.data[base + 13],
                    sec.data[base + 14],
                    sec.data[base + 15],
                ])
            } else {
                u64::from_le_bytes([
                    sec.data[base + 8],
                    sec.data[base + 9],
                    sec.data[base + 10],
                    sec.data[base + 11],
                    sec.data[base + 12],
                    sec.data[base + 13],
                    sec.data[base + 14],
                    sec.data[base + 15],
                ])
            };
            let st_size = if BE {
                u64::from_be_bytes([
                    sec.data[base + 16],
                    sec.data[base + 17],
                    sec.data[base + 18],
                    sec.data[base + 19],
                    sec.data[base + 20],
                    sec.data[base + 21],
                    sec.data[base + 22],
                    sec.data[base + 23],
                ])
            } else {
                u64::from_le_bytes([
                    sec.data[base + 16],
                    sec.data[base + 17],
                    sec.data[base + 18],
                    sec.data[base + 19],
                    sec.data[base + 20],
                    sec.data[base + 21],
                    sec.data[base + 22],
                    sec.data[base + 23],
                ])
            };

            let binding = SymbolBinding::from_raw(st_info >> 4);
            let sym_type = SymbolType::from_raw(st_info & 0xf);

            let name = if let Some(st) = strtab {
                resolve_symbol_name(data, st, st_name)
            } else {
                None
            };

            target.push(SymbolEntry {
                name,
                name_offset: st_name,
                value: st_value,
                size: st_size,
                binding,
                sym_type,
                shndx: st_shndx,
            });
        }
    }

    (symbols, dyn_symbols)
}

/// Parse all symbol tables for ELF32.
pub fn parse_all_symbols_32<'a, const BE: bool>(
    data: &'a [u8],
    sections: &[SectionHeader<'a>],
    _warnings: &mut Vec<ElfWarning>,
) -> (Vec<SymbolEntry<'a>>, Vec<SymbolEntry<'a>>) {
    let mut symbols = Vec::new();
    let mut dyn_symbols = Vec::new();

    for (i, sec) in sections.iter().enumerate() {
        if sec.sh_type != 2 && sec.sh_type != 11 {
            continue;
        }

        let strtab = find_strtab_for_symtab(sections, i, sec.sh_type);

        let entry_size = 16usize; // sizeof(Elf32_Sym)
        if sec.size == 0 || sec.data.is_empty() {
            continue;
        }

        let num_syms = sec.data.len() / entry_size;
        let target = if sec.sh_type == 11 {
            &mut dyn_symbols
        } else {
            &mut symbols
        };

        for j in 0..num_syms {
            let base = j * entry_size;
            if base + entry_size > sec.data.len() {
                break;
            }

            let st_name = if BE {
                u32::from_be_bytes([
                    sec.data[base],
                    sec.data[base + 1],
                    sec.data[base + 2],
                    sec.data[base + 3],
                ]) as usize
            } else {
                u32::from_le_bytes([
                    sec.data[base],
                    sec.data[base + 1],
                    sec.data[base + 2],
                    sec.data[base + 3],
                ]) as usize
            };

            let st_value = if BE {
                u32::from_be_bytes([
                    sec.data[base + 4],
                    sec.data[base + 5],
                    sec.data[base + 6],
                    sec.data[base + 7],
                ]) as u64
            } else {
                u32::from_le_bytes([
                    sec.data[base + 4],
                    sec.data[base + 5],
                    sec.data[base + 6],
                    sec.data[base + 7],
                ]) as u64
            };

            let st_size = if BE {
                u32::from_be_bytes([
                    sec.data[base + 8],
                    sec.data[base + 9],
                    sec.data[base + 10],
                    sec.data[base + 11],
                ]) as u64
            } else {
                u32::from_le_bytes([
                    sec.data[base + 8],
                    sec.data[base + 9],
                    sec.data[base + 10],
                    sec.data[base + 11],
                ]) as u64
            };

            let st_info = sec.data[base + 12];
            let st_shndx = if BE {
                u16::from_be_bytes([sec.data[base + 14], sec.data[base + 15]])
            } else {
                u16::from_le_bytes([sec.data[base + 14], sec.data[base + 15]])
            };

            let binding = SymbolBinding::from_raw(st_info >> 4);
            let sym_type = SymbolType::from_raw(st_info & 0xf);

            let name = if let Some(st) = strtab {
                resolve_symbol_name(data, st, st_name)
            } else {
                None
            };

            target.push(SymbolEntry {
                name,
                name_offset: st_name,
                value: st_value,
                size: st_size,
                binding,
                sym_type,
                shndx: st_shndx,
            });
        }
    }

    (symbols, dyn_symbols)
}

/// Find the string table associated with a symbol table section.
/// Uses sh_link if available, falls back to name-based lookup.
fn find_strtab_for_symtab<'a, 'b>(
    sections: &'b [SectionHeader<'a>],
    _symtab_index: usize,
    symtab_type: u32,
) -> Option<&'b SectionHeader<'a>> {
    // Try name-based lookup first (more reliable than sh_link without re-parsing)
    let strtab_name = if symtab_type == 11 {
        ".dynstr"
    } else {
        ".strtab"
    };

    sections.iter().find(|s| s.name == strtab_name)
}
