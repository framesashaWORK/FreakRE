//! Public decompilation API for the server (`/api/decompile`).
//!
//! Lifts and decompiles a real function from a PE image in memory. This is
//! the same pipeline the scanner's experimental decompiler finding uses
//! (func-finder boundaries → x86 lifter → decompiler), exposed as a
//! standalone entry point so the HTTP server does not need to re-implement
//! or dump findings.

use crate::report::Finding;
use crate::Severity;

/// One decompiled function, ready for JSON serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecompiledFunction {
    /// Virtual address the function was found at.
    pub address: u64,
    /// Synthetic name (`sub_<hex address>`).
    pub name: String,
    /// Function size in bytes, as detected by func-finder.
    pub size: u64,
    /// C pseudocode.
    pub c_code: String,
    /// What the SSA stage (Phase 0.6) did: attempted / failed / rsp-fallback.
    /// Lets batch harnesses measure how often the pre-SSA fallback fires.
    pub events: decompiler::PipelineEvents,
}

/// Decompile the function containing `address` from a PE image.
///
/// With `None`, the largest detected function in `.text` is used (the same
/// heuristic as the scanner finding). Returns `Err` with a human-readable
/// reason for every failure mode: not a PE, no executable section, no
/// function detected, lift or decompile errors.
pub fn decompile_pe_function(data: &[u8], address: Option<u64>) -> Result<DecompiledFunction, String> {
    let pe = pe_parser::PeFile::parse(data)
        .map_err(|e| format!("not a parseable PE image: {e}"))?;

    let text_section = pe.sections.iter().find(|s| {
        let name = s.name_string();
        name == ".text" || name == "CODE"
    });
    let Some(sec) = text_section else {
        return Err("no .text/CODE section found".to_string());
    };
    let code_region = sec.raw_data(data);
    if code_region.is_empty() {
        return Err(".text section has no raw data".to_string());
    }

    use func_finder::{Architecture, FunctionFinder};
    use freakre_ir::x86_lifter::X86Lifter;
    use freakre_ir::Lifter;

    let arch = if pe.is_64bit {
        Architecture::X86_64
    } else {
        Architecture::X86
    };
    let finder = FunctionFinder::new(arch).with_code_base(sec.virtual_address as u64);
    let entry_va = pe.image_base + pe.entry_point as u64;
    let detected = finder
        .find_all(code_region, &[entry_va])
        .map_err(|e| format!("function detection failed: {e}"))?;
    if detected.is_empty() {
        return Err("no functions detected in .text".to_string());
    }

    // Prefer the function containing the requested address; fall back to the
    // largest detected function. The detected start addresses are section-
    // relative (`code_base` = section VA), so translate the image-absolute
    // caller address into that space.
    let rel_addr = address.map(|a| a.saturating_sub(pe.image_base));
    let chosen = rel_addr.and_then(|a| {
        detected
            .iter()
            .find(|f| f.start <= a && a < f.start + f.size as u64)
            .or_else(|| detected.iter().filter(|f| f.start <= a).max_by_key(|f| f.start))
    });
    let func = chosen.unwrap_or_else(|| {
        detected
            .iter()
            .max_by_key(|f| f.size)
            .or_else(|| detected.first())
            .expect("detected is non-empty")
    });

    let func_slice = crate::scanner::carve_func_slice(
        code_region,
        sec.virtual_address as u64,
        func.start,
        func.size,
    )
    .ok_or_else(|| "detected function lies outside .text bounds".to_string())?;

    let lifter = match pe_image_ctx(&pe, data) {
        Some(img) => X86Lifter::new(pe.is_64bit).with_image(img),
        None => X86Lifter::new(pe.is_64bit),
    };
    let func_name = format!("sub_{:X}", func.start);
    let mut ir_func = lifter
        .lift_function(func_slice, func.start, &func_name)
        .map_err(|e| format!("IR lift failed: {e}"))?;
    resolve_indirect_calls_emu(
        &mut ir_func,
        code_region,
        sec.virtual_address as u64,
        func.start,
        &pe_data_windows(&pe, data),
    );

    let string_table = build_string_table(&pe, data);
    let (c_code, events) =
        decompiler::decompile_function_with_strings_and_events(&ir_func, &string_table);
    let c_code = c_code.map_err(|e| format!("decompilation failed: {e}"))?;

    Ok(DecompiledFunction {
        address: func.start,
        name: func_name,
        size: func.size as u64,
        c_code,
        events,
    })
}

/// Decompile ONE function with an explicit byte size, bypassing the
/// detection-based size guess. For callers that know exact boundaries
/// (e.g. from a linker map file): the slice `[address, address+size)`
/// is lifted and decompiled as-is.
pub fn decompile_pe_function_sized(
    data: &[u8],
    address: u64,
    size: usize,
) -> Result<DecompiledFunction, String> {
    let pe = pe_parser::PeFile::parse(data)
        .map_err(|e| format!("not a parseable PE image: {e}"))?;
    let text_section = pe.sections.iter().find(|s| {
        let name = s.name_string();
        name == ".text" || name == "CODE"
    });
    let Some(sec) = text_section else {
        return Err("no .text/CODE section found".to_string());
    };
    let code_region = sec.raw_data(data);
    if code_region.is_empty() {
        return Err(".text section has no raw data".to_string());
    }

    use freakre_ir::x86_lifter::X86Lifter;
    use freakre_ir::Lifter;

    let rel = address.saturating_sub(pe.image_base);
    let func_slice = crate::scanner::carve_func_slice(
        code_region,
        sec.virtual_address as u64,
        rel,
        size,
    )
    .ok_or("requested function lies outside .text bounds")?;
    let lifter = match pe_image_ctx(&pe, data) {
        Some(img) => X86Lifter::new(pe.is_64bit).with_image(img),
        None => X86Lifter::new(pe.is_64bit),
    };
    let func_name = format!("sub_{rel:X}");
    let mut ir_func = lifter
        .lift_function(func_slice, rel, &func_name)
        .map_err(|e| format!("IR lift failed: {e}"))?;
    resolve_indirect_calls_emu(
        &mut ir_func,
        code_region,
        sec.virtual_address as u64,
        rel,
        &pe_data_windows(&pe, data),
    );
    let string_table = build_string_table(&pe, data);
    let (c_code, events) =
        decompiler::decompile_function_with_strings_and_events(&ir_func, &string_table);
    let c_code = c_code.map_err(|e| format!("decompilation failed: {e}"))?;
    Ok(DecompiledFunction {
        address: rel,
        name: func_name,
        size: size as u64,
        c_code,
        events,
    })
}

/// Decompile EVERY detected function in the PE's `.text` section.
///
/// Bench harness entry point: runs func-finder over the whole `.text`,
/// lifts and decompiles each detected function independently. Functions
/// whose lift/decompile fails are skipped (reported through
/// `DecompiledFunction::size == 0` never happens — failures are simply
/// absent from the result, counted by the caller via the original count).
pub fn decompile_pe_all_functions(data: &[u8]) -> Result<Vec<DecompiledFunction>, String> {
    let pe = pe_parser::PeFile::parse(data)
        .map_err(|e| format!("not a parseable PE image: {e}"))?;

    let text_section = pe.sections.iter().find(|s| {
        let name = s.name_string();
        name == ".text" || name == "CODE"
    });
    let Some(sec) = text_section else {
        return Err("no .text/CODE section found".to_string());
    };
    let code_region = sec.raw_data(data);
    if code_region.is_empty() {
        return Err(".text section has no raw data".to_string());
    }

    use func_finder::{Architecture, FunctionFinder};
    use freakre_ir::x86_lifter::X86Lifter;
    use freakre_ir::Lifter;

    let arch = if pe.is_64bit {
        Architecture::X86_64
    } else {
        Architecture::X86
    };
    let finder = FunctionFinder::new(arch).with_code_base(sec.virtual_address as u64);
    let entry_va = pe.image_base + pe.entry_point as u64;
    let detected = finder
        .find_all(code_region, &[entry_va])
        .map_err(|e| format!("function detection failed: {e}"))?;

    let string_table = build_string_table(&pe, data);
    let windows = pe_data_windows(&pe, data);
    let lifter = match pe_image_ctx(&pe, data) {
        Some(img) => X86Lifter::new(pe.is_64bit).with_image(img),
        None => X86Lifter::new(pe.is_64bit),
    };
    let mut detected: Vec<_> = detected;
    detected.sort_by_key(|f| f.start);
    let sec_end = sec.virtual_address as u64 + code_region.len() as u64;
    // Extend each function's lift window to the next detected start: jump
    // tables terminate detection early (indirect jmp reads as a terminator),
    // while the switch case bodies live past that point and must be inside
    // the slice for table recovery to lift them.
    let extended: Vec<(u64, usize)> = detected
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let next = detected
                .get(i + 1)
                .map(|n| n.start)
                .unwrap_or(sec_end);
            let sz = ((next - f.start) as usize).max(f.size);
            (f.start, sz.min(code_region.len()))
        })
        .collect();
    let mut out = Vec::new();
    for (i, _func) in detected.iter().enumerate() {
        let (fstart, fsize) = extended[i];
        let Some(func_slice) = crate::scanner::carve_func_slice(
            code_region,
            sec.virtual_address as u64,
            fstart,
            fsize,
        ) else {
            continue;
        };
        let func_name = format!("sub_{fstart:X}");
        let Ok(mut ir_func) = lifter.lift_function(func_slice, fstart, &func_name) else {
            continue;
        };
        resolve_indirect_calls_emu(
            &mut ir_func,
            code_region,
            sec.virtual_address as u64,
            fstart,
            &windows,
        );
        if let (Ok(c_code), events) =
            decompiler::decompile_function_with_strings_and_events(&ir_func, &string_table)
        {
            out.push(DecompiledFunction {
                address: fstart,
                name: func_name,
                size: fsize as u64,
                c_code,
                events,
            });
        }
    }
    Ok(out)
}

/// Emulation-assisted indirect-call resolution.
///
/// One bounded emulation run over the `.text` view; opaque `call reg`
/// targets that land inside the section become concrete references the
/// decompiler can name. Any doubt (never executed, polymorphic, out of
/// section) leaves the call untouched.
fn resolve_indirect_calls_emu(
    ir_func: &mut freakre_ir::IrFunction,
    code_region: &[u8],
    section_va: u64,
    func_base: u64,
    windows: &[(u64, &[u8])],
) {
    use emulator_x86::emu_resolve;
    const EMU_BUDGET_STEPS: u64 = 20_000;
    let resolved = emu_resolve::resolve_indirect_calls_with_data(
        ir_func,
        code_region,
        section_va,
        func_base,
        EMU_BUDGET_STEPS,
        windows,
    );
    if !resolved.is_empty() {
        emu_resolve::apply_resolved_calls(ir_func, func_base, &resolved);
    }
}

/// Raw bytes of every non-executable section mapped at its virtual
/// address, so emulation can read vtables and data pointers.
fn pe_data_windows<'a>(pe: &pe_parser::PeFile, data: &'a [u8]) -> Vec<(u64, &'a [u8])> {
    pe.sections
        .iter()
        .filter(|s| s.name_string() != ".text" && s.name_string() != "CODE")
        .filter_map(|s| {
            let raw = s.raw_data(data);
            (!raw.is_empty()).then_some((s.virtual_address as u64, raw))
        })
        .collect()
}

/// Synthesize a section-aligned view of the PE at its image base so the
/// x86 lifter can read jump tables (and other data) by virtual address.
fn pe_image_ctx(pe: &pe_parser::PeFile, data: &[u8]) -> Option<freakre_ir::x86_lifter::ImageCtx> {
    let mut end = 0u64;
    let mut sections = Vec::new();
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let sz = s.virtual_size.max(s.raw_data_size) as u64;
        if sz == 0 {
            continue;
        }
        sections.push((va, sz));
        end = end.max(va + sz);
    }
    if sections.is_empty() || end == 0 {
        return None;
    }
    let mut bytes = vec![0u8; end as usize];
    for s in &pe.sections {
        let raw = s.raw_data(data);
        if raw.is_empty() {
            continue;
        }
        let off = s.virtual_address as usize;
        if off + raw.len() <= bytes.len() {
            bytes[off..off + raw.len()].copy_from_slice(raw);
        }
    }
    Some(freakre_ir::x86_lifter::ImageCtx::new(
        sections,
        pe.image_base,
        bytes,
    )
    .in_coord_base(0))
}

/// Build a virtual-address → string table for the whole PE image.
///
/// Strings are extracted from every section's raw data and mapped to their
/// virtual addresses (`image_base + section VA + file offset`), so
/// decompiled references like `f(0x14001000)` render as `f("...")`.
/// ASCII only, minimum 5 characters — UTF-16 API strings on Windows are
/// passed via explicit pointer math and rarely appear as bare constants.
fn build_string_table(pe: &pe_parser::PeFile, data: &[u8]) -> decompiler::StringTable {
    let mut table = decompiler::StringTable::new();
    let config = str_extract::ExtractConfig::ascii_only(5);
    for s in str_extract::extract_strings(data, &config) {
        let file_off = s.offset;
        // Find the section whose raw data range contains this offset.
        for sec in &pe.sections {
            let start = sec.raw_data_offset as usize;
            let end = start.saturating_add(sec.raw_data_size as usize);
            if file_off >= start && file_off < end {
                let va = pe.image_base
                    + sec.virtual_address as u64
                    + (file_off - start) as u64;
                table.insert(va, s.value.clone());
                break;
            }
        }
    }
    table
}

/// Decompile and wrap failures as a `DECOMPILE_FAILED`-style finding list.
///
/// Convenience for callers that want the same finding shape as the scanner.
pub fn decompile_pe_function_findings(
    data: &[u8],
    address: Option<u64>,
) -> Vec<Finding> {
    match decompile_pe_function(data, address) {
        Ok(f) => vec![Finding {
            severity: Severity::Info,
            module: "decompiler".into(),
            rule_id: "DECOMPILED_CODE".into(),
            description: format!(
                "Decompiled function {} at 0x{:X} ({} bytes)",
                f.name, f.address, f.size
            ),
            details: Some(f.c_code.lines().take(20).collect::<Vec<_>>().join("\n")),
        }],
        Err(e) => vec![Finding {
            severity: Severity::Low,
            module: "decompiler".into(),
            rule_id: "DECOMPILE_FAILED".into(),
            description: e,
            details: None,
        }],
    }
}
