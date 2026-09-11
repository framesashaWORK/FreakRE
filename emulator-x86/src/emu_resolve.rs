//! Emulation-assisted decompilation support.
//!
//! Runs a lifted function once under the interpreter and reports where
//! indirect calls landed, so the decompiler can rewrite opaque
//! `call reg` / `call [vtable+N]` sites into concrete `func_XXXX`
//! references. Conservative: a call site only resolves when the run
//! reaches it, the computed target lies inside the mapped image, and
//! repeated visits agree.

use crate::exec::Emulator;
use crate::env::DefaultEnv;
use freakre_ir::{IrFunction, IrInst, Value};

/// Per-block address of a call whose target is statically opaque.
type Site = (u64, u32);

/// Enumerate the dynamically-targeted calls of `func`, keyed by
/// (block address, ordinal among that block's dynamic calls).
fn dynamic_sites(func: &IrFunction, base: u64) -> Vec<Site> {
    let mut sites = Vec::new();
    for block in &func.blocks {
        let baddr = crate::exec::block_address(&block.label, base);
        let Some(baddr) = baddr else { continue };
        let mut ord = 0u32;
        for inst in &block.insts {
            if let IrInst::Call { target, .. } = inst {
                let dynamic = !matches!(target,
                    Value::Const(_) | Value::Symbol(_));
                if dynamic {
                    sites.push((baddr, ord));
                    ord += 1;
                }
            }
        }
    }
    sites
}

/// Resolve indirect call targets for `func` by emulating one path through it.
///
/// Returns a map of (block address, dynamic-call ordinal) → concrete target
/// address. Block addresses and resolved targets are in `func_base` space;
/// `image` is the guest memory window mapped at `image_base` (may span more
/// than the function itself, e.g. the whole executable section). Only sites
/// whose computed target falls inside the image window are reported; a site
/// that resolves to different targets across executions stays opaque.
pub fn resolve_indirect_calls(
    func: &IrFunction,
    image: &[u8],
    image_base: u64,
    func_base: u64,
    max_steps: u64,
) -> std::collections::HashMap<Site, u64> {
    resolve_indirect_calls_with_data(func, image, image_base, func_base, max_steps, &[])
}

/// Like [`resolve_indirect_calls`], but with additional read-only guest
/// windows (e.g. `.rdata`/`.data` raw bytes mapped at their virtual
/// addresses) so memory-indirect calls through tables
/// (`call [rax+0x188]` where `rax` was loaded from a vtable) resolve too.
pub fn resolve_indirect_calls_with_data(
    func: &IrFunction,
    image: &[u8],
    image_base: u64,
    func_base: u64,
    max_steps: u64,
    data_windows: &[(u64, &[u8])],
) -> std::collections::HashMap<Site, u64> {
    let sites = dynamic_sites(func, func_base);
    if sites.is_empty() {
        return Default::default();
    }
    // Sites in blocks unreachable from entry never execute; skipping them
    // avoids paying the emulation budget on exception/handler tables that
    // CRT code carries but a single-path run can never observe.
    let reachable: std::collections::HashSet<u64> = {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![func.entry_block];
        while let Some(b) = stack.pop() {
            if !seen.insert(b) {
                continue;
            }
            if let Some(block) = func.blocks.get(b.0 as usize) {
                for s in func.successors(b) {
                    stack.push(s);
                }
            }
        }
        seen.into_iter()
            .filter_map(|b| func.blocks.get(b.0 as usize))
            .filter_map(|block| crate::exec::block_address(&block.label, func_base))
            .collect()
    };
    if !sites.iter().any(|(baddr, _)| reachable.contains(baddr)) {
        return Default::default();
    }
    let image_end = image_base + image.len() as u64;
    let mut emu = Emulator::new(DefaultEnv::new());
    emu.load_image(image_base, image);
    for (base, bytes) in data_windows {
        emu.load_image(*base, bytes);
    }
    let res = emu.run(func, func_base, 0, max_steps);

    // Block address → dynamic-call ordinals observed, in execution order.
    let mut observed: std::collections::HashMap<u64, Vec<u64>> =
        std::collections::HashMap::new();
    for call in &res.calls {
        let Some(target) = call.target else {
            continue;
        };
        if target < image_base || target >= image_end {
            continue;
        }
        observed.entry(call.at).or_default().push(target);
    }

    let mut out = std::collections::HashMap::new();
    for (baddr, ord) in sites.iter().copied() {
        let Some(records) = observed.get(&baddr) else {
            continue; // site never executed — no verdict
        };
        let Some(target) = records.get(ord as usize) else {
            continue; // fewer executions than sites — no verdict
        };
        // Every visit to this block must resolve this ordinal identically.
        let dyn_count = sites.iter().filter(|(b, _)| *b == baddr).count().max(1);
        let stable = records
            .iter()
            .enumerate()
            .all(|(i, t)| i % dyn_count != ord as usize || t == target);
        if stable {
            out.insert((baddr, ord), *target);
        }
    }
    out
}

/// Rewrite dynamically-targeted calls with emulated concrete targets.
///
/// A block is rewritten only when it contains exactly one dynamic call and
/// that site resolved. Direct calls are left untouched.
pub fn apply_resolved_calls(
    func: &mut IrFunction,
    base: u64,
    resolved: &std::collections::HashMap<Site, u64>,
) -> usize {
    let mut rewritten = 0;
    for block in &mut func.blocks {
        let Some(baddr) = crate::exec::block_address(&block.label, base) else {
            continue;
        };
        let dyn_indices: Vec<usize> = block
            .insts
            .iter()
            .enumerate()
            .filter(|(_, i)| matches!(i, IrInst::Call { target, .. }
                if !matches!(target, Value::Const(_) | Value::Symbol(_))))
            .map(|(idx, _)| idx)
            .collect();
        if dyn_indices.len() != 1 {
            continue;
        }
        let idx = dyn_indices[0];
        if let Some(target) = resolved.get(&(baddr, 0)) {
            let target = *target;
            if let IrInst::Call { target: slot, .. } = &mut block.insts[idx] {
                *slot = Value::Const(target as i64);
                rewritten += 1;
            }
        }
    }
    rewritten
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{Lifter, x86_lifter::X86Lifter};

    /// x64: `lea rax, [rip+target]; call rax; ret` — an opaque-register call
    /// that only resolves through execution. Then a plain `call rel32` for
    /// contrast (already static, reported the same way).
    #[test]
    fn resolves_register_indirect_call() {
        // Layout (base 0x1000):
        //   0x1000: 48 8D 05 xx xx xx xx   lea rax, [rip+disp32]  -> 0x1010
        //   0x1007: FF D0                  call rax
        //   0x1009: C3                     ret
        //   0x100A..0x100F: padding nops
        //   0x1010: C3                     ret   (the callee)
        let mut code = vec![0u8; 0x20];
        code[0..7].copy_from_slice(&[0x48, 0x8D, 0x05, 0x09, 0x00, 0x00, 0x00]);
        code[7] = 0xFF; // call rax
        code[8] = 0xD0;
        code[9] = 0xC3; // ret
        for b in &mut code[0x0A..0x10] {
            *b = 0x90;
        }
        code[0x10] = 0xC3; // callee: ret

        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x1000, "t").expect("lift");
        let map = resolve_indirect_calls(&func, &code, 0x1000, 0x1000, 10_000);
        assert_eq!(
            map.get(&(0x1000, 0)),
            Some(&0x1010),
            "indirect call in block 0x1000 must resolve to the lea target; got {:?}",
            map
        );

        // Applying the resolution turns the opaque call into a concrete one.
        let mut func = lifter.lift_function(&code, 0x1000, "t").expect("lift");
        let rewritten = apply_resolved_calls(&mut func, 0x1000, &map);
        assert_eq!(rewritten, 1, "exactly one dynamic call must be rewritten");
        let has_concrete = func.blocks.iter().any(|b| {
            b.insts.iter().any(|i| matches!(
                i,
                IrInst::Call { target: Value::Const(0x1010), .. }
            ))
        });
        assert!(has_concrete, "call target must be rewritten to Const(0x1010)");
    }

    /// x64 vtable dispatch: `mov rax, [rip+obj]; call [rax+8]` — the object
    /// field holds the vtable base and the callee pointer lives in a DATA
    /// window (`.rdata`), not in the code image. Resolution must succeed
    /// only when the data window is mapped.
    #[test]
    fn resolves_vtable_dispatch_through_data_window() {
        // Code (base 0x1000):
        //   0x1000: 48 8B 05 disp32      mov rax, [rip+disp] -> 0x2000
        //   0x1007: 48 FF 50 08          call qword [rax+8]
        //   0x100B: C3                   ret
        //   0x100C..0x100F: nops
        //   0x1010: C3                   vtable[0] target (ret)
        //   0x1011: C3                   vtable[1] target (ret)
        let mut code = vec![0u8; 0x20];
        // disp = 0x2000 - (0x1000 + 7) = 0xFF9
        code[0..7].copy_from_slice(&[0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00]);
        code[7..11].copy_from_slice(&[0x48, 0xFF, 0x50, 0x08]); // call [rax+8]
        code[11] = 0xC3; // ret
        for b in &mut code[0x0C..0x10] {
            *b = 0x90;
        }
        code[0x10] = 0xC3;
        code[0x11] = 0xC3;

        // .rdata window at 0x2000: object field -> vtable base 0x2010,
        // vtable at 0x2010 with two qword entries.
        let mut rdata = vec![0u8; 0x20];
        rdata[0..8].copy_from_slice(&0x2010u64.to_le_bytes());
        rdata[0x10..0x18].copy_from_slice(&0x1010u64.to_le_bytes());
        rdata[0x18..0x20].copy_from_slice(&0x1011u64.to_le_bytes());

        let lifter = X86Lifter::new(true);
        let func = lifter.lift_function(&code, 0x1000, "t").expect("lift");

        // Without the data window the load reads zeros -> opaque.
        let no_data = resolve_indirect_calls(&func, &code, 0x1000, 0x1000, 10_000);
        assert!(
            no_data.is_empty(),
            "must not resolve without the .rdata window: {no_data:?}"
        );

        // With the .rdata window the vtable entry resolves.
        let map = resolve_indirect_calls_with_data(
            &func,
            &code,
            0x1000,
            0x1000,
            10_000,
            &[(0x2000, &rdata)],
        );
        assert_eq!(
            map.get(&(0x1000, 0)),
            Some(&0x1011),
            "call [rax+8] must resolve to vtable[1] = 0x1011; got {map:?}"
        );
    }
}
