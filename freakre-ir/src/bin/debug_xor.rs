use freakre_ir::lifter::Lifter;
use freakre_ir::x86_lifter::X86Lifter;

fn block_address(label: &str, base: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
        return rest.parse::<usize>().ok().map(|o| base.wrapping_add(o as u64));
    }
    if let Some(rest) = label.strip_prefix("loc_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = label.strip_prefix("fall_") {
        return u64::from_str_radix(rest, 16).ok();
    }
    if label == "entry" {
        return Some(base);
    }
    None
}

const XOR_LOOP: [u8; 14] = [0x80, 0x34, 0x07, 0x37, 0x48, 0xFF, 0xC0, 0x48, 0x83, 0xF8, 0x08, 0x7C, 0xF3, 0xC3];
const BASE: u64 = 0x0040_1000;

fn main() {
    let lifter = X86Lifter::new(true);
    let func = lifter.lift_function(&XOR_LOOP, BASE, "xor_stub").unwrap();
    for b in &func.blocks {
        println!("block {} label='{}' id={:?} insts={} source_range={:?}", b.id.0, b.label, b.id, b.insts.len(), b.source_range);
        for inst in &b.insts {
            println!("  {:?}", inst);
        }
    }
    println!("entry_block {:?}", func.entry_block);
    // Try find_entry_block for offset 4
    let want = BASE + 4;
    for b in &func.blocks {
        let addr = block_address(&b.label, BASE);
        println!("block {} label {} -> addr {:?}", b.id.0, b.label, addr);
        if addr == Some(want) {
            println!("  MATCH for want 0x{:X}", want);
        }
        if let Some((s,e)) = b.source_range {
            if want >= s && want < e {
                println!("  source_range MATCH");
            }
        }
    }
}
