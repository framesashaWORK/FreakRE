//! Probe: dump lifted IR for known instruction sequences to verify
//! displacement handling, push/pop modeling and SSE stores.
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::Lifter;

fn dump(code: &[u8]) -> String {
    let lifter = X86Lifter::new(true);
    match lifter.lift_function(code, 0x1000, "probe") {
        Ok(f) => {
            let mut s = String::new();
            for b in &f.blocks {
                s.push_str(&format!("-- block {} --\n", b.id.0));
                for i in &b.insts {
                    s.push_str(&format!("  {:?}\n", i));
                }
            }
            s
        }
        Err(e) => format!("ERR: {:?}", e),
    }
}

#[test]
fn probe_mov_disp() {
    // mov rdx, [rbp-8]  = 48 8B 55 F8
    println!(
        "=== mov rdx,[rbp-8] ===\n{}",
        dump(&[0x48, 0x8B, 0x55, 0xF8, 0xC3])
    );
    // mov [rsp+0x20], rax = 48 89 44 24 20
    println!(
        "=== mov [rsp+0x20],rax ===\n{}",
        dump(&[0x48, 0x89, 0x44, 0x24, 0x20, 0xC3])
    );
    // push rbp; mov rbp,rsp; push r15
    println!(
        "=== push rbp; mov rbp,rsp; push r15 ===\n{}",
        dump(&[0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0xC3])
    );
    // movaps [rsp+0x20], xmm6 = 44 0F 29 74 24 20
    println!(
        "=== movaps [rsp+0x20],xmm6 ===\n{}",
        dump(&[0x44, 0x0F, 0x29, 0x74, 0x24, 0x20, 0xC3])
    );
}
