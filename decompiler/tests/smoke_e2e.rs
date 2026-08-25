//! End-to-end smoke test: lift real bytes through the x86 lifter and
//! decompile them, verifying the pipeline emits sane pseudocode.

use decompiler::decompile_function;
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::Lifter;

fn lift(code: &[u8], addr: u64, name: &str, is64: bool) -> Result<freakre_ir::IrFunction, String> {
    let lifter = X86Lifter::new(is64);
    lifter
        .lift_function(code, addr, name)
        .map_err(|e| e.to_string())
}

/// Classic prologue sequence valid in both modes.
const PROLOGUE: [u8; 8] = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];

#[test]
fn e2e_lift_and_decompile_prologue() {
    let ir = lift(&PROLOGUE, 0x1000, "smoke", true).expect("lifter failed");

    let c = decompile_function(&ir).expect("decompiler failed");
    println!("---- lifted C ----\n{}", c);

    assert!(c.contains("smoke"), "function name missing:\n{}", c);
    assert!(c.contains("return"), "no return emitted:\n{}", c);
}

#[test]
fn e2e_repo_sample_shellcode_if_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sample_shellcode.bin");
    if !path.exists() {
        return; // optional sample
    }
    let code = std::fs::read(&path).unwrap();
    if let Ok(ir) = lift(&code, 0x401000, "sample", true) {
        let c = decompile_function(&ir).unwrap();
        // Structural soundness: any goto must have a matching label.
        for line in c.lines() {
            let t = line.trim_start();
            if t.starts_with("goto ") {
                let label = t.trim_start_matches("goto ").trim_end_matches(';');
                assert!(
                    c.contains(&format!("{}:", label)),
                    "goto without label '{}':\n{}",
                    label,
                    c
                );
            }
        }
    }
}
