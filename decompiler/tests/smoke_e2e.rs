//! End-to-end smoke test: lift real bytes through the x86 lifter and
//! decompile them, verifying the pipeline emits sane pseudocode.

use decompiler::decompile_function;
use freakre_ir::x86_lifter::X86Lifter;
use freakre_ir::{IrInst, Lifter};

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

/// x64 call with register arguments: `mov ecx,1; mov edx,2; call f; ret`.
/// The lifter must recover `f(1, 2)` — argument values flow into the C.
#[test]
fn e2e_call_args_recovered() {
    // mov ecx, 1 / mov edx, 2 / call rel32 (target = next insn) / ret
    let code: [u8; 15] = [
        0xB9, 0x01, 0x00, 0x00, 0x00, 0xBA, 0x02, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
    ];
    let ir = lift(&code, 0x1000, "caller", true).expect("lifter failed");
    let c = decompile_function(&ir).expect("decompiler failed");
    println!("---- caller C ----\n{}", c);

    assert!(
        c.contains("func_100F(0x1, 0x2)"),
        "call args not recovered:\n{}",
        c
    );
}

/// Signedness from comparisons: unsigned `jb` must print `(uint64_t)`
/// widening casts; signed `jl` must print a plain `<` without casts.
#[test]
fn e2e_cmp_signedness_in_c() {
    // jb: cmp eax,5; jb skip; mov eax,1; ret; skip: ret
    let jb_code: [u8; 12] = [
        0x83, 0xF8, 0x05, 0x72, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3,
    ];
    let ir = lift(&jb_code, 0x1000, "ub", true).expect("lifter failed");
    let c = decompile_function(&ir).expect("decompile failed");
    assert!(
        c.contains("(uint64_t)"),
        "unsigned comparison must widen:\n{}",
        c
    );

    // jl: same shape, signed branch (7C)
    let jl_code: [u8; 12] = [
        0x83, 0xF8, 0x05, 0x7C, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3,
    ];
    let ir = lift(&jl_code, 0x1000, "sb", true).expect("lifter failed");
    let c = decompile_function(&ir).expect("decompile failed");
    assert!(
        !c.contains("(uint64_t)") && c.contains("<"),
        "signed comparison must stay plain:\n{}",
        c
    );
}

/// A real x64 jump-table dispatch:
/// `cmp eax,1; ja default; jmp [rip-disp table]` with two in-function
/// cases. The lifter (with an image) must turn `IndirectBranch` into
/// `Switch`, and the decompiler must print a C `switch`.
#[test]
fn e2e_jump_table_decompiles_to_switch() {
    use freakre_ir::x86_lifter::ImageCtx;

    // Code at 0x14001000 (base 0x14000000):
    //   0x14001000: 83 F8 01        cmp eax, 1
    //   0x14001003: 77 0E           ja +0x0E -> 0x14001013 (default)
    //   0x14001005: 48 FF 24 C5 xx  jmp [disp32 + rax*8]  (table of VAs)
    //   0x1400100D: B8 01 00 00 00 C3  mov eax,1; ret   (case 0)
    //   0x14001013: B8 00 00 00 00 C3  mov eax,0; ret   (default)
    let mut code: Vec<u8> = [
        0x83, 0xF8, 0x01, 0x77, 0x0E, 0x48, 0xFF, 0x24, 0xC5, // up to disp32
    ]
    .to_vec();
    let base = 0x14000000u64;
    let func_va = 0x14001000u64;
    let table_va = 0x14002000u64;
    let jmp_next = func_va + 13; // after REX+FF+modrm+SIB+disp32
    let disp = (table_va as i64).wrapping_sub(jmp_next as i64) as i32; // disp32
    code.extend_from_slice(&disp.to_le_bytes());
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // case 0
    code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]); // default

    let mut image = code.clone();
    image.resize(0x2100, 0);
    let entries: [u64; 2] = [0x1400100D, 0x14001013];
    for (i, e) in entries.iter().enumerate() {
        let off = (table_va - base) as usize + i * 8;
        image[off..off + 8].copy_from_slice(&e.to_le_bytes());
    }

    // Sections are given in the image-offset coordinate space (0 = image_base).
    let ctx = ImageCtx::new(vec![(0, image.len() as u64)], base, image);
    let lifter = X86Lifter::new(true).with_image(ctx);
    let ir = lifter
        .lift_function(&code, func_va, "jt_func")
        .expect("lifter failed");

    println!("code bytes: {}", code.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
    let mut hit = 0usize;
    for b in &ir.blocks {
        if let Some(IrInst::Switch { cases, .. }) = b.terminator() {
            println!("SWITCH in bb{} with {} cases", b.id.0, cases.len());
            hit += 1;
        }
    }
    assert!(hit > 0, "no Switch recovered");

    let c = decompile_function(&ir).expect("decompile failed");
    println!("---- jump-table C ----\n{}", c);

    assert!(
        c.contains("switch"),
        "indirect jump must decompile to switch:\n{}",
        c
    );
    assert!(c.contains("case "), "case labels missing:\n{}", c);
    assert!(
        c.contains("0x1") || c.contains("= 1;") || c.contains("= 1u"),
        "case-0 body (eax=1) missing:\n{}",
        c
    );
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
