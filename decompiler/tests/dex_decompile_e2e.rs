//! End-to-end: dalvik bytecode → IR → C. Proves the DEX path through the
//! whole decompiler pipeline (SSA, structuring, patterns, emission).

use decompiler::decompile_function;
use freakre_ir::dex_lifter::{lift_dex_method, DexNames};

fn decompile_dex(insns: &[u16], registers: usize) -> String {
    let func = lift_dex_method(insns, registers, "Lcom/example/Main;run()V", &DexNames::default());
    decompile_function(&func).expect("decompile must succeed")
}

#[test]
fn dex_arithmetic_loop_decompiles() {
    // int sum(int n) { int s = 0; for (int i = 0; i != n; i = i + 1) s = s + i; return s; }
    // Hand-encoded dalvik:
    //   const/4 v0, #0          ; s
    //   const/4 v1, #0          ; i
    // loop:
    //   if-eq v1, v2, done      ; i != n ?
    //   add-int/2addr v0, v1    ; s += i
    //   add-int/lit8 v1, v1, #1 ; i++
    //   goto loop
    // done:
    //   return v0
    let insns: Vec<u16> = vec![
        0x12, // 0: const/4 v0, #0
        0x12 | (1 << 8), // 1: const/4 v1, #0
        // 2: if-eq v1, v2, +4 (to unit 6)
        0x32 | (1 << 8) | (2 << 12), 4,
        // 4: add-int/2addr v0, v1
        0xb0 | (1 << 12),
        // 5: add-int/lit8 v1, v1, #1
        0xd8 | (1 << 8), (1) | (1 << 8),
        // 6... wait: if-eq occupies units 2-3, so next is 4 (2addr, 1 unit),
        // 5 (lit8, 2 units: opcode+operands). goto back to 2 from 7: offset
        // -5.
        0x29, (-5i16) as u16, // 7-8: goto/16 -5 → unit 2
        0x0f, // 9: return v0
    ];
    let c = decompile_dex(&insns, 4);
    // The loop must survive structuring as a loop (while/for/do-while), not
    // as raw gotos everywhere.
    assert!(
        c.contains("while") || c.contains("for") || c.contains("do"),
        "backward goto must become a structured loop:\n{}",
        c
    );
    assert!(
        c.contains("cmp"),
        "comparison must flow into the C output:\n{}",
        c
    );
}

#[test]
fn dex_call_and_result_flow() {
    // s = "hello"; foo(s); return foo(s);
    let insns: Vec<u16> = vec![
        0x1a, 5, // 0-1: const-string v0, string@5
        0x71 | (1 << 12), 9, 0, 0, // 2-5: invoke-static {v0}, method@9
        0x0a | (1 << 8), // 6: move-result v1
        0x0f | (1 << 8), // 7: return v1
    ];
    let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
    let c = decompile_function(&func).expect("decompile must succeed");
    // The symbolic method reference reaches the C output (call naming
    // sanitizes `@` to `_`).
    assert!(
        c.contains("method_9") || c.contains("method@9"),
        "symbolic references must reach the C output:\n{}",
        c
    );
}

#[test]
fn dex_sparse_junk_does_not_break_pipeline() {
    // Random code units — the decoder must stay total and the pipeline must
    // produce *some* valid C.
    let insns: Vec<u16> = (0u16..200)
        .map(|i| i.wrapping_mul(0x9D3F).wrapping_add(0x1337))
        .collect();
    let func = lift_dex_method(&insns, 16, "junk", &DexNames::default());
    let c = decompile_function(&func).expect("decompile must succeed on junk");
    assert!(c.contains("void"), "C output must exist:\n{}", c);
}
