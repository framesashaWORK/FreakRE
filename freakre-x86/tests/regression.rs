//! Regression tests for previously confirmed decoder/LDE bugs.
//! Every test here failed before the corresponding fix.

use freakre_x86::decoder::decode as dec;
use freakre_x86::types::*;
use freakre_x86::{decode_len, format_instruction};

fn fmt(code: &[u8], addr: u64, mode: Mode) -> String {
    format_instruction(&dec(code, addr, mode).unwrap())
}

// в”Ђв”Ђ LDE length bugs в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[test]
fn lde_jcc_rel32_is_six_bytes() {
    // je rel32: 0F 84 xx xx xx xx
    let code = [0x0F, 0x84, 0x10, 0x00, 0x00, 0x00];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 6);
    assert_eq!(dec(&code, 0x1000, Mode::X64).unwrap().length, 6);
}

#[test]
fn lde_bswap_has_no_modrm() {
    // bswap edx: 0F CA вЂ” exactly 2 bytes, no ModR/M byte
    let code = [0x0F, 0xCA];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 2);
    assert_eq!(fmt(&code, 0, Mode::X64), "bswap edx");
}

#[test]
fn lde_moffs32_without_rex_w() {
    // mov eax, moffs32 (A1): opcode + 4-byte address in x64 without REX.W
    let code = [0xA1, 0x00, 0x20, 0x40, 0x00];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 5);
}

#[test]
fn lde_moffs64_with_rex_w() {
    let mut code = vec![0x48, 0xA1, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 10);
    let insn = dec(&code, 0, Mode::X64).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::Mov);
    code[1] = 0xA1;
}

#[test]
fn lde_rdtsc_cpuid_are_two_bytes() {
    // 0F 31 rdtsc / 0F A2 cpuid вЂ” no ModR/M
    assert_eq!(decode_len(&[0x0F, 0x31], Mode::X64).unwrap(), 2);
    assert_eq!(decode_len(&[0x0F, 0xA2], Mode::X64).unwrap(), 2);
}

#[test]
fn lde_imul_imm8_length() {
    // imul ecx, dword ptr [rax], 5 в†’ 6B 08 05 = 3 bytes
    let code = [0x6B, 0x08, 0x05];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 3);
}

#[test]
fn lde_test_rm8_imm8_length() {
    // test byte ptr [rcx], 0xFF в†’ F6 01 FF = 3 bytes
    let code = [0xF6, 0x01, 0xFF];
    assert_eq!(decode_len(&code, Mode::X64).unwrap(), 3);
    // test eax, 0x41 в†’ A9 41 00 00 00 = 5 bytes; but F7 /0 with modrm:
    let code2 = [0xF7, 0xC1, 0x39, 0x05, 0x00, 0x00]; // test ecx, 0x539
    assert_eq!(decode_len(&code2, Mode::X64).unwrap(), 6);
}

// в”Ђв”Ђ Decoder operand bugs в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[test]
fn decode_movsx_dest_and_src_sizes() {
    // movsx esi, al: reg field 7 = esi (dword), rm 0 = al (byte)
    assert_eq!(fmt(&[0x0F, 0xBE, 0xF0], 0, Mode::X64), "movsx esi, al");
    // movsx rax, al with REX.W: 48 0F BE C8 в†’ movsx rax, al
    assert_eq!(fmt(&[0x48, 0x0F, 0xBE, 0xC0], 0, Mode::X64), "movsx rax, al");
    // movzx edx, bx (register form reads the full 16-bit source): 0F B7 D3
    assert_eq!(
        fmt(&[0x0F, 0xB7, 0xD3], 0, Mode::X64),
        "movzx edx, bx"
    );
    // movzx edx, word ptr [rbx] (memory form): 0F B7 13
    assert_eq!(
        fmt(&[0x0F, 0xB7, 0x13], 0, Mode::X64),
        "movzx edx, word ptr [rbx]"
    );
}

#[test]
fn decode_movzx_uses_full_base_registers_in_x64() {
    // movzx eax, byte ptr [rax] вЂ” base must be rax, not eax
    assert_eq!(
        fmt(&[0x0F, 0xB6, 0x00], 0, Mode::X64),
        "movzx eax, byte ptr [rax]"
    );
}

#[test]
fn decode_push_pop_default_to_64bit_in_x64() {
    assert_eq!(fmt(&[0x50], 0, Mode::X64), "push rax");
    assert_eq!(fmt(&[0x55], 0, Mode::X64), "push rbp");
    assert_eq!(fmt(&[0x5D], 0, Mode::X64), "pop rbp");
    // 66 prefix shrinks them back to word
    assert_eq!(fmt(&[0x66, 0x50], 0, Mode::X64), "push ax");
    // In 32-bit mode they stay 32-bit
    assert_eq!(fmt(&[0x50], 0, Mode::X86), "push eax");
}

#[test]
fn decode_rex_swaps_high_bytes_for_low_bytes() {
    // 40 B4 05: REX present without B в†’ idx 4 is spl, not ah
    assert_eq!(fmt(&[0x40, 0xB4, 0x05], 0, Mode::X64), "mov spl, 0x5");
    // Without REX it stays ah
    assert_eq!(fmt(&[0xB4, 0x05], 0, Mode::X64), "mov ah, 0x5");
    // 41 B4 05 в†’ r12b
    assert_eq!(fmt(&[0x41, 0xB4, 0x05], 0, Mode::X64), "mov r12b, 0x5");
}

// в”Ђв”Ђ New opcode coverage в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

#[test]
fn coverage_alu_reg_forms() {
    // mov r/m,r and byte forms via generic ALU table
    assert_eq!(fmt(&[0x88, 0xC3], 0, Mode::X64), "mov bl, al");      // mov r/m8, r8
    assert_eq!(fmt(&[0x8A, 0xD9], 0, Mode::X64), "mov bl, cl");      // mov r8, r/m8
    assert_eq!(fmt(&[0x30, 0xDB], 0, Mode::X64), "xor bl, bl");      // xor r/m8, r8
    assert_eq!(fmt(&[0x39, 0xCA], 0, Mode::X64), "cmp edx, ecx");    // cmp r/m, r
}

#[test]
fn coverage_mov_imm_to_rm() {
    // mov dword ptr [rsp+0x10], 0 в†’ C7 44 24 10 00...
    let c = fmt(
        &[0xC7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00],
        0,
        Mode::X64,
    );
    assert_eq!(c, "mov dword ptr [rsp+0x10], 0x0");
}

#[test]
fn coverage_shift_group() {
    // shl eax, 4 в†’ C1 E0 04
    assert_eq!(fmt(&[0xC1, 0xE0, 0x04], 0, Mode::X64), "shl eax, 0x4");
    // shr eax, 1 в†’ D1 E8
    assert_eq!(fmt(&[0xD1, 0xE8], 0, Mode::X64), "shr eax, 0x1");
    // sar eax, cl в†’ D3 F8
    assert_eq!(fmt(&[0xD3, 0xF8], 0, Mode::X64), "sar eax, cl");
}

#[test]
fn coverage_group3_f7() {
    // neg rax в†’ 48 F7 D8
    assert_eq!(fmt(&[0x48, 0xF7, 0xD8], 0, Mode::X64), "neg rax");
    // not rax в†’ 48 F7 D0
    assert_eq!(fmt(&[0x48, 0xF7, 0xD0], 0, Mode::X64), "not rax");
    // div rbx в†’ 48 F7 F3
    assert_eq!(fmt(&[0x48, 0xF7, 0xF3], 0, Mode::X64), "div rbx");
    // imul rbx в†’ 48 F7 EB
    assert_eq!(fmt(&[0x48, 0xF7, 0xEB], 0, Mode::X64), "imul rbx");
}

#[test]
fn coverage_imul_with_immediate() {
    // imul ecx, dword ptr [rax], 5 в†’ 6B 08 05
    assert_eq!(
        fmt(&[0x6B, 0x08, 0x05], 0, Mode::X64),
        "imul ecx, dword ptr [rax], 0x5"
    );
    // imul r9d, r10d, -3 в†’ 45 6B CA FD
    assert_eq!(
        fmt(&[0x45, 0x6B, 0xCA, 0xFD], 0, Mode::X64),
        "imul r9d, r10d, -0x3"
    );
}

#[test]
fn coverage_leave_enter_push_imm() {
    assert_eq!(fmt(&[0xC9], 0, Mode::X64), "leave");
    assert_eq!(fmt(&[0x68, 0x0A, 0x00, 0x00, 0x00], 0, Mode::X64), "push 0xa");
    assert_eq!(fmt(&[0x6A, 0x02], 0, Mode::X64), "push 0x2");
}

#[test]
fn coverage_cmovcc_and_bt() {
    // cmovz eax, ebx в†’ 0F 44 C3
    assert_eq!(fmt(&[0x0F, 0x44, 0xC3], 0, Mode::X64), "cmove eax, ebx");
    // bt dword ptr [rax], ecx в†’ 0F A3 08
    assert_eq!(fmt(&[0x0F, 0xA3, 0x08], 0, Mode::X64), "bt dword ptr [rax], ecx");
    // bt eax, 5 в†’ 0F BA E0 05
    assert_eq!(fmt(&[0x0F, 0xBA, 0xE0, 0x05], 0, Mode::X64), "bt eax, 0x5");
}

#[test]
fn coverage_misc_system_ops() {
    assert_eq!(fmt(&[0x0F, 0x31], 0, Mode::X64), "rdtsc");
    assert_eq!(fmt(&[0x0F, 0xA2], 0, Mode::X64), "cpuid");
    assert_eq!(fmt(&[0xFC], 0, Mode::X64), "cld");
}

#[test]
fn sanity_known_good_decodes_still_work() {
    // call rel32 target arithmetic
    let insn = dec(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000, Mode::X64).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::Call);
    assert_eq!(insn.length, 5);
    if let Operand::Rel(t) = insn.operands[0] {
        assert_eq!(t, 0x1005);
    }
    // jne short backwards: 75 FE at 0x10 в†’ target = 0x10 + 2 - 2 = 0x10
    let insn = dec(&[0x75, 0xFE], 0x10, Mode::X64).unwrap();
    if let Operand::Rel(t) = insn.operands[0] {
        assert_eq!(t, 0x10);
    }
    // sub rsp, 0x28
    assert_eq!(
        fmt(&[0x48, 0x83, 0xEC, 0x28], 0, Mode::X64),
        "sub rsp, 0x28"
    );
}
