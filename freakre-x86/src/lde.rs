//! Length Disassembler (LDE) for x86/x64.
//! Returns instruction length without full decode. Fast path for CFG building.

use crate::types::{Mode, DecodeError};

const MAX_INSN_LEN: usize = 15;

/// Decode instruction length only. Returns Err on malformed input.
pub fn decode_len(code: &[u8], mode: Mode) -> Result<usize, DecodeError> {
    if code.is_empty() {
        return Err(DecodeError::TooShort);
    }

    let mut pos = 0usize;
    let mut has_66 = false;
    let is_64 = mode == Mode::X64;

    // Skip legacy prefixes
    loop {
        if pos >= code.len() || pos >= MAX_INSN_LEN {
            return Err(if pos >= MAX_INSN_LEN { DecodeError::MaxLengthExceeded } else { DecodeError::TooShort });
        }
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 => { pos += 1; } // LOCK, REPNE, REP
            0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => { pos += 1; } // CS, SS, DS, ES, FS, GS
            0x66 => { has_66 = true; pos += 1; } // Operand size override
            0x67 => { pos += 1; } // Address size override
            _ => break,
        }
    }

    // REX prefix (64-bit only)
    let has_rex_w = if is_64 && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
        let rex_w = (code[pos] & 0x08) != 0;
        pos += 1;
        rex_w
    } else {
        false
    };

    if pos >= code.len() {
        return Err(DecodeError::TooShort);
    }

    let opcode = code[pos];
    pos += 1;

    // Two-byte opcode escape
    let (opcode, _two_byte) = if opcode == 0x0F {
        if pos >= code.len() { return Err(DecodeError::TooShort); }
        let op2 = code[pos];
        pos += 1;

        // Three-byte opcode
        if op2 == 0x38 || op2 == 0x3A {
            if pos >= code.len() { return Err(DecodeError::TooShort); }
            pos += 1; // skip third opcode byte
            if op2 == 0x3A {
                // 3-byte + imm8
                return read_modrm_and_disp(code, pos, is_64, has_rex_w)
                    .map(|mr| pos + mr + 1);
            }
            return read_modrm_and_disp(code, pos, is_64, has_rex_w)
                .map(|mr| pos + mr);
        }

        let len = two_byte_tail_len(code, pos, op2)?;
        if len > code.len() { return Err(DecodeError::TooShort); }
        return Ok(len);
    } else {
        (opcode, false)
    };

    // VEX prefix in 64-bit mode (C4/C5 are not LES/LDS there)
    if is_64 && (opcode == 0xC4 || opcode == 0xC5) {
        let len = vex_len(code, pos - 1, opcode)?;
        if len > code.len() { return Err(DecodeError::TooShort); }
        return Ok(len);
    }

    // One-byte opcodes
    let has_modrm = matches!(opcode,
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B |
        0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B |
        0x62 | 0x63 | 0x69 | 0x6B |
        0x80..=0x8F | 0xC0..=0xC1 | 0xC4..=0xC7 |
        0xD0..=0xD3 | 0xD8..=0xDF |
        0xF6..=0xF7 | 0xFE..=0xFF
    );

    let imm_size: usize = match opcode {
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | // AL, imm8
        0x80 | 0x82 | 0x83 | 0xC0 | 0xC1 | 0xC6 | 0xCD | 0xD4 | 0xD5 |
        0x6B | 0xA8 | // imul r,rm,imm8; test al,imm8
        0xEB |
        0x70..=0x7F | // short jumps
        0xB0..=0xB7 => 1, // mov reg8, imm8

        // mov al/ax/eax/rax, moffs — operand size, not address size:
        // REX.W → 8, 66 → 2, otherwise 4 (in both modes)
        0xA0..=0xA3 => if has_rex_w && is_64 { 8 } else if has_66 { 2 } else { 4 },

        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D |
        0x68 | 0x69 | 0x81 | 0xC7 |
        0xA9 | 0xE8 | 0xE9 => 4, // imm32

        0xB8..=0xBF => if has_rex_w && is_64 { 8 } else { 4 }, // mov reg, imm32/64

        0xEA | 0x9A => return Err(DecodeError::InvalidOpcode), // far jmp/call not in 64-bit

        _ => 0,
    };

    // Fix: some opcodes above overlap, handle special cases
    let imm_size = match opcode {
        0xC2 | 0xCA => 2,
        0xC8 => 3,
        0x6A => 1,
        0x68 => 4,
        0xA0..=0xA3 => if has_rex_w && is_64 { 8 } else if has_66 { 2 } else { 4 },
        0xB8..=0xBF => if has_rex_w && is_64 { 8 } else { 4 },
        _ => imm_size,
    };

    let len = if has_modrm {
        // F6/F7 /0 and /1 are TEST r/m, imm forms with a trailing immediate
        let extra_imm = if opcode == 0xF6 || opcode == 0xF7 {
            if pos < code.len() && (code[pos] >> 3) & 7 <= 1 {
                if opcode == 0xF6 { 1 } else { 4 }
            } else {
                0
            }
        } else {
            0
        };
        pos + read_modrm_and_disp(code, pos, is_64, has_rex_w)? + imm_size + extra_imm
    } else {
        pos + imm_size
    };
    if len > code.len() { return Err(DecodeError::TooShort); }
    Ok(len)
}

/// Two-byte (0F xx / VEX.map1) tail: ModR/M presence + immediate.
/// Returns total bytes consumed from `pos` (which points past the op2 byte).
fn two_byte_tail_len(code: &[u8], pos: usize, op2: u8) -> Result<usize, DecodeError> {
    let has_modrm = matches!(op2,
        0x00..=0x01 | 0x0D | 0x10..=0x19 | 0x1F |
        0x20..=0x23 | 0x28..=0x2F | 0x36..=0x37 | 0x3F |
        0x40..=0x4F | 0x50..=0x7F | 0x90..=0x9F | 0xA3..=0xA7 |
        0xAB..=0xB7 | 0xBA..=0xBF |
        0xC0..=0xC7 | 0xD0..=0xFF
    );

    let imm_size = match op2 {
        0x70..=0x73 => 1, // pshuf* etc
        0x80..=0x8F => 4, // jcc rel32
        0xA4 | 0xAC => 1, // shld/shrd imm8
        0xBA => 1,        // bt/bts/btr/btc imm8
        0xC2 => 1,        // cmpps imm8
        0xC4..=0xC6 => 1, // pinsrw/pextrw/shufps imm8
        _ => 0,
    };

    if has_modrm {
        Ok(pos + read_modrm_and_disp(code, pos, true, false)? + imm_size)
    } else {
        Ok(pos + imm_size)
    }
}

/// VEX-encoded instruction length. `vex_pos` points at the C4/C5 byte.
///
/// Layouts:
///   C5 vb1 opcode      [modrm][sib][disp][imm]   — implied map 1 (0F)
///   C4 b1 b2 opcode    [modrm][sib][disp][imm]
///     b1[1:0]: map select — 0: invalid, 1: 0F, 2: 0F38, 3: 0F3A (+imm8)
fn vex_len(code: &[u8], vex_pos: usize, vex_byte: u8) -> Result<usize, DecodeError> {
    const TOO_SHORT: DecodeError = DecodeError::TooShort;
    if vex_byte == 0xC5 {
        let _vb1 = *code.get(vex_pos + 1).ok_or(TOO_SHORT)?;
        let op2 = *code.get(vex_pos + 2).ok_or(TOO_SHORT)?;
        two_byte_tail_len(code, vex_pos + 3, op2)
    } else {
        let b1 = *code.get(vex_pos + 1).ok_or(TOO_SHORT)?;
        let _b2 = *code.get(vex_pos + 2).ok_or(TOO_SHORT)?;
        let op3 = *code.get(vex_pos + 3).ok_or(TOO_SHORT)?;
        match b1 & 0x03 {
            0 => Err(DecodeError::InvalidOpcode),
            1 => two_byte_tail_len(code, vex_pos + 4, op3),
            2 => {
                // 0F38: all have ModR/M, no immediates in practice
                read_modrm_and_disp(code, vex_pos + 4, true, false)
                    .map(|mr| vex_pos + 4 + mr)
            }
            _ => {
                // 0F3A: all have ModR/M + imm8
                read_modrm_and_disp(code, vex_pos + 4, true, false)
                    .map(|mr| vex_pos + 5 + mr)
            }
        }
    }
}

/// Read ModR/M + optional SIB + displacement. Returns total bytes consumed.
fn read_modrm_and_disp(code: &[u8], pos: usize, _is_64: bool, _rex_w: bool) -> Result<usize, DecodeError> {
    if pos >= code.len() {
        return Err(DecodeError::TooShort);
    }

    let modrm = code[pos];
    let r#mod = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let mut consumed = 1usize;

    // SIB byte needed when mod != 3 and rm == 4
    if r#mod != 3 && rm == 4 {
        if pos + consumed >= code.len() {
            return Err(DecodeError::TooShort);
        }
        let sib = code[pos + consumed];
        consumed += 1;
        let base = sib & 0x07;
        // If base == 5 and mod == 0, there's a disp32
        if base == 5 && r#mod == 0 {
            consumed += 4;
        }
    }

    // Displacement
    let disp_size = match r#mod {
        0 => {
            if rm == 5 {
                4 // RIP-relative or disp32
            } else {
                0
            }
        }
        1 => 1,
        2 => 4,
        _ => 0, // mod == 3: register direct, no displacement
    };

    consumed += disp_size;

    if pos + consumed > code.len() {
        return Err(DecodeError::TooShort);
    }
    if pos + consumed > MAX_INSN_LEN {
        return Err(DecodeError::MaxLengthExceeded);
    }

    Ok(consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        assert_eq!(decode_len(&[0x90], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_ret() {
        assert_eq!(decode_len(&[0xC3], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_mov_reg_imm32() {
        // mov eax, 0x12345678
        assert_eq!(decode_len(&[0xB8, 0x78, 0x56, 0x34, 0x12], Mode::X64).unwrap(), 5);
    }

    #[test]
    fn test_rex_mov_r64_imm64() {
        // REX.W mov rax, imm64
        assert_eq!(decode_len(&[0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0], Mode::X64).unwrap(), 10);
    }

    #[test]
    fn test_push_rbp() {
        assert_eq!(decode_len(&[0x55], Mode::X64).unwrap(), 1);
    }

    #[test]
    fn test_sub_rsp_imm8() {
        // sub rsp, 0x28 → REX.W 0x83 0xEC 0x28
        assert_eq!(decode_len(&[0x48, 0x83, 0xEC, 0x28], Mode::X64).unwrap(), 4);
    }

    #[test]
    fn test_too_short() {
        assert!(decode_len(&[], Mode::X64).is_err());
        assert!(decode_len(&[0x0F], Mode::X64).is_err());
    }
}
