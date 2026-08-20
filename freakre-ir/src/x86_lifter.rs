//! x86/x86-64 lifter — translates x86 machine code into IR.
//!
//! This lifter handles the most common x86/x64 instructions and produces
//! IR suitable for analysis. It uses the built-in LDE for instruction
//! boundaries and lifts semantically.

use crate::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

/// x86/x86-64 lifter.
pub struct X86Lifter {
    is_64bit: bool,
    max_instructions: usize,
}

impl X86Lifter {
    /// Create a new x86 lifter.
    /// `is_64bit` — true for x86-64, false for 32-bit x86.
    pub fn new(is_64bit: bool) -> Self {
        X86Lifter {
            is_64bit,
            max_instructions: 100_000,
        }
    }

    /// Register type based on architecture.
    fn reg_ty(&self) -> Ty {
        if self.is_64bit { Ty::i64() } else { Ty::i32() }
    }

    /// Common register names for x86-64.
    fn reg64(&self, name: &str) -> Value {
        Value::Register {
            name: name.to_string(),
            ty: Ty::i64(),
        }
    }

    fn reg32(&self, name: &str) -> Value {
        Value::Register {
            name: name.to_string(),
            ty: Ty::i32(),
        }
    }

    fn reg8(&self, name: &str) -> Value {
        Value::Register {
            name: name.to_string(),
            ty: Ty::i8(),
        }
    }

    fn flag(&self, name: &str) -> Value {
        Value::Register {
            name: format!("flag_{}", name),
            ty: Ty::Bool,
        }
    }

    /// Lift a function prologue pattern (push rbp; mov rbp, rsp).
    fn try_lift_prologue(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
    ) -> usize {
        if code.len() < 4 {
            return 0;
        }

        // push rbp: 0x55
        // mov rbp, rsp: 0x48 0x89 0xE5 (64-bit) or 0x89 0xE5 (32-bit)
        if code[0] == 0x55 {
            let rsp = self.reg64("rsp");
            let eight = Value::int(8);
            let new_rsp = func.alloc_var(Ty::i64());

            func.push_inst(block, IrInst::Binary {
                dst: new_rsp.clone(),
                op: OpCode::Sub,
                lhs: rsp.clone(),
                rhs: eight,
            });
            func.push_inst(block, IrInst::Store {
                addr: new_rsp.clone(),
                value: self.reg64("rbp"),
                size: 8,
            });
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rsp"),
                op: OpCode::Copy,
                src: new_rsp,
            });

            // Check for mov rbp, rsp
            if code.len() >= 4 && code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5 {
                func.push_inst(block, IrInst::Unary {
                    dst: self.reg64("rbp"),
                    op: OpCode::Copy,
                    src: self.reg64("rsp"),
                });
                return 4; // push(1) + mov(3) = 4
            }

            return 1; // Just push rbp
        }

        0
    }

    /// Lift a function epilogue pattern (pop rbp; ret or leave; ret).
    fn try_lift_epilogue(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
    ) -> usize {
        if code.is_empty() {
            return 0;
        }

        // ret: 0xC3
        if code[0] == 0xC3 {
            let rsp = self.reg64("rsp");
            let eight = Value::int(8);
            let old_rbp = func.alloc_var(Ty::i64());
            let new_rsp = func.alloc_var(Ty::i64());

            func.push_inst(block, IrInst::Load {
                dst: old_rbp.clone(),
                addr: rsp.clone(),
                size: 8,
            });
            func.push_inst(block, IrInst::Binary {
                dst: new_rsp.clone(),
                op: OpCode::Add,
                lhs: rsp,
                rhs: eight,
            });
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rsp"),
                op: OpCode::Copy,
                src: new_rsp,
            });
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rbp"),
                op: OpCode::Copy,
                src: old_rbp,
            });
            func.push_inst(block, IrInst::Return {
                value: Some(self.reg64("rax")),
            });

            return 1;
        }

        // leave: 0xC9 (mov rsp, rbp; pop rbp)
        if code[0] == 0xC9 && code.len() >= 2 && code[1] == 0xC3 {
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rsp"),
                op: OpCode::Copy,
                src: self.reg64("rbp"),
            });
            let old_rbp = func.alloc_var(Ty::i64());
            func.push_inst(block, IrInst::Load {
                dst: old_rbp.clone(),
                addr: self.reg64("rsp"),
                size: 8,
            });
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rbp"),
                op: OpCode::Copy,
                src: old_rbp,
            });
            let eight = Value::int(8);
            let new_rsp = func.alloc_var(Ty::i64());
            func.push_inst(block, IrInst::Binary {
                dst: new_rsp.clone(),
                op: OpCode::Add,
                lhs: self.reg64("rsp"),
                rhs: eight,
            });
            func.push_inst(block, IrInst::Unary {
                dst: self.reg64("rsp"),
                op: OpCode::Copy,
                src: new_rsp,
            });
            func.push_inst(block, IrInst::Return {
                value: Some(self.reg64("rax")),
            });

            return 2;
        }

        0
    }

    /// Lift common x86 instructions. Returns (bytes_consumed, lifted_successfully).
    fn lift_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> (usize, bool) {
        if code.is_empty() {
            return (1, false);
        }

        let mut pos = 0;

        // Skip prefixes
        while pos < code.len() && pos < 4 {
            match code[pos] {
                0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 => {
                    pos += 1;
                }
                _ => break,
            }
        }

        // REX prefix
        let has_rex_w = self.is_64bit && pos < code.len() && (code[pos] & 0xF8) == 0x48;
        if self.is_64bit && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
            pos += 1;
        }

        if pos >= code.len() {
            return (1, false);
        }

        let opcode = code[pos];
        let reg_ty = if has_rex_w { Ty::i64() } else { self.reg_ty() };

        // ─── Common instructions ────────────────────────────────────

        match opcode {
            // PUSH reg (0x50-0x57)
            0x50..=0x57 => {
                let reg_idx = opcode - 0x50;
                let reg_name = x86_reg_name(reg_idx, self.is_64bit);
                let reg_val = Value::Register { name: reg_name.clone(), ty: reg_ty.clone() };

                let eight = Value::int(if self.is_64bit { 8 } else { 4 });
                let new_rsp = func.alloc_var(reg_ty.clone());

                func.push_inst(block, IrInst::Binary {
                    dst: new_rsp.clone(),
                    op: OpCode::Sub,
                    lhs: self.reg64("rsp"),
                    rhs: eight.clone(),
                });
                func.push_inst(block, IrInst::Store {
                    addr: new_rsp.clone(),
                    value: reg_val,
                    size: if self.is_64bit { 8 } else { 4 },
                });
                func.push_inst(block, IrInst::Unary {
                    dst: self.reg64("rsp"),
                    op: OpCode::Copy,
                    src: new_rsp,
                });

                (pos + 1, true)
            }

            // POP reg (0x58-0x5F)
            0x58..=0x5F => {
                let reg_idx = opcode - 0x58;
                let reg_name = x86_reg_name(reg_idx, self.is_64bit);
                let reg_val = Value::Register { name: reg_name.clone(), ty: reg_ty.clone() };
                let size = if self.is_64bit { 8u32 } else { 4 };
                let size_val = Value::int(size as i64);

                let loaded = func.alloc_var(reg_ty.clone());
                let new_rsp = func.alloc_var(reg_ty.clone());

                func.push_inst(block, IrInst::Load {
                    dst: loaded.clone(),
                    addr: self.reg64("rsp"),
                    size,
                });
                func.push_inst(block, IrInst::Binary {
                    dst: new_rsp.clone(),
                    op: OpCode::Add,
                    lhs: self.reg64("rsp"),
                    rhs: size_val,
                });
                func.push_inst(block, IrInst::Unary {
                    dst: reg_val,
                    op: OpCode::Copy,
                    src: loaded,
                });
                func.push_inst(block, IrInst::Unary {
                    dst: self.reg64("rsp"),
                    op: OpCode::Copy,
                    src: new_rsp,
                });

                (pos + 1, true)
            }

            // RET (0xC3)
            0xC3 => {
                func.push_inst(block, IrInst::Return {
                    value: Some(self.reg64("rax")),
                });
                (1, true)
            }

            // NOP (0x90)
            0x90 => {
                func.push_inst(block, IrInst::Nop);
                (pos + 1, true)
            }

            // INT3 (0xCC)
            0xCC => {
                func.push_inst(block, IrInst::Nop);
                (pos + 1, true)
            }

            // MOV r/m, reg or reg, r/m (0x88-0x8B)
            0x88 | 0x89 | 0x8A | 0x8B => {
                // Simplified: treat as COPY
                let dst_reg = func.alloc_var(reg_ty.clone());
                let src_reg = func.alloc_var(reg_ty.clone());
                func.push_inst(block, IrInst::Unary {
                    dst: dst_reg,
                    op: OpCode::Copy,
                    src: src_reg,
                });
                let len = pos + 1 + modrm_length(code.get(pos + 1).copied().unwrap_or(0));
                (len, true)
            }

            // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (0x80-0x83)
            0x80 | 0x81 | 0x83 => {
                let modrm = code.get(pos + 1).copied().unwrap_or(0);
                let reg_field = (modrm >> 3) & 0x07;
                let op = match reg_field {
                    0 => OpCode::Add,
                    1 => OpCode::Or,
                    4 => OpCode::And,
                    5 => OpCode::Sub,
                    6 => OpCode::Xor,
                    7 => OpCode::Sub, // CMP = SUB (flags only)
                    _ => OpCode::Add,
                };

                let dst = func.alloc_var(reg_ty.clone());
                let lhs = func.alloc_var(reg_ty.clone());
                let rhs = func.alloc_var(reg_ty.clone());

                func.push_inst(block, IrInst::Binary {
                    dst: dst.clone(),
                    op,
                    lhs,
                    rhs,
                });

                let imm_size = if opcode == 0x81 { 4 } else { 1 };
                let len = pos + 1 + modrm_length(modrm) + imm_size;
                (len, true)
            }

            // TEST r/m, reg (0x84-0x85)
            0x84 | 0x85 => {
                let lhs = func.alloc_var(reg_ty.clone());
                let rhs = func.alloc_var(reg_ty.clone());
                let result = func.alloc_var(reg_ty.clone());
                func.push_inst(block, IrInst::Binary {
                    dst: result.clone(),
                    op: OpCode::And,
                    lhs,
                    rhs,
                });
                let len = pos + 1 + modrm_length(code.get(pos + 1).copied().unwrap_or(0));
                (len, true)
            }

            // LEA reg, mem (0x8D)
            0x8D => {
                let dst = func.alloc_var(reg_ty.clone());
                let addr = func.alloc_var(reg_ty.clone());
                func.push_inst(block, IrInst::Unary {
                    dst,
                    op: OpCode::Copy,
                    src: addr,
                });
                let len = pos + 1 + modrm_length(code.get(pos + 1).copied().unwrap_or(0));
                (len, true)
            }

            // CALL rel32 (0xE8)
            0xE8 if code.len() >= pos + 5 => {
                let rel = i32::from_le_bytes([
                    code[pos + 1], code[pos + 2], code[pos + 3], code[pos + 4],
                ]) as i64;
                let target_addr = (address as i64 + 5 + rel) as u64;
                let target = Value::Symbol(format!("sub_{:X}", target_addr));

                func.push_inst(block, IrInst::Call {
                    dst: Some(self.reg64("rax")),
                    target,
                    args: Vec::new(),
                });

                (5, true)
            }

            // JMP rel32 (0xE9)
            0xE9 if code.len() >= pos + 5 => {
                let rel = i32::from_le_bytes([
                    code[pos + 1], code[pos + 2], code[pos + 3], code[pos + 4],
                ]) as i64;
                let target_addr = (address as i64 + 5 + rel) as u64;
                let target_block = func.add_block(&format!("loc_{:X}", target_addr));

                func.push_inst(block, IrInst::Branch { target: target_block });

                (5, true)
            }

            // JMP rel8 (0xEB)
            0xEB if code.len() >= pos + 2 => {
                let rel = code[pos + 1] as i8 as i64;
                let target_addr = (address as i64 + 2 + rel) as u64;
                let target_block = func.add_block(&format!("loc_{:X}", target_addr));

                func.push_inst(block, IrInst::Branch { target: target_block });

                (2, true)
            }

            // Jcc rel8 (0x70-0x7F)
            0x70..=0x7F if code.len() >= pos + 2 => {
                let rel = code[pos + 1] as i8 as i64;
                let target_addr = (address as i64 + 2 + rel) as u64;

                let target_true = func.add_block(&format!("loc_{:X}", target_addr));
                let target_false = func.add_block(&format!("fall_{:X}", address + 2));

                let cond = func.alloc_var(Ty::Bool);
                func.push_inst(block, IrInst::CBranch {
                    cond,
                    target_true,
                    target_false,
                });

                (2, true)
            }

            // MOV reg, imm32 (0xB8-0xBF)
            0xB8..=0xBF => {
                let reg_idx = opcode - 0xB8;
                let reg_name = x86_reg_name(reg_idx, self.is_64bit);
                let reg_val = Value::Register { name: reg_name, ty: reg_ty.clone() };

                if code.len() >= pos + 5 {
                    let imm = i32::from_le_bytes([
                        code[pos + 1], code[pos + 2], code[pos + 3], code[pos + 4],
                    ]) as i64;
                    func.push_inst(block, IrInst::Unary {
                        dst: reg_val,
                        op: OpCode::Copy,
                        src: Value::Const(imm),
                    });
                    (5, true)
                } else {
                    (1, false)
                }
            }

            // Default: skip instruction
            _ => {
                // Use LDE to determine length
                let (len, _) = lde_length(code, self.is_64bit);
                (len.max(1), false)
            }
        }
    }
}

impl Lifter for X86Lifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit { "x86_64" } else { "x86" }
    }

    fn max_instructions(&self) -> usize {
        self.max_instructions
    }

    fn lift_function(
        &self,
        code: &[u8],
        base_address: u64,
        function_name: &str,
    ) -> Result<IrFunction, LifterError> {
        let mut func = IrFunction::new(function_name, base_address);
        let mut current_block = func.entry_block;
        let mut offset = 0usize;
        let mut instruction_count = 0usize;

        // Try to detect and lift prologue
        let prologue_size = self.try_lift_prologue(&mut func, current_block, code);
        offset += prologue_size;

        while offset < code.len() && instruction_count < self.max_instructions {
            let remaining = &code[offset..];
            let address = base_address + offset as u64;

            // Try epilogue detection
            let epilogue_size = self.try_lift_epilogue(&mut func, current_block, remaining);
            if epilogue_size > 0 {
                offset += epilogue_size;
                instruction_count += 1;
                break; // Epilogue ends the function
            }

            let (consumed, lifted) = self.lift_instruction(
                &mut func,
                current_block,
                remaining,
                address,
            );

            if consumed == 0 {
                break; // Can't decode further
            }

            offset += consumed;
            instruction_count += 1;

            // If we lifted a terminator, create a new block
            if lifted {
                let block = func.block(current_block);
                if let Some(b) = block {
                    if b.terminator().is_some() {
                        current_block = func.add_block(&format!("bb_{}", offset));
                    }
                }
            }
        }

        func.build_cfg();

        Ok(func)
    }
}

// ─── Helper functions ────────────────────────────────────────────────

fn x86_reg_name(idx: u8, is_64bit: bool) -> String {
    if is_64bit {
        match idx {
            0 => "rax", 1 => "rcx", 2 => "rdx", 3 => "rbx",
            4 => "rsp", 5 => "rbp", 6 => "rsi", 7 => "rdi",
            _ => "r?",
        }
    } else {
        match idx {
            0 => "eax", 1 => "ecx", 2 => "edx", 3 => "ebx",
            4 => "esp", 5 => "ebp", 6 => "esi", 7 => "edi",
            _ => "e?",
        }
    }.to_string()
}

fn modrm_length(modrm: u8) -> usize {
    let mod_bits = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let mut len = 1;

    if mod_bits != 3 && rm == 4 {
        len += 1; // SIB
    }

    match mod_bits {
        0 if rm == 5 => len += 4,
        1 => len += 1,
        2 => len += 4,
        _ => {}
    }

    len
}

/// LDE: determine instruction length without full classification.
fn lde_length(code: &[u8], is_64bit: bool) -> (usize, bool) {
    if code.is_empty() {
        return (1, false);
    }

    let mut pos = 0;

    while pos < code.len() && pos < 4 {
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 => {
                pos += 1;
            }
            _ => break,
        }
    }

    if is_64bit && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
        pos += 1;
    }

    if pos >= code.len() {
        return (pos.max(1), false);
    }

    let opcode = code[pos];
    pos += 1;

    // Two-byte escape
    if opcode == 0x0F && pos < code.len() {
        let second = code[pos];
        pos += 1;

        if second >= 0x80 && second <= 0x8F {
            return (pos + 4, true);
        }

        // Most 0F instructions have ModR/M
        let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };

        // Some special cases
        if second == 0x31 || second == 0xA2 || second == 0x05 || second == 0x34 {
            return (pos, true);
        }

        return (pos + len, true);
    }

    match opcode {
        0xC3 | 0xCB | 0x90 | 0xCC | 0xF4 | 0xF5 => (pos, true),
        0xC2 | 0xCA => (pos + 2, true),
        0xE8 | 0xE9 => (pos + 4, true),
        0xEB => (pos + 1, true),
        0x70..=0x7F => (pos + 1, true),
        0xE0..=0xE3 => (pos + 1, true),
        0x50..=0x5F => (pos, true),
        0xB8..=0xBF => (pos + 4, true),
        0xB0..=0xB7 => (pos + 1, true),
        0x6A => (pos + 1, true),
        0x68 => (pos + 4, true),
        0xFF => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            (pos + len, true)
        }
        0x80 | 0x82 => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            (pos + len + 1, true)
        }
        0x81 => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            (pos + len + 4, true)
        }
        0x83 => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            (pos + len + 1, true)
        }
        0x88..=0x8B | 0x8D | 0x84 | 0x85 | 0x86 | 0x87 => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            (pos + len, true)
        }
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => (pos + 1, true),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (pos + 4, true),
        _ => {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 1 };
            (pos + len, false)
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lift_ret() {
        let lifter = X86Lifter::new(true);
        let code = [0xC3]; // ret
        let func = lifter.lift_function(&code, 0x1000, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_lift_prologue_epilogue() {
        let lifter = X86Lifter::new(true);
        // push rbp; mov rbp, rsp; ... ; leave; ret
        let code = [
            0x55,                   // push rbp
            0x48, 0x89, 0xE5,      // mov rbp, rsp
            0x90,                   // nop
            0xC9,                   // leave
            0xC3,                   // ret
        ];
        let func = lifter.lift_function(&code, 0x401000, "main").unwrap();
        assert!(func.total_instructions() > 3);
    }

    #[test]
    fn test_lift_nop_sequence() {
        let lifter = X86Lifter::new(true);
        let code = [0x90, 0x90, 0x90, 0xC3]; // nop; nop; nop; ret
        let func = lifter.lift_function(&code, 0x0, "nops").unwrap();
        assert!(func.total_instructions() >= 3);
    }

    #[test]
    fn test_lift_push_pop() {
        let lifter = X86Lifter::new(true);
        // push rax; pop rbx; ret
        let code = [0x50, 0x5B, 0xC3];
        let func = lifter.lift_function(&code, 0x0, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_registry() {
        use crate::lifter::LifterRegistry;
        let lifter = LifterRegistry::get("x86_64").unwrap();
        assert_eq!(lifter.arch_name(), "x86_64");
    }

    #[test]
    fn test_lde_length() {
        assert_eq!(lde_length(&[0xC3], true), (1, true));
        assert_eq!(lde_length(&[0x90], true), (1, true));
        assert_eq!(lde_length(&[0xE8, 0x00, 0x01, 0x00, 0x00], true), (5, true));
        assert_eq!(lde_length(&[0xEB, 0x10], true), (2, true));
    }
}
