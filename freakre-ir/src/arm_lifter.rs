//! ARM/AArch64 lifter — translates ARM machine code into IR.
//!
//! This lifter handles the most common ARM (32-bit) and AArch64 (64-bit)
//! instructions and produces IR suitable for analysis.

use crate::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

/// ARM/AArch64 lifter.
pub struct ArmLifter {
    is_64bit: bool,
    is_thumb: bool,
    max_instructions: usize,
}

impl ArmLifter {
    /// Create a new ARM lifter.
    /// `is_64bit` — true for AArch64, false for ARM32.
    /// `is_thumb` — true for Thumb mode (ARM32 only).
    pub fn new(is_64bit: bool, is_thumb: bool) -> Self {
        ArmLifter {
            is_64bit,
            is_thumb: is_thumb && !is_64bit,
            max_instructions: 100_000,
        }
    }

    /// Register type based on architecture.
    fn reg_ty(&self) -> Ty {
        if self.is_64bit { Ty::i64() } else { Ty::i32() }
    }

    /// Create a register value.
    fn reg(&self, name: &str) -> Value {
        Value::Register {
            name: name.to_string(),
            ty: self.reg_ty(),
        }
    }

    /// ARM32 register name from index (R0-R15).
    fn arm32_reg_name(idx: u8) -> &'static str {
        match idx {
            0 => "r0", 1 => "r1", 2 => "r2", 3 => "r3",
            4 => "r4", 5 => "r5", 6 => "r6", 7 => "r7",
            8 => "r8", 9 => "r9", 10 => "r10", 11 => "r11",
            12 => "r12", 13 => "sp", 14 => "lr", 15 => "pc",
            _ => "r?",
        }
    }

    /// AArch64 register name from index (X0-X30, SP, XZR).
    fn aarch64_reg_name(idx: u8) -> &'static str {
        match idx {
            0 => "x0", 1 => "x1", 2 => "x2", 3 => "x3",
            4 => "x4", 5 => "x5", 6 => "x6", 7 => "x7",
            8 => "x8", 9 => "x9", 10 => "x10", 11 => "x11",
            12 => "x12", 13 => "x13", 14 => "x14", 15 => "x15",
            16 => "x16", 17 => "x17", 18 => "x18", 19 => "x19",
            20 => "x20", 21 => "x21", 22 => "x22", 23 => "x23",
            24 => "x24", 25 => "x25", 26 => "x26", 27 => "x27",
            28 => "x28", 29 => "x29", 30 => "x30",
            31 => "sp", // or xzr depending on context
            _ => "x?",
        }
    }

    /// Lift ARM32 instruction. Returns (bytes_consumed, lifted_successfully).
    fn lift_arm32_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> (usize, bool) {
        if code.len() < 4 {
            return (4, false);
        }

        // ARM32 is little-endian, 4-byte instructions
        let instr = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let condition = (instr >> 28) & 0xF;

        // Condition codes (simplified — we treat all as unconditional for IR)
        let _ = condition;

        // Decode instruction class
        let class = (instr >> 25) & 0x7;

        match class {
            // Data processing (immediate or register)
            0 | 1 => {
                let opcode = (instr >> 21) & 0xF;
                let s = (instr >> 20) & 1;
                let rn = ((instr >> 16) & 0xF) as u8;
                let rd = ((instr >> 12) & 0xF) as u8;

                let rd_val = self.reg(Self::arm32_reg_name(rd));
                let rn_val = self.reg(Self::arm32_reg_name(rn));

                let rhs = if (instr >> 25) & 1 == 1 {
                    // Immediate operand
                    let imm = (instr & 0xFF) as i64;
                    let rotate = ((instr >> 8) & 0xF) * 2;
                    let rotated = ((imm as u32).rotate_right(rotate as u32)) as i64;
                    Value::Const(rotated)
                } else {
                    // Register operand
                    let rm = (instr & 0xF) as u8;
                    self.reg(Self::arm32_reg_name(rm))
                };

                let _ = s; // Set flags (ignored in IR for simplicity)

                let op = match opcode {
                    0 => OpCode::And,    // AND
                    1 => OpCode::Xor,    // EOR
                    2 => OpCode::Sub,    // SUB
                    3 => OpCode::Sub,    // RSB (reverse subtract)
                    4 => OpCode::Add,    // ADD
                    5 => OpCode::Add,    // ADC
                    6 => OpCode::Sub,    // SBC
                    7 => OpCode::Sub,    // RSC
                    8 => OpCode::And,    // TST (test)
                    9 => OpCode::And,    // TEQ (test equal)
                    10 => OpCode::Sub,   // CMP (compare)
                    11 => OpCode::Add,   // CMN (compare negative)
                    12 => OpCode::Or,    // ORR
                    13 => OpCode::Copy,  // MOV
                    14 => OpCode::And,   // BIC (bit clear)
                    15 => OpCode::Not,   // MVN (move not)
                    _ => OpCode::Copy,
                };

                if op.is_unary() {
                    func.push_inst(block, IrInst::Unary {
                        dst: rd_val,
                        op,
                        src: rhs,
                    });
                } else {
                    func.push_inst(block, IrInst::Binary {
                        dst: rd_val,
                        op,
                        lhs: rn_val,
                        rhs,
                    });
                }

                (4, true)
            }

            // Single data transfer (LDR/STR)
            2 | 3 => {
                let is_load = (instr >> 20) & 1 == 1;
                let byte_transfer = (instr >> 22) & 1 == 1;
                let rn = ((instr >> 16) & 0xF) as u8;
                let rd = ((instr >> 12) & 0xF) as u8;

                let rn_val = self.reg(Self::arm32_reg_name(rn));
                let rd_val = self.reg(Self::arm32_reg_name(rd));

                let offset = if (instr >> 25) & 1 == 1 {
                    // Register offset
                    let rm = (instr & 0xF) as u8;
                    self.reg(Self::arm32_reg_name(rm))
                } else {
                    // Immediate offset
                    let imm = (instr & 0xFFF) as i64;
                    let is_up = (instr >> 23) & 1 == 1;
                    Value::Const(if is_up { imm } else { -imm })
                };

                let addr = func.alloc_var(Ty::i32());
                func.push_inst(block, IrInst::Binary {
                    dst: addr.clone(),
                    op: OpCode::Add,
                    lhs: rn_val,
                    rhs: offset,
                });

                let size = if byte_transfer { 1 } else { 4 };

                if is_load {
                    func.push_inst(block, IrInst::Load {
                        dst: rd_val,
                        addr,
                        size,
                    });
                } else {
                    func.push_inst(block, IrInst::Store {
                        addr,
                        value: rd_val,
                        size,
                    });
                }

                (4, true)
            }

            // Block data transfer (LDM/STM, PUSH/POP)
            4 => {
                let is_load = (instr >> 20) & 1 == 1;
                let rn = ((instr >> 16) & 0xF) as u8;
                let register_list = instr & 0xFFFF;

                let rn_val = self.reg(Self::arm32_reg_name(rn));
                let sp = self.reg("sp");

                // PUSH = STMDB sp!, {...}
                // POP = LDMIA sp!, {...}
                let is_push = !is_load && rn == 13;
                let is_pop = is_load && rn == 13;

                if is_push {
                    // Decrement SP, store registers
                    let count = register_list.count_ones();
                    let decrement = Value::Const((count * 4) as i64);
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(block, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Sub,
                        lhs: sp.clone(),
                        rhs: decrement,
                    });
                    func.push_inst(block, IrInst::Unary {
                        dst: sp.clone(),
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                }

                // For simplicity, we don't lift individual register loads/stores
                // from block transfers — just update SP

                if is_pop {
                    let count = register_list.count_ones();
                    let increment = Value::Const((count * 4) as i64);
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(block, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Add,
                        lhs: sp.clone(),
                        rhs: increment,
                    });
                    func.push_inst(block, IrInst::Unary {
                        dst: sp,
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                }

                let _ = rn_val; // suppress unused warning

                (4, true)
            }

            // Branch (B, BL)
            5 => {
                let is_link = (instr >> 24) & 1 == 1;
                let offset = (instr & 0xFFFFFF) as i32;
                // Sign-extend 24-bit offset
                let offset = if offset & 0x800000 != 0 {
                    offset | 0xFF000000u32 as i32
                } else {
                    offset
                };
                let offset = (offset << 2) as i64; // ARM branches are shifted by 2

                let target_addr = (address as i64 + 8 + offset) as u64;

                if is_link {
                    // BL — branch with link (function call)
                    let lr = self.reg("lr");
                    func.push_inst(block, IrInst::Unary {
                        dst: lr,
                        op: OpCode::Copy,
                        src: Value::Const((address + 4) as i64),
                    });
                    func.push_inst(block, IrInst::Call {
                        dst: Some(self.reg("r0")),
                        target: Value::Symbol(format!("sub_{:X}", target_addr)),
                        args: Vec::new(),
                    });
                } else {
                    // B — unconditional branch
                    let target_block = func.add_block(&format!("loc_{:X}", target_addr));
                    func.push_inst(block, IrInst::Branch { target: target_block });
                }

                (4, true)
            }

            // Coprocessor / SVC (syscall)
            7 => {
                if (instr >> 24) & 0xF == 0xF {
                    // SVC (supervisor call)
                    let svc_number = instr & 0xFFFFFF;
                    func.push_inst(block, IrInst::Syscall {
                        number: Some(Value::Const(svc_number as i64)),
                        args: Vec::new(),
                    });
                    (4, true)
                } else {
                    (4, false)
                }
            }

            _ => (4, false),
        }
    }

    /// Lift AArch64 instruction. Returns (bytes_consumed, lifted_successfully).
    fn lift_aarch64_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> (usize, bool) {
        if code.len() < 4 {
            return (4, false);
        }

        let instr = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);

        // Decode instruction class (bits 25-28)
        let class = (instr >> 25) & 0xF;

        match class {
            // Data processing — immediate
            0x8 | 0x9 => {
                let sub_class = (instr >> 23) & 0x7;

                match sub_class {
                    // ADD/SUB immediate
                    0x0 | 0x1 | 0x2 | 0x3 => {
                        let is_sub = (instr >> 30) & 1 == 1;
                        let is_64bit = (instr >> 31) & 1 == 1;
                        let rd = (instr & 0x1F) as u8;
                        let rn = ((instr >> 5) & 0x1F) as u8;
                        let imm = ((instr >> 10) & 0xFFF) as i64;
                        let shift = ((instr >> 22) & 0x3) * 12;
                        let shifted_imm = imm << shift;

                        let ty = if is_64bit { Ty::i64() } else { Ty::i32() };
                        let rd_name = if is_64bit {
                            Self::aarch64_reg_name(rd)
                        } else {
                            // W registers
                            match rd {
                                0 => "w0", 1 => "w1", 2 => "w2", 3 => "w3",
                                4 => "w4", 5 => "w5", 6 => "w6", 7 => "w7",
                                8 => "w8", 9 => "w9", 10 => "w10", 11 => "w11",
                                12 => "w12", 13 => "w13", 14 => "w14", 15 => "w15",
                                16 => "w16", 17 => "w17", 18 => "w18", 19 => "w19",
                                20 => "w20", 21 => "w21", 22 => "w22", 23 => "w23",
                                24 => "w24", 25 => "w25", 26 => "w26", 27 => "w27",
                                28 => "w28", 29 => "w29", 30 => "w30",
                                31 => "wsp",
                                _ => "w?",
                            }
                        };
                        let rn_name = if is_64bit {
                            Self::aarch64_reg_name(rn)
                        } else {
                            // Use W register names directly instead of leaking strings
                            match rn {
                                0 => "w0", 1 => "w1", 2 => "w2", 3 => "w3",
                                4 => "w4", 5 => "w5", 6 => "w6", 7 => "w7",
                                8 => "w8", 9 => "w9", 10 => "w10", 11 => "w11",
                                12 => "w12", 13 => "w13", 14 => "w14", 15 => "w15",
                                16 => "w16", 17 => "w17", 18 => "w18", 19 => "w19",
                                20 => "w20", 21 => "w21", 22 => "w22", 23 => "w23",
                                24 => "w24", 25 => "w25", 26 => "w26", 27 => "w27",
                                28 => "w28", 29 => "w29", 30 => "w30",
                                31 => "wsp",
                                _ => "w?",
                            }
                        };

                        let rd_val = Value::Register { name: rd_name.to_string(), ty: ty.clone() };
                        let rn_val = Value::Register { name: rn_name.to_string(), ty: ty.clone() };

                        func.push_inst(block, IrInst::Binary {
                            dst: rd_val,
                            op: if is_sub { OpCode::Sub } else { OpCode::Add },
                            lhs: rn_val,
                            rhs: Value::Const(shifted_imm),
                        });

                        (4, true)
                    }
                    _ => (4, false),
                }
            }

            // Data processing — register
            0xA | 0xB => {
                let op0 = (instr >> 30) & 0x3;
                let rd = (instr & 0x1F) as u8;
                let rn = ((instr >> 5) & 0x1F) as u8;
                let rm = ((instr >> 16) & 0x1F) as u8;
                let is_64bit = (instr >> 31) & 1 == 1;

                let ty = if is_64bit { Ty::i64() } else { Ty::i32() };
                let rd_name = Self::aarch64_reg_name(rd);
                let rn_name = Self::aarch64_reg_name(rn);
                let rm_name = Self::aarch64_reg_name(rm);

                let rd_val = Value::Register { name: rd_name.to_string(), ty: ty.clone() };
                let rn_val = Value::Register { name: rn_name.to_string(), ty: ty.clone() };
                let rm_val = Value::Register { name: rm_name.to_string(), ty: ty.clone() };

                let op = match op0 {
                    0 => OpCode::Add,
                    1 => OpCode::Sub,
                    2 => OpCode::Add, // ADD with shift
                    3 => OpCode::Sub, // SUB with shift
                    _ => OpCode::Copy,
                };

                func.push_inst(block, IrInst::Binary {
                    dst: rd_val,
                    op,
                    lhs: rn_val,
                    rhs: rm_val,
                });

                (4, true)
            }

            // Branches
            0xC | 0xD => {
                let branch_type = (instr >> 26) & 0x7;

                match branch_type {
                    // B (unconditional)
                    0 | 2 => {
                        let offset = (instr & 0x3FFFFFF) as i32;
                        let offset = if offset & 0x2000000 != 0 {
                            offset | 0xFC000000u32 as i32
                        } else {
                            offset
                        };
                        let offset = (offset << 2) as i64;
                        let target_addr = (address as i64 + offset) as u64;

                        let target_block = func.add_block(&format!("loc_{:X}", target_addr));
                        func.push_inst(block, IrInst::Branch { target: target_block });

                        (4, true)
                    }
                    // BL (branch with link)
                    1 | 3 => {
                        let offset = (instr & 0x3FFFFFF) as i32;
                        let offset = if offset & 0x2000000 != 0 {
                            offset | 0xFC000000u32 as i32
                        } else {
                            offset
                        };
                        let offset = (offset << 2) as i64;
                        let target_addr = (address as i64 + offset) as u64;

                        let lr = self.reg("x30");
                        func.push_inst(block, IrInst::Unary {
                            dst: lr,
                            op: OpCode::Copy,
                            src: Value::Const((address + 4) as i64),
                        });
                        func.push_inst(block, IrInst::Call {
                            dst: Some(self.reg("x0")),
                            target: Value::Symbol(format!("sub_{:X}", target_addr)),
                            args: Vec::new(),
                        });

                        (4, true)
                    }
                    // RET
                    5 | 6 if (instr >> 21) & 0x3 == 2 => {
                        func.push_inst(block, IrInst::Return {
                            value: Some(self.reg("x0")),
                        });
                        (4, true)
                    }
                    _ => (4, false),
                }
            }

            // Loads and stores
            0x4 | 0x5 | 0x6 | 0x7 => {
                let size = (instr >> 30) & 0x3;
                let rd = (instr & 0x1F) as u8;
                let rn = ((instr >> 5) & 0x1F) as u8;

                let rd_name = Self::aarch64_reg_name(rd);
                let rn_name = Self::aarch64_reg_name(rn);
                let rd_val = self.reg(rd_name);
                let rn_val = self.reg(rn_name);

                let access_size = match size {
                    0 => 1, // byte
                    1 => 2, // halfword
                    2 => 4, // word
                    3 => 8, // doubleword
                    _ => 4,
                };

                // Simplified: assume immediate offset
                let offset = ((instr >> 10) & 0xFFF) as i64 * access_size as i64;
                let addr = func.alloc_var(Ty::i64());
                func.push_inst(block, IrInst::Binary {
                    dst: addr.clone(),
                    op: OpCode::Add,
                    lhs: rn_val,
                    rhs: Value::Const(offset),
                });

                let is_load = (instr >> 22) & 1 == 1;
                if is_load {
                    func.push_inst(block, IrInst::Load {
                        dst: rd_val,
                        addr,
                        size: access_size,
                    });
                } else {
                    func.push_inst(block, IrInst::Store {
                        addr,
                        value: rd_val,
                        size: access_size,
                    });
                }

                (4, true)
            }

            // SVC (syscall)
            _ if instr & 0xFFE0001F == 0xD4000001 => {
                let svc_number = (instr >> 5) & 0xFFFF;
                func.push_inst(block, IrInst::Syscall {
                    number: Some(Value::Const(svc_number as i64)),
                    args: Vec::new(),
                });
                (4, true)
            }

            _ => (4, false),
        }
    }
}

impl Lifter for ArmLifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit {
            "arm64"
        } else if self.is_thumb {
            "thumb"
        } else {
            "arm"
        }
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

        while offset < code.len() && instruction_count < self.max_instructions {
            let remaining = &code[offset..];
            let address = base_address + offset as u64;

            let (consumed, lifted) = if self.is_64bit {
                self.lift_aarch64_instruction(&mut func, current_block, remaining, address)
            } else {
                self.lift_arm32_instruction(&mut func, current_block, remaining, address)
            };

            if consumed == 0 {
                break;
            }

            offset += consumed;
            instruction_count += 1;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm32_mov() {
        let lifter = ArmLifter::new(false, false);
        // MOV R0, #42 (0xE3A0002A)
        let code = [0x2A, 0x00, 0xA0, 0xE3];
        let func = lifter.lift_function(&code, 0x1000, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_aarch64_add() {
        let lifter = ArmLifter::new(true, false);
        // ADD X0, X1, #10 (0x91002820)
        let code = [0x20, 0x28, 0x00, 0x91];
        let func = lifter.lift_function(&code, 0x400000, "test").unwrap();
        assert!(func.total_instructions() > 0);
    }

    #[test]
    fn test_arm32_branch() {
        let lifter = ArmLifter::new(false, false);
        // B +8 (0xEA000000)
        let code = [0x00, 0x00, 0x00, 0xEA];
        let func = lifter.lift_function(&code, 0x1000, "test").unwrap();
        assert!(func.blocks.len() > 1); // Should create a new block
    }

    #[test]
    fn test_aarch64_ret() {
        let lifter = ArmLifter::new(true, false);
        // RET (0xD65F03C0)
        let code = [0xC0, 0x03, 0x5F, 0xD6];
        let func = lifter.lift_function(&code, 0x400000, "test").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.is_return_block());
    }
}
