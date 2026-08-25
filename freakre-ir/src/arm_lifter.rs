//! ARM/AArch64/Thumb lifter — translates ARM machine code into IR.
//!
//! This lifter handles the most common ARM (32-bit), Thumb (16-bit) and
//! AArch64 (64-bit) instructions and produces IR suitable for analysis.

use crate::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;
use std::sync::Mutex;

fn sign_extend(value: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}

/// ARM/AArch64/Thumb lifter.
pub struct ArmLifter {
    is_64bit: bool,
    is_thumb: bool,
    max_instructions: usize,
    warnings: Mutex<Vec<String>>,
}

impl ArmLifter {
    /// Create a new ARM lifter.
    ///
    /// `is_64bit` — true for AArch64, false for ARM32.
    /// `is_thumb` — true for Thumb mode (ARM32 only).
    pub fn new(is_64bit: bool, is_thumb: bool) -> Self {
        ArmLifter {
            is_64bit,
            is_thumb: is_thumb && !is_64bit,
            max_instructions: 100_000,
            warnings: Mutex::new(Vec::new()),
        }
    }

    /// Drain collected diagnostics (unsupported encodings replaced by Nop).
    pub fn take_warnings(&self) -> Vec<String> {
        self.warnings
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default()
    }

    fn warn_unsupported(&self, address: u64, encoding: u32, what: &str) {
        if let Ok(mut w) = self.warnings.lock() {
            w.push(format!(
                "unsupported {} instruction 0x{:08X} at 0x{:X}",
                what, encoding, address
            ));
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
            31 => "sp",
            _ => "x?",
        }
    }

    /// AArch64 W-register name from index.
    fn aarch64_w_reg_name(idx: u8) -> &'static str {
        match idx {
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
    }

    /// Lift a single ARM32 (A32) instruction into `block`.
    ///
    /// Returns `(bytes_consumed, lifted_ok, continuation_block)`.
    ///
    /// Conditional execution (`condition != AL`) is modelled with guarded
    /// basic blocks: NZCV is not tracked, so the lifter allocates an opaque
    /// boolean SSA variable, emits `CBranch(flag, guarded, fallthrough)` in
    /// the current block, lifts the instruction's effects into `guarded`,
    /// and links `guarded` back to `fallthrough` with a `Branch`. This keeps
    /// the CFG faithful (the instruction may or may not execute) without
    /// inventing flag semantics; a conditional `B` becomes a `CBranch`
    /// between its target and the fallthrough block. ADC/SBC/RSC are
    /// approximated as ADD/SUB without carry-in.
    fn lift_arm32_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> (usize, bool, Option<BlockId>) {
        if code.len() < 4 {
            return (4, false, None);
        }

        let instr = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let condition = (instr >> 28) & 0xF;

        let (work, continuation) = if condition != 0xE {
            let cond_flag = func.alloc_var(Ty::Bool);
            let guarded = func.add_block(&format!("guarded_{:X}", address));
            let fallthrough = func.add_block(&format!("after_{:X}", address));
            func.push_inst(block, IrInst::CBranch {
                cond: cond_flag,
                target_true: guarded,
                target_false: fallthrough,
            });
            (guarded, Some(fallthrough))
        } else {
            (block, None)
        };

        let class = (instr >> 25) & 0x7;

        match class {
            0 | 1 => {
                let opcode = (instr >> 21) & 0xF;
                let rn = ((instr >> 16) & 0xF) as u8;
                let rd = ((instr >> 12) & 0xF) as u8;

                let rd_val = self.reg(Self::arm32_reg_name(rd));
                let rn_val = self.reg(Self::arm32_reg_name(rn));

                let rhs = if (instr >> 25) & 1 == 1 {
                    let imm = (instr & 0xFF) as i64;
                    let rotate = ((instr >> 8) & 0xF) * 2;
                    let rotated = ((imm as u32).rotate_right(rotate)) as i64;
                    Value::Const(rotated)
                } else {
                    let rm = (instr & 0xF) as u8;
                    self.reg(Self::arm32_reg_name(rm))
                };

                match opcode {
                    3 | 7 => {
                        func.push_inst(work, IrInst::Binary {
                            dst: rd_val,
                            op: OpCode::Sub,
                            lhs: rhs,
                            rhs: rn_val,
                        });
                    }
                    14 => {
                        let inverted = func.alloc_var(Ty::i32());
                        func.push_inst(work, IrInst::Unary {
                            dst: inverted.clone(),
                            op: OpCode::Not,
                            src: rhs,
                        });
                        func.push_inst(work, IrInst::Binary {
                            dst: rd_val,
                            op: OpCode::And,
                            lhs: rn_val,
                            rhs: inverted,
                        });
                    }
                    8..=11 => {
                        let flags_tmp = func.alloc_var(Ty::i32());
                        let op = match opcode {
                            8 => OpCode::And,
                            9 => OpCode::Xor,
                            10 => OpCode::Sub,
                            _ => OpCode::Add,
                        };
                        func.push_inst(work, IrInst::Binary {
                            dst: flags_tmp,
                            op,
                            lhs: rn_val,
                            rhs,
                        });
                    }
                    13 => {
                        func.push_inst(work, IrInst::Unary {
                            dst: rd_val,
                            op: OpCode::Copy,
                            src: rhs,
                        });
                    }
                    15 => {
                        func.push_inst(work, IrInst::Unary {
                            dst: rd_val,
                            op: OpCode::Not,
                            src: rhs,
                        });
                    }
                    _ => {
                        let op = match opcode {
                            0 => OpCode::And,
                            1 => OpCode::Xor,
                            2 | 6 => OpCode::Sub,
                            4 | 5 => OpCode::Add,
                            12 => OpCode::Or,
                            _ => OpCode::Copy,
                        };
                        func.push_inst(work, IrInst::Binary {
                            dst: rd_val,
                            op,
                            lhs: rn_val,
                            rhs,
                        });
                    }
                }
            }

            2 | 3 => {
                let is_load = (instr >> 20) & 1 == 1;
                let byte_transfer = (instr >> 22) & 1 == 1;
                let pre_index = (instr >> 24) & 1 == 1;
                let up = (instr >> 23) & 1 == 1;
                let writeback = (instr >> 21) & 1 == 1;
                let rn = ((instr >> 16) & 0xF) as u8;
                let rd = ((instr >> 12) & 0xF) as u8;

                let rn_val = self.reg(Self::arm32_reg_name(rn));
                let rd_val = self.reg(Self::arm32_reg_name(rd));

                let (offset, negate) = if (instr >> 25) & 1 == 1 {
                    let rm = (instr & 0xF) as u8;
                    (self.reg(Self::arm32_reg_name(rm)), !up)
                } else {
                    (Value::Const((instr & 0xFFF) as i64), !up)
                };

                let size = if byte_transfer { 1 } else { 4 };
                let ty = self.reg_ty();

                let addr = func.alloc_var(ty.clone());
                if pre_index {
                    let op = if negate { OpCode::Sub } else { OpCode::Add };
                    func.push_inst(work, IrInst::Binary {
                        dst: addr.clone(),
                        op,
                        lhs: rn_val.clone(),
                        rhs: offset.clone(),
                    });
                } else {
                    func.push_inst(work, IrInst::Unary {
                        dst: addr.clone(),
                        op: OpCode::Copy,
                        src: rn_val.clone(),
                    });
                }

                if is_load {
                    func.push_inst(work, IrInst::Load {
                        dst: rd_val,
                        addr: addr.clone(),
                        size,
                    });
                } else {
                    func.push_inst(work, IrInst::Store {
                        addr: addr.clone(),
                        value: rd_val,
                        size,
                    });
                }

                if rn != 15 && (!pre_index || writeback) {
                    if pre_index {
                        func.push_inst(work, IrInst::Unary {
                            dst: rn_val,
                            op: OpCode::Copy,
                            src: addr,
                        });
                    } else {
                        let new_base = func.alloc_var(ty);
                        let op = if negate { OpCode::Sub } else { OpCode::Add };
                        func.push_inst(work, IrInst::Binary {
                            dst: new_base.clone(),
                            op,
                            lhs: rn_val.clone(),
                            rhs: offset,
                        });
                        func.push_inst(work, IrInst::Unary {
                            dst: rn_val,
                            op: OpCode::Copy,
                            src: new_base,
                        });
                    }
                }
            }

            4 => {
                let is_load = (instr >> 20) & 1 == 1;
                let rn = ((instr >> 16) & 0xF) as u8;
                let register_list = instr & 0xFFFF;

                let sp = self.reg("sp");

                let is_push = !is_load && rn == 13;
                let is_pop = is_load && rn == 13;

                if is_push {
                    let count = register_list.count_ones();
                    let decrement = Value::Const((count * 4) as i64);
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(work, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Sub,
                        lhs: sp.clone(),
                        rhs: decrement,
                    });
                    func.push_inst(work, IrInst::Unary {
                        dst: sp.clone(),
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                }

                if is_pop {
                    let count = register_list.count_ones();
                    let increment = Value::Const((count * 4) as i64);
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(work, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Add,
                        lhs: sp.clone(),
                        rhs: increment,
                    });
                    func.push_inst(work, IrInst::Unary {
                        dst: sp,
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                }
            }

            5 => {
                let is_link = (instr >> 24) & 1 == 1;
                let raw = (instr & 0xFFFFFF) as i64;
                let signed = if raw & 0x800000 != 0 {
                    raw - 0x1000000
                } else {
                    raw
                };
                let target_addr = (address as i64 + 8 + (signed << 2)) as u64;

                if is_link {
                    let lr = self.reg("lr");
                    func.push_inst(work, IrInst::Unary {
                        dst: lr,
                        op: OpCode::Copy,
                        src: Value::Const((address + 4) as i64),
                    });
                    func.push_inst(work, IrInst::Call {
                        dst: Some(self.reg("r0")),
                        target: Value::Symbol(format!("sub_{:X}", target_addr)),
                        args: Vec::new(),
                    });
                } else {
                    let target_block = func.add_block(&format!("loc_{:X}", target_addr));
                    func.push_inst(work, IrInst::Branch { target: target_block });
                }
            }

            7
                if (instr >> 24) & 0xF == 0xF => {
                    let svc_number = instr & 0xFFFFFF;
                    func.push_inst(work, IrInst::Syscall {
                        number: Some(Value::Const(svc_number as i64)),
                        args: Vec::new(),
                    });
                }

            _ => {
                self.warn_unsupported(address, instr, "arm32");
                func.push_inst(work, IrInst::Nop);
            }
        }

        if let Some(cont) = continuation {
            let ends_with_terminator = func.block(work).and_then(|b| b.terminator()).is_some();
            if !ends_with_terminator {
                func.push_inst(work, IrInst::Branch { target: cont });
            }
        }

        (4, true, continuation)
    }

    /// Lift a single AArch64 instruction into `block`.
    ///
    /// Returns `(bytes_consumed, lifted_ok, continuation_block)`.
    ///
    /// Dispatches on the top byte / fixed bit patterns: branches
    /// (B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, RET, BR/BLR), loads and stores
    /// (unsigned-offset forms), and the main data-processing groups
    /// (register and immediate). Unrecognised encodings become `Nop` plus a
    /// recorded warning instead of fabricated operations.
    fn lift_aarch64_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> (usize, bool, Option<BlockId>) {
        if code.len() < 4 {
            return (4, false, None);
        }

        let instr = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let top = ((instr >> 24) & 0xFF) as u8;

        if instr & 0xFFFFFC1F == 0xD65F0000 {
            func.push_inst(block, IrInst::Return {
                value: Some(self.reg("x0")),
            });
            return (4, true, None);
        }

        if instr & 0xFFFFFC1F == 0xD61F0000 {
            let rn = ((instr >> 5) & 0x1F) as u8;
            func.push_inst(block, IrInst::IndirectBranch {
                target: self.reg(Self::aarch64_reg_name(rn)),
            });
            return (4, true, None);
        }

        if instr & 0xFFFFFC1F == 0xD63F0000 {
            let rn = ((instr >> 5) & 0x1F) as u8;
            func.push_inst(block, IrInst::Unary {
                dst: self.reg("x30"),
                op: OpCode::Copy,
                src: Value::Const((address + 4) as i64),
            });
            func.push_inst(block, IrInst::Call {
                dst: Some(self.reg("x0")),
                target: self.reg(Self::aarch64_reg_name(rn)),
                args: Vec::new(),
            });
            return (4, true, None);
        }

        if instr & 0xFFE0001F == 0xD4000001 {
            let svc_number = (instr >> 5) & 0xFFFF;
            func.push_inst(block, IrInst::Syscall {
                number: Some(Value::Const(svc_number as i64)),
                args: Vec::new(),
            });
            return (4, true, None);
        }

        if (0x14..=0x17).contains(&top) {
            let off = sign_extend((instr & 0x03FFFFFF) as i64, 26) << 2;
            let target_addr = (address as i64 + off) as u64;
            let target_block = func.add_block(&format!("loc_{:X}", target_addr));
            func.push_inst(block, IrInst::Branch { target: target_block });
            return (4, true, None);
        }

        if (0x94..=0x97).contains(&top) {
            let off = sign_extend((instr & 0x03FFFFFF) as i64, 26) << 2;
            let target_addr = (address as i64 + off) as u64;
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
            return (4, true, None);
        }

        if (0x54..=0x57).contains(&top) {
            let off = sign_extend(((instr >> 5) & 0x7FFFF) as i64, 19) << 2;
            let target_addr = (address as i64 + off) as u64;
            let cond_flag = func.alloc_var(Ty::Bool);
            let taken = func.add_block(&format!("taken_{:X}", address));
            let after = func.add_block(&format!("after_{:X}", address));
            func.push_inst(block, IrInst::CBranch {
                cond: cond_flag,
                target_true: taken,
                target_false: after,
            });
            let loc = func.add_block(&format!("loc_{:X}", target_addr));
            func.push_inst(taken, IrInst::Branch { target: loc });
            return (4, true, Some(after));
        }

        if (0x34..=0x37).contains(&top) || (0xB4..=0xB7).contains(&top) {
            let is_64bit = top >= 0xB4;
            let ty = if is_64bit { Ty::i64() } else { Ty::i32() };
            let rt = (instr & 0x1F) as u8;
            let rt_name = if is_64bit {
                Self::aarch64_reg_name(rt)
            } else {
                Self::aarch64_w_reg_name(rt)
            };
            let rt_val = Value::Register {
                name: rt_name.to_string(),
                ty: ty.clone(),
            };
            let cmp_op = if top & 0x01 == 1 { OpCode::Ne } else { OpCode::Eq };

            let (cond_val, target_addr) = if top & 0x02 == 0 {
                let off = sign_extend(((instr >> 5) & 0x7FFFF) as i64, 19) << 2;
                let zero = func.alloc_var(Ty::Bool);
                func.push_inst(block, IrInst::Binary {
                    dst: zero.clone(),
                    op: cmp_op,
                    lhs: rt_val,
                    rhs: Value::Const(0),
                });
                (zero, (address as i64 + off) as u64)
            } else {
                let bit = ((instr >> 19) & 0x1F) + if is_64bit { 32 } else { 0 };
                let off = sign_extend(((instr >> 5) & 0x3FFF) as i64, 14) << 2;
                let masked = func.alloc_var(ty);
                func.push_inst(block, IrInst::Binary {
                    dst: masked.clone(),
                    op: OpCode::And,
                    lhs: rt_val,
                    rhs: Value::Const(1i64 << bit),
                });
                let zero = func.alloc_var(Ty::Bool);
                func.push_inst(block, IrInst::Binary {
                    dst: zero.clone(),
                    op: cmp_op,
                    lhs: masked,
                    rhs: Value::Const(0),
                });
                (zero, (address as i64 + off) as u64)
            };

            let loc = func.add_block(&format!("loc_{:X}", target_addr));
            let after = func.add_block(&format!("after_{:X}", address));
            func.push_inst(block, IrInst::CBranch {
                cond: cond_val,
                target_true: loc,
                target_false: after,
            });
            return (4, true, Some(after));
        }

        if top == 0x39 || top == 0x79 || top == 0xB9 || top == 0xF9 {
            let access_size = 1u32 << ((instr >> 30) & 0x3);
            let opc = (instr >> 22) & 0x3;
            if opc > 1 {
                self.warn_unsupported(address, instr, "arm64");
                func.push_inst(block, IrInst::Nop);
                return (4, true, None);
            }
            let rd = (instr & 0x1F) as u8;
            let rn = ((instr >> 5) & 0x1F) as u8;
            let rd_val = self.reg(Self::aarch64_reg_name(rd));
            let rn_val = self.reg(Self::aarch64_reg_name(rn));
            let offset = ((instr >> 10) & 0xFFF) as i64 * access_size as i64;
            let addr = func.alloc_var(Ty::i64());
            func.push_inst(block, IrInst::Binary {
                dst: addr.clone(),
                op: OpCode::Add,
                lhs: rn_val,
                rhs: Value::Const(offset),
            });
            if opc == 1 {
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
            return (4, true, None);
        }

        let a64_name = |idx: u8, w: bool| if w {
            Self::aarch64_w_reg_name(idx)
        } else {
            Self::aarch64_reg_name(idx)
        };

        if (instr & 0x1F000000) == 0x0B000000 {
            let is_sub = (instr >> 30) & 1 == 1;
            let is_wide = (instr >> 31) & 1 == 0;
            let ty = if is_wide { Ty::i32() } else { Ty::i64() };
            let rd = (instr & 0x1F) as u8;
            let rn = ((instr >> 5) & 0x1F) as u8;
            let rm = ((instr >> 16) & 0x1F) as u8;
            func.push_inst(block, IrInst::Binary {
                dst: Value::Register { name: a64_name(rd, is_wide).to_string(), ty: ty.clone() },
                op: if is_sub { OpCode::Sub } else { OpCode::Add },
                lhs: Value::Register { name: a64_name(rn, is_wide).to_string(), ty: ty.clone() },
                rhs: Value::Register { name: a64_name(rm, is_wide).to_string(), ty },
            });
            return (4, true, None);
        }

        if (instr & 0x1F000000) == 0x0A000000 {
            let opc = (instr >> 29) & 0x3;
            let is_wide = (instr >> 31) & 1 == 0;
            let ty = if is_wide { Ty::i32() } else { Ty::i64() };
            let rd = (instr & 0x1F) as u8;
            let rn = ((instr >> 5) & 0x1F) as u8;
            let rm = ((instr >> 16) & 0x1F) as u8;
            let op = match opc {
                0 => OpCode::And,
                1 => OpCode::Or,
                2 => OpCode::Xor,
                _ => OpCode::And,
            };
            func.push_inst(block, IrInst::Binary {
                dst: Value::Register { name: a64_name(rd, is_wide).to_string(), ty: ty.clone() },
                op,
                lhs: Value::Register { name: a64_name(rn, is_wide).to_string(), ty: ty.clone() },
                rhs: Value::Register { name: a64_name(rm, is_wide).to_string(), ty },
            });
            return (4, true, None);
        }

        if (instr & 0x1F000000) == 0x11000000 {
            let is_sub = (instr >> 30) & 1 == 1;
            let is_wide = (instr >> 31) & 1 == 0;
            let rd = (instr & 0x1F) as u8;
            let rn = ((instr >> 5) & 0x1F) as u8;
            let imm = ((instr >> 10) & 0xFFF) as i64;
            let shift = ((instr >> 22) & 1) * 12;
            let shifted_imm = imm << shift;
            let ty = if is_wide { Ty::i32() } else { Ty::i64() };
            func.push_inst(block, IrInst::Binary {
                dst: Value::Register { name: a64_name(rd, is_wide).to_string(), ty: ty.clone() },
                op: if is_sub { OpCode::Sub } else { OpCode::Add },
                lhs: Value::Register { name: a64_name(rn, is_wide).to_string(), ty },
                rhs: Value::Const(shifted_imm),
            });
            return (4, true, None);
        }

        if (instr & 0x1F000000) == 0x12000000 {
            let opc = (instr >> 29) & 0x3;
            let is_64bit = (instr >> 31) & 1 == 1;
            let hw_shift = (instr >> 21) & 0x3;
            let imm16 = ((instr >> 5) & 0xFFFF) as u64;
            let rd = (instr & 0x1F) as u8;
            let name = if is_64bit {
                Self::aarch64_reg_name(rd)
            } else {
                Self::aarch64_w_reg_name(rd)
            };
            let dst = Value::Register {
                name: name.to_string(),
                ty: if is_64bit { Ty::i64() } else { Ty::i32() },
            };
            match opc {
                2 => {
                    let val = (imm16 << (hw_shift * 16)) as i64;
                    func.push_inst(block, IrInst::Unary {
                        dst,
                        op: OpCode::Copy,
                        src: Value::Const(val),
                    });
                }
                0 => {
                    let shifted = imm16 << (hw_shift * 16);
                    let mask: u64 = if is_64bit { u64::MAX } else { 0xFFFF_FFFF };
                    func.push_inst(block, IrInst::Unary {
                        dst,
                        op: OpCode::Copy,
                        src: Value::Const(((!shifted) & mask) as i64),
                    });
                }
                _ => {
                    self.warn_unsupported(address, instr, "arm64");
                    func.push_inst(block, IrInst::Nop);
                }
            }
            return (4, true, None);
        }

        if (instr & 0x9F000000) == 0x90000000 {
            let immlo = (instr >> 29) & 0x3;
            let immhi = (instr >> 5) & 0x7FFFF;
            let imm = sign_extend(((immhi << 2) | immlo) as i64, 21);
            let page = (((address >> 12) as i64 + imm) << 12) as u64;
            let rd = (instr & 0x1F) as u8;
            func.push_inst(block, IrInst::Unary {
                dst: self.reg(Self::aarch64_reg_name(rd)),
                op: OpCode::Copy,
                src: Value::Const(page as i64),
            });
            return (4, true, None);
        }

        if (instr & 0x9F000000) == 0x10000000 {
            let immlo = (instr >> 29) & 0x3;
            let immhi = (instr >> 5) & 0x7FFFF;
            let imm = sign_extend(((immhi << 2) | immlo) as i64, 21);
            let target_addr = (address as i64 + imm) as u64;
            let rd = (instr & 0x1F) as u8;
            func.push_inst(block, IrInst::Unary {
                dst: self.reg(Self::aarch64_reg_name(rd)),
                op: OpCode::Copy,
                src: Value::Const(target_addr as i64),
            });
            return (4, true, None);
        }

        self.warn_unsupported(address, instr, "arm64");
        func.push_inst(block, IrInst::Nop);
        (4, true, None)
    }

    /// Lift a single Thumb (T16/T32) instruction into `block`.
    ///
    /// Returns `Err(LifterError::UnsupportedInstruction)` for encodings
    /// outside the supported subset instead of lifting misleading IR.
    /// Covered subset: shifts by immediate, ADD/SUB (reg/imm3/imm8),
    /// MOV/CMP imm8, high-register MOV/CMP/ADD, BX/BLX register, LDR literal
    /// and sp-relative forms, word/byte/halfword immediate load/store,
    /// ADR/ADD-sp-imm, PUSH/POP, B.cond, short B, and long BL/BLX.
    fn lift_thumb_instruction(
        &self,
        func: &mut IrFunction,
        block: BlockId,
        code: &[u8],
        address: u64,
    ) -> Result<(usize, bool, Option<BlockId>), LifterError> {
        if code.len() < 2 {
            return Ok((2, false, None));
        }
        let hw = u16::from_le_bytes([code[0], code[1]]);

        if hw & 0xF800 == 0xE000 {
            let off = sign_extend((hw & 0x07FF) as i64, 11) << 1;
            let target_addr = (address as i64 + 4 + off) as u64;
            let target_block = func.add_block(&format!("loc_{:X}", target_addr));
            func.push_inst(block, IrInst::Branch { target: target_block });
            return Ok((2, true, None));
        }

        if hw & 0xF000 == 0xE000 || hw & 0xF000 == 0xF000 {
            if code.len() < 4 {
                return Err(LifterError::InvalidInstruction(
                    address,
                    "truncated Thumb-2 instruction".to_string(),
                ));
            }
            let hw2 = u16::from_le_bytes([code[2], code[3]]);
            if hw2 & 0xC000 != 0xC000 {
                let encoding = ((hw as u32) << 16) | hw2 as u32;
                self.warn_unsupported(address, encoding, "thumb");
                func.push_inst(block, IrInst::Nop);
                return Ok((4, true, None));
            }
            let s = ((hw >> 10) & 1) as i64;
            let j1 = ((hw2 >> 13) & 1) as i64;
            let j2 = ((hw2 >> 11) & 1) as i64;
            let i1 = (j1 ^ s) ^ 1;
            let i2 = (j2 ^ s) ^ 1;
            let off = (s << 24)
                | (i1 << 23)
                | (i2 << 22)
                | (((hw & 0x03FF) as i64) << 12)
                | (((hw2 & 0x07FF) as i64) << 1);
            let signed_off = if s == 1 { off - (1 << 25) } else { off };
            let is_blx = hw2 & 0x1000 == 0;
            let final_off = if is_blx { signed_off & !3 } else { signed_off };
            let target_addr = (address as i64 + 4 + final_off) as u64;
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
            return Ok((4, true, None));
        }

        macro_rules! unsupported {
            () => {
                return Err(LifterError::UnsupportedInstruction(format!(
                    "thumb instruction 0x{:04X} at 0x{:X}",
                    hw, address
                )))
            };
        }

        match hw >> 12 {
            0x0 | 0x1 => {
                if hw & 0x1800 == 0x1800 {
                    let imm_form = hw & 0x0400 != 0;
                    let is_sub = hw & 0x0200 != 0;
                    let operand = ((hw >> 6) & 0x7) as i64;
                    let rs = ((hw >> 3) & 0x7) as u8;
                    let rd = (hw & 0x7) as u8;
                    let rhs = if imm_form {
                        Value::Const(operand)
                    } else {
                        self.reg(Self::arm32_reg_name(operand as u8))
                    };
                    func.push_inst(block, IrInst::Binary {
                        dst: self.reg(Self::arm32_reg_name(rd)),
                        op: if is_sub { OpCode::Sub } else { OpCode::Add },
                        lhs: self.reg(Self::arm32_reg_name(rs)),
                        rhs,
                    });
                } else {
                    let op = match (hw >> 11) & 0x3 {
                        0 => OpCode::Shl,
                        1 => OpCode::Shr,
                        _ => OpCode::Sar,
                    };
                    let imm5 = ((hw >> 6) & 0x1F) as i64;
                    let rm = ((hw >> 3) & 0x7) as u8;
                    let rd = (hw & 0x7) as u8;
                    func.push_inst(block, IrInst::Binary {
                        dst: self.reg(Self::arm32_reg_name(rd)),
                        op,
                        lhs: self.reg(Self::arm32_reg_name(rm)),
                        rhs: Value::Const(imm5),
                    });
                }
            }

            0x2 | 0x3 => {
                let sub_op = (hw >> 11) & 0x3;
                let rd = ((hw >> 8) & 0x7) as u8;
                let imm = (hw & 0xFF) as i64;
                let rd_val = self.reg(Self::arm32_reg_name(rd));
                match sub_op {
                    0 => {
                        func.push_inst(block, IrInst::Unary {
                            dst: rd_val,
                            op: OpCode::Copy,
                            src: Value::Const(imm),
                        });
                    }
                    1 => {
                        let tmp = func.alloc_var(Ty::i32());
                        func.push_inst(block, IrInst::Binary {
                            dst: tmp,
                            op: OpCode::Sub,
                            lhs: rd_val,
                            rhs: Value::Const(imm),
                        });
                    }
                    2 | 3 => {
                        func.push_inst(block, IrInst::Binary {
                            dst: rd_val.clone(),
                            op: if sub_op == 2 { OpCode::Add } else { OpCode::Sub },
                            lhs: rd_val,
                            rhs: Value::Const(imm),
                        });
                    }
                    _ => unsupported!(),
                }
            }

            0x4 => {
                if hw & 0xFC00 == 0x4000 {
                    let alu = (hw >> 6) & 0xF;
                    let rm = ((hw >> 3) & 0x7) as u8;
                    let rd = (hw & 0x7) as u8;
                    let dn = self.reg(Self::arm32_reg_name(rd));
                    let src = self.reg(Self::arm32_reg_name(rm));
                    let simple_op = match alu {
                        0x0 => Some(OpCode::And),
                        0x1 => Some(OpCode::Xor),
                        0x2 => Some(OpCode::Shl),
                        0x3 => Some(OpCode::Shr),
                        0x4 => Some(OpCode::Sar),
                        0x5 => Some(OpCode::Add),
                        0x6 => Some(OpCode::Sub),
                        0x7 => Some(OpCode::Ror),
                        0xC => Some(OpCode::Or),
                        0xD => Some(OpCode::Mul),
                        _ => None,
                    };
                    if let Some(op) = simple_op {
                        let dst = dn.clone();
                        func.push_inst(block, IrInst::Binary {
                            dst,
                            op,
                            lhs: dn,
                            rhs: src,
                        });
                    } else {
                        match alu {
                            0x8 => {
                                let tmp = func.alloc_var(Ty::i32());
                                func.push_inst(block, IrInst::Binary {
                                    dst: tmp,
                                    op: OpCode::And,
                                    lhs: dn,
                                    rhs: src,
                                });
                            }
                            0x9 => {
                                func.push_inst(block, IrInst::Binary {
                                    dst: dn.clone(),
                                    op: OpCode::Sub,
                                    lhs: src,
                                    rhs: dn,
                                });
                            }
                            0xA => {
                                let tmp = func.alloc_var(Ty::i32());
                                func.push_inst(block, IrInst::Binary {
                                    dst: tmp,
                                    op: OpCode::Sub,
                                    lhs: dn,
                                    rhs: src,
                                });
                            }
                            0xB => {
                                let tmp = func.alloc_var(Ty::i32());
                                func.push_inst(block, IrInst::Binary {
                                    dst: tmp,
                                    op: OpCode::Add,
                                    lhs: dn,
                                    rhs: src,
                                });
                            }
                            0xE => {
                                let inverted = func.alloc_var(Ty::i32());
                                func.push_inst(block, IrInst::Unary {
                                    dst: inverted.clone(),
                                    op: OpCode::Not,
                                    src,
                                });
                                let dst = dn.clone();
                                func.push_inst(block, IrInst::Binary {
                                    dst,
                                    op: OpCode::And,
                                    lhs: dn,
                                    rhs: inverted,
                                });
                            }
                            0xF => {
                                func.push_inst(block, IrInst::Unary {
                                    dst: dn,
                                    op: OpCode::Not,
                                    src,
                                });
                            }
                            _ => unsupported!(),
                        }
                    }
                } else if hw & 0xFE00 == 0x4400 {
                    let op = (hw >> 8) & 0x3;
                    let d = ((hw >> 7) & 1) as u8;
                    let rm = ((hw >> 3) & 0xF) as u8;
                    let rd = (d << 3) | (hw & 0x7) as u8;
                    match op {
                        0 => {
                            func.push_inst(block, IrInst::Binary {
                                dst: self.reg(Self::arm32_reg_name(rd)),
                                op: OpCode::Add,
                                lhs: self.reg(Self::arm32_reg_name(rd)),
                                rhs: self.reg(Self::arm32_reg_name(rm)),
                            });
                        }
                        1 => {
                            let tmp = func.alloc_var(Ty::i32());
                            func.push_inst(block, IrInst::Binary {
                                dst: tmp,
                                op: OpCode::Sub,
                                lhs: self.reg(Self::arm32_reg_name(rd)),
                                rhs: self.reg(Self::arm32_reg_name(rm)),
                            });
                        }
                        2 => {
                            func.push_inst(block, IrInst::Unary {
                                dst: self.reg(Self::arm32_reg_name(rd)),
                                op: OpCode::Copy,
                                src: self.reg(Self::arm32_reg_name(rm)),
                            });
                        }
                        _ => {
                            if hw & 0x80 != 0 {
                                let lr = self.reg("lr");
                                func.push_inst(block, IrInst::Unary {
                                    dst: lr,
                                    op: OpCode::Copy,
                                    src: Value::Const((address + 4) as i64),
                                });
                                func.push_inst(block, IrInst::Call {
                                    dst: Some(self.reg("r0")),
                                    target: self.reg(Self::arm32_reg_name(rm)),
                                    args: Vec::new(),
                                });
                            } else {
                                func.push_inst(block, IrInst::IndirectBranch {
                                    target: self.reg(Self::arm32_reg_name(rm)),
                                });
                            }
                        }
                    }
                } else if hw & 0xF800 == 0x4800 {
                    let rt = ((hw >> 8) & 0x7) as u8;
                    let addr = (address + 4 + ((hw & 0xFF) as u64) * 4) as i64;
                    func.push_inst(block, IrInst::Load {
                        dst: self.reg(Self::arm32_reg_name(rt)),
                        addr: Value::Const(addr),
                        size: 4,
                    });
                } else {
                    unsupported!();
                }
            }

            0x5 => {
                unsupported!();
            }

            0x6 | 0x7 => {
                let is_byte = hw & 0x1000 != 0;
                let is_load = hw & 0x0800 != 0;
                let imm5 = ((hw >> 6) & 0x1F) as i64 * if is_byte { 1 } else { 4 };
                let rn = ((hw >> 3) & 0x7) as u8;
                let rt = (hw & 0x7) as u8;
                let size = if is_byte { 1 } else { 4 };
                let addr = func.alloc_var(Ty::i32());
                func.push_inst(block, IrInst::Binary {
                    dst: addr.clone(),
                    op: OpCode::Add,
                    lhs: self.reg(Self::arm32_reg_name(rn)),
                    rhs: Value::Const(imm5),
                });
                if is_load {
                    func.push_inst(block, IrInst::Load {
                        dst: self.reg(Self::arm32_reg_name(rt)),
                        addr,
                        size,
                    });
                } else {
                    func.push_inst(block, IrInst::Store {
                        addr,
                        value: self.reg(Self::arm32_reg_name(rt)),
                        size,
                    });
                }
            }

            0x8 => {
                let is_load = hw & 0x0800 != 0;
                let imm5 = ((hw >> 6) & 0x1F) as i64 * 2;
                let rn = ((hw >> 3) & 0x7) as u8;
                let rt = (hw & 0x7) as u8;
                let addr = func.alloc_var(Ty::i32());
                func.push_inst(block, IrInst::Binary {
                    dst: addr.clone(),
                    op: OpCode::Add,
                    lhs: self.reg(Self::arm32_reg_name(rn)),
                    rhs: Value::Const(imm5),
                });
                if is_load {
                    func.push_inst(block, IrInst::Load {
                        dst: self.reg(Self::arm32_reg_name(rt)),
                        addr,
                        size: 2,
                    });
                } else {
                    func.push_inst(block, IrInst::Store {
                        addr,
                        value: self.reg(Self::arm32_reg_name(rt)),
                        size: 2,
                    });
                }
            }

            0x9 => {
                let is_load = hw & 0x0800 != 0;
                let rt = ((hw >> 8) & 0x7) as u8;
                let off = ((hw & 0xFF) as i64) * 4;
                let addr = func.alloc_var(Ty::i32());
                func.push_inst(block, IrInst::Binary {
                    dst: addr.clone(),
                    op: OpCode::Add,
                    lhs: self.reg("sp"),
                    rhs: Value::Const(off),
                });
                if is_load {
                    func.push_inst(block, IrInst::Load {
                        dst: self.reg(Self::arm32_reg_name(rt)),
                        addr,
                        size: 4,
                    });
                } else {
                    func.push_inst(block, IrInst::Store {
                        addr,
                        value: self.reg(Self::arm32_reg_name(rt)),
                        size: 4,
                    });
                }
            }

            0xA => {
                let rd = ((hw >> 8) & 0x7) as u8;
                let off = ((hw & 0xFF) as i64) * 4;
                if hw & 0x0800 == 0 {
                    let val = (address + 4 + off as u64) as i64;
                    func.push_inst(block, IrInst::Unary {
                        dst: self.reg(Self::arm32_reg_name(rd)),
                        op: OpCode::Copy,
                        src: Value::Const(val),
                    });
                } else {
                    func.push_inst(block, IrInst::Binary {
                        dst: self.reg(Self::arm32_reg_name(rd)),
                        op: OpCode::Add,
                        lhs: self.reg("sp"),
                        rhs: Value::Const(off),
                    });
                }
            }

            0xB => {
                if hw & 0xFE00 == 0xB400 {
                    let link = ((hw >> 8) & 1) as i64;
                    let list = hw & 0xFF;
                    let count = list.count_ones() as i64 + link;
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(block, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Sub,
                        lhs: self.reg("sp"),
                        rhs: Value::Const(count * 4),
                    });
                    func.push_inst(block, IrInst::Unary {
                        dst: self.reg("sp"),
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                } else if hw & 0xFE00 == 0xBC00 {
                    let use_pc = (hw >> 8) & 1 == 1;
                    let list = hw & 0xFF;
                    let count = list.count_ones() as i64 + if use_pc { 1 } else { 0 };
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(block, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: OpCode::Add,
                        lhs: self.reg("sp"),
                        rhs: Value::Const(count * 4),
                    });
                    func.push_inst(block, IrInst::Unary {
                        dst: self.reg("sp"),
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                    if use_pc {
                        func.push_inst(block, IrInst::Return {
                            value: Some(self.reg("r0")),
                        });
                    }
                } else if hw & 0xFF00 == 0xBF00 {
                    func.push_inst(block, IrInst::Nop);
                } else if hw & 0xFF80 == 0xB000 || hw & 0xFF80 == 0xB080 {
                    let is_sub = hw & 0x0080 != 0;
                    let imm7 = ((hw & 0x7F) as i64) * 4;
                    let new_sp = func.alloc_var(Ty::i32());
                    func.push_inst(block, IrInst::Binary {
                        dst: new_sp.clone(),
                        op: if is_sub { OpCode::Sub } else { OpCode::Add },
                        lhs: self.reg("sp"),
                        rhs: Value::Const(imm7),
                    });
                    func.push_inst(block, IrInst::Unary {
                        dst: self.reg("sp"),
                        op: OpCode::Copy,
                        src: new_sp,
                    });
                } else {
                    unsupported!();
                }
            }

            0xC => {
                unsupported!();
            }

            0xD => {
                let cond = (hw >> 8) & 0xF;
                match cond {
                    0xF => {
                        let svc_number = hw & 0xFF;
                        func.push_inst(block, IrInst::Syscall {
                            number: Some(Value::Const(svc_number as i64)),
                            args: Vec::new(),
                        });
                    }
                    0xE => unsupported!(),
                    _ => {
                        let off = sign_extend((hw & 0xFF) as i64, 8) << 1;
                        let target_addr = (address as i64 + 4 + off) as u64;
                        let cond_flag = func.alloc_var(Ty::Bool);
                        let taken = func.add_block(&format!("taken_{:X}", address));
                        let after = func.add_block(&format!("after_{:X}", address));
                        func.push_inst(block, IrInst::CBranch {
                            cond: cond_flag,
                            target_true: taken,
                            target_false: after,
                        });
                        let loc = func.add_block(&format!("loc_{:X}", target_addr));
                        func.push_inst(taken, IrInst::Branch { target: loc });
                        return Ok((2, true, Some(after)));
                    }
                }
            }

            _ => {
                unsupported!();
            }
        }

        Ok((2, true, None))
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

            let (consumed, lifted, next_block) = if self.is_64bit {
                self.lift_aarch64_instruction(&mut func, current_block, remaining, address)
            } else if self.is_thumb {
                self.lift_thumb_instruction(&mut func, current_block, remaining, address)?
            } else {
                self.lift_arm32_instruction(&mut func, current_block, remaining, address)
            };

            if consumed == 0 {
                break;
            }

            offset += consumed;
            instruction_count += 1;

            if lifted {
                current_block = match next_block {
                    Some(nb) => nb,
                    None => {
                        let terminated = func
                            .block(current_block)
                            .and_then(|b| b.terminator())
                            .is_some();
                        if terminated {
                            func.add_block(&format!("bb_{}", offset))
                        } else {
                            current_block
                        }
                    }
                };
            }
        }

        crate::ir::repair_block_graph(&mut func, parse_arm_block_addr);
        func.build_cfg();
        Ok(func)
    }
}

/// Address encoded in an ARM lifter block label: `bb_N` chunks carry a code
/// offset relative to the function base, while `loc_/after_/guarded_/taken_`
/// labels carry absolute hex addresses.
fn parse_arm_block_addr(label: &str, base_address: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
        return rest.parse::<usize>().ok().map(|o| base_address + o as u64);
    }
    for prefix in ["loc_", "after_", "guarded_", "taken_"] {
        if let Some(rest) = label.strip_prefix(prefix) {
            return u64::from_str_radix(rest, 16).ok();
        }
    }
    None
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
        assert!(func.blocks.len() > 1);
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

    #[test]
    fn test_arm32_rsb_reversed_operands() {
        let lifter = ArmLifter::new(false, false);
        // RSB R0, R1, #10 (0xE261000A)
        let code = [0x0A, 0x00, 0x61, 0xE2];
        let func = lifter.lift_function(&code, 0x1000, "rsb").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        let found = entry.insts.iter().any(|inst| match inst {
            IrInst::Binary { op: OpCode::Sub, lhs: Value::Const(10), rhs, .. } => {
                matches!(rhs, Value::Register { name, .. } if name == "r1")
            }
            _ => false,
        });
        assert!(found, "RSB must lift to Sub(imm, rn)");
    }

    #[test]
    fn test_arm32_bic_inverts_operand() {
        let lifter = ArmLifter::new(false, false);
        // BIC R0, R1, #1 (0xE3C10001)
        let code = [0x01, 0x00, 0xC1, 0xE3];
        let func = lifter.lift_function(&code, 0x1000, "bic").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        let has_not = entry
            .insts
            .iter()
            .any(|i| matches!(i, IrInst::Unary { op: OpCode::Not, src: Value::Const(1), .. }));
        let has_and_rn = entry.insts.iter().any(|i| match i {
            IrInst::Binary { op: OpCode::And, lhs, .. } => {
                matches!(lhs, Value::Register { name, .. } if name == "r1")
            }
            _ => false,
        });
        assert!(has_not && has_and_rn);
    }

    #[test]
    fn test_arm32_cmp_writes_temp_not_rd() {
        let lifter = ArmLifter::new(false, false);
        // CMP R0, #1 (0xE3500001)
        let code = [0x01, 0x00, 0x50, 0xE3];
        let func = lifter.lift_function(&code, 0x1000, "cmp").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert_eq!(entry.insts.len(), 1);
        match &entry.insts[0] {
            IrInst::Binary { dst: Value::Var { .. }, op: OpCode::Sub, lhs, rhs } => {
                assert!(matches!(lhs, Value::Register { name, .. } if name == "r0"));
                assert_eq!(*rhs, Value::Const(1));
            }
            other => panic!("CMP must write a temp var, got {:?}", other),
        }
    }

    #[test]
    fn test_arm32_conditional_instruction_guarded_by_cbranch() {
        let lifter = ArmLifter::new(false, false);
        // MOVNE R0, #1 (0x13A00001)
        let code = [0x01, 0x00, 0xA0, 0x13];
        let func = lifter.lift_function(&code, 0x1000, "movne").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(entry.terminator(), Some(IrInst::CBranch { .. })));
        let guard_has_mov = func.blocks.iter().any(|b| {
            b.label.starts_with("guarded_")
                && b.insts.iter().any(|i| match i {
                    IrInst::Unary { op: OpCode::Copy, src: Value::Const(1), dst } => {
                        matches!(dst, Value::Register { name, .. } if name == "r0")
                    }
                    _ => false,
                })
        });
        assert!(guard_has_mov);
    }

    #[test]
    fn test_arm32_ldr_postindex_writeback() {
        let lifter = ArmLifter::new(false, false);
        // LDR R0, [R1], #4 (0xE4910004)
        let code = [0x04, 0x00, 0x91, 0xE4];
        let func = lifter.lift_function(&code, 0x1000, "ldrpost").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        let load_ok = entry
            .insts
            .iter()
            .any(|i| matches!(i, IrInst::Load { dst, size: 4, .. }
                if matches!(dst, Value::Register { name, .. } if name == "r0")));
        let base_add = entry.insts.iter().any(|i| match i {
            IrInst::Binary { op: OpCode::Add, lhs, rhs: Value::Const(4), .. } => {
                matches!(lhs, Value::Register { name, .. } if name == "r1")
            }
            _ => false,
        });
        let wb_ok = entry.insts.iter().any(|i| match i {
            IrInst::Unary { op: OpCode::Copy, src: Value::Var { .. }, dst } => {
                matches!(dst, Value::Register { name, .. } if name == "r1")
            }
            _ => false,
        });
        assert!(load_ok && base_add && wb_ok);
    }

    #[test]
    fn test_arm32_str_preindex_writeback() {
        let lifter = ArmLifter::new(false, false);
        // STR R0, [R1, #4]! (0xE5A10004)
        let code = [0x04, 0x00, 0xA1, 0xE5];
        let func = lifter.lift_function(&code, 0x1000, "strpre").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        let store_ok = entry
            .insts
            .iter()
            .any(|i| matches!(i, IrInst::Store { size: 4, value, .. }
                if matches!(value, Value::Register { name, .. } if name == "r0")));
        let wb_ok = entry.insts.iter().any(|i| match i {
            IrInst::Unary { op: OpCode::Copy, src: Value::Var { .. }, dst } => {
                matches!(dst, Value::Register { name, .. } if name == "r1")
            }
            _ => false,
        });
        assert!(store_ok && wb_ok);
    }

    #[test]
    fn test_aarch64_bcond_creates_cbranch() {
        let lifter = ArmLifter::new(true, false);
        // B.EQ +8 (0x54000040)
        let code = [0x40, 0x00, 0x00, 0x54];
        let func = lifter.lift_function(&code, 0x400000, "bcond").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        match entry.terminator() {
            Some(IrInst::CBranch { .. }) => {}
            other => panic!("B.cond must end in CBranch, got {:?}", other),
        }
        assert!(func.blocks.len() >= 3);
    }

    #[test]
    fn test_aarch64_cbz_compares_zero_then_branches() {
        let lifter = ArmLifter::new(true, false);
        // CBZ X0, +8 (0xB4000040)
        let code = [0x40, 0x00, 0x00, 0xB4];
        let func = lifter.lift_function(&code, 0x400000, "cbz").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        let has_eq = entry.insts.iter().any(|i| match i {
            IrInst::Binary { op: OpCode::Eq, lhs, rhs: Value::Const(0), .. } => {
                matches!(lhs, Value::Register { name, .. } if name == "x0")
            }
            _ => false,
        });
        assert!(has_eq);
        assert!(matches!(entry.terminator(), Some(IrInst::CBranch { .. })));
    }

    #[test]
    fn test_aarch64_unknown_emits_nop_with_warning() {
        let lifter = ArmLifter::new(true, false);
        let code = [0x00, 0x00, 0x00, 0x00];
        let func = lifter.lift_function(&code, 0x400000, "unk").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.insts.iter().any(|i| matches!(i, IrInst::Nop)));
        assert_eq!(lifter.take_warnings().len(), 1);
    }

    #[test]
    fn test_thumb_mov_imm8() {
        let lifter = ArmLifter::new(false, true);
        // MOVS R0, #42 (0x202A)
        let code = [0x2A, 0x20];
        let func = lifter.lift_function(&code, 0x1000, "tmov").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.insts.iter().any(|i| match i {
            IrInst::Unary { op: OpCode::Copy, src: Value::Const(42), dst } => {
                matches!(dst, Value::Register { name, .. } if name == "r0")
            }
            _ => false,
        }));
    }

    #[test]
    fn test_thumb_bcond_creates_cbranch() {
        let lifter = ArmLifter::new(false, true);
        // BEQ +0 (0xD000)
        let code = [0x00, 0xD0];
        let func = lifter.lift_function(&code, 0x2000, "tb").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(entry.terminator(), Some(IrInst::CBranch { .. })));
    }

    #[test]
    fn test_thumb_bl_long_call() {
        let lifter = ArmLifter::new(false, true);
        // BL +0 (0xF000 0xF800)
        let code = [0x00, 0xF0, 0x00, 0xF8];
        let func = lifter.lift_function(&code, 0x2000, "tbl").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.insts.iter().any(|i| matches!(i, IrInst::Call { .. })));
    }

    #[test]
    fn test_thumb_pop_pc_returns() {
        let lifter = ArmLifter::new(false, true);
        // POP {R0, PC} (0xBD01)
        let code = [0x01, 0xBD];
        let func = lifter.lift_function(&code, 0x2000, "tpop").unwrap();
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.is_return_block());
        assert!(entry.insts.iter().any(|i| matches!(i,
            IrInst::Binary { op: OpCode::Add, lhs, rhs: Value::Const(8), .. }
            if matches!(lhs, Value::Register { name, .. } if name == "sp"))));
    }

    #[test]
    fn test_thumb_unknown_is_error() {
        let lifter = ArmLifter::new(false, true);
        // STR R0, [R1, R2] register-offset form (0x5080) — outside supported subset
        let code = [0x80, 0x50];
        let err = lifter.lift_function(&code, 0x1000, "bad").unwrap_err();
        assert!(matches!(err, LifterError::UnsupportedInstruction(_)));
    }

    fn assert_all_branch_targets_have_code(func: &IrFunction) {
        let mut targets: Vec<BlockId> = Vec::new();
        for b in &func.blocks {
            match b.terminator() {
                Some(IrInst::Branch { target }) => targets.push(*target),
                Some(IrInst::CBranch { target_true, target_false, .. }) => {
                    targets.push(*target_true);
                    targets.push(*target_false);
                }
                _ => {}
            }
        }
        for t in targets {
            let tb = func.block(t).unwrap_or_else(|| panic!("target bb{} missing", t.0));
            assert!(
                !tb.insts.is_empty(),
                "branch target bb{} ({}) must contain lifted code, not an empty label",
                t.0,
                tb.label
            );
        }
    }

    #[test]
    fn test_aarch64_branch_edges_reach_real_code() {
        let lifter = ArmLifter::new(true, false);
        // CBZ X0, +8 ; B +4 ; RET — both paths converge on the RET block.
        let code = [
            0x40, 0x00, 0x00, 0xB4, // CBZ X0, 0x400008
            0x01, 0x00, 0x00, 0x14, // B 0x400008
            0xC0, 0x03, 0x5F, 0xD6, // RET
        ];
        let func = lifter.lift_function(&code, 0x400000, "conv").unwrap();
        assert_all_branch_targets_have_code(&func);
    }

    #[test]
    fn test_thumb_conditional_branch_edges_reach_real_code() {
        let lifter = ArmLifter::new(false, true);
        // BEQ +4 ; B to the POP ; POP {R0, PC}
        let code = [
            0x00, 0xD0, // BEQ 0x2004
            0xFF, 0xE7, // B 0x2004
            0x01, 0xBD, // POP {R0, PC}
        ];
        let func = lifter.lift_function(&code, 0x2000, "t16").unwrap();
        assert_all_branch_targets_have_code(&func);
    }

    #[test]
    fn test_arm32_conditional_branch_edges_reach_real_code() {
        let lifter = ArmLifter::new(false, false);
        // BEQ +8 ; B to the MOV ; MOV R0, #0
        let code = [
            0x00, 0x00, 0x00, 0x0A, // BEQ 0x1008
            0xFF, 0xFF, 0xFF, 0xEA, // B 0x1008
            0x00, 0x00, 0xA0, 0xE3, // MOV R0, #0
        ];
        let func = lifter.lift_function(&code, 0x1000, "a32").unwrap();
        assert_all_branch_targets_have_code(&func);
    }
}



