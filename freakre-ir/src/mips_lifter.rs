//! MIPS32/MIPS64 lifter — minimal stub for now.
//! Handles common MIPS instructions and falls back to Nop for unknown.

use crate::ir::{IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

pub struct MipsLifter {
    is_64bit: bool,
    max_instructions: usize,
}

impl MipsLifter {
    pub fn new(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            max_instructions: 100_000,
        }
    }

    fn reg(&self, idx: u8) -> Value {
        let name = match idx {
            0 => "zero",
            1 => "at",
            2 => "v0",
            3 => "v1",
            4 => "a0",
            5 => "a1",
            6 => "a2",
            7 => "a3",
            8 => "t0",
            9 => "t1",
            10 => "t2",
            11 => "t3",
            12 => "t4",
            13 => "t5",
            14 => "t6",
            15 => "t7",
            16 => "s0",
            17 => "s1",
            18 => "s2",
            19 => "s3",
            20 => "s4",
            21 => "s5",
            22 => "s6",
            23 => "s7",
            24 => "t8",
            25 => "t9",
            26 => "k0",
            27 => "k1",
            28 => "gp",
            29 => "sp",
            30 => "fp",
            31 => "ra",
            _ => "r?",
        };
        Value::Register {
            name: name.to_string(),
            ty: if self.is_64bit { Ty::i64() } else { Ty::i32() },
        }
    }
}

impl Lifter for MipsLifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit {
            "mips64"
        } else {
            "mips32"
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
        // See x86_lifter: clamp hostile base addresses once, up front.
        let base_address = crate::lifter::clamp_base_address(base_address, code.len());
        let mut func = IrFunction::new(function_name, base_address);
        let mut current_block = func.entry_block;
        let mut offset = 0usize;

        while offset + 4 <= code.len() {
            let instr = u32::from_be_bytes([
                code[offset],
                code[offset + 1],
                code[offset + 2],
                code[offset + 3],
            ]);
            // Also try LE
            let instr_le = u32::from_le_bytes([
                code[offset],
                code[offset + 1],
                code[offset + 2],
                code[offset + 3],
            ]);
            // Heuristic: use BE if more plausible
            let word = if instr >> 26 == 0 && instr_le >> 26 != 0 {
                instr_le
            } else {
                instr
            };
            let opcode = (word >> 26) & 0x3F;
            let rs = ((word >> 21) & 0x1F) as u8;
            let rt = ((word >> 16) & 0x1F) as u8;
            let rd = ((word >> 11) & 0x1F) as u8;
            let _shamt = (word >> 6) & 0x1F;
            let funct = word & 0x3F;
            let imm = (word & 0xFFFF) as i16 as i64;
            let target = word & 0x3FFFFFF;

            let address = base_address + offset as u64;

            match opcode {
                0x00 => {
                    // R-type
                    match funct {
                        0x20 => {
                            // add
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::Add,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x21 => {
                            // addu
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::Add,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x22 => {
                            // sub
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::Sub,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x24 => {
                            // and
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::And,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x25 => {
                            // or
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::Or,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x26 => {
                            // xor
                            let dst = self.reg(rd);
                            func.push_inst(
                                current_block,
                                IrInst::Binary {
                                    dst,
                                    op: OpCode::Xor,
                                    lhs: self.reg(rs),
                                    rhs: self.reg(rt),
                                },
                            );
                        }
                        0x08 => {
                            // jr
                            if rs == 31 {
                                func.push_inst(current_block, IrInst::Return { value: None });
                            } else {
                                func.push_inst(
                                    current_block,
                                    IrInst::IndirectBranch {
                                        target: self.reg(rs),
                                    },
                                );
                            }
                        }
                        0x09 => {
                            // jalr
                            func.push_inst(
                                current_block,
                                IrInst::Call {
                                    dst: Some(self.reg(rd)),
                                    target: self.reg(rs),
                                    args: vec![],
                                },
                            );
                        }
                        _ => {
                            func.push_inst(current_block, IrInst::Nop);
                        }
                    }
                }
                0x02 => {
                    // j
                    let target_addr = (base_address & 0xF0000000) | ((target as u64) << 2);
                    let nb = func.add_block(&format!("loc_{:X}", target_addr));
                    func.push_inst(current_block, IrInst::Branch { target: nb });
                    current_block = func.add_block(&format!("bb_{}", offset + 4));
                }
                0x03 => {
                    // jal
                    let target_addr = (base_address & 0xF0000000) | ((target as u64) << 2);
                    func.push_inst(
                        current_block,
                        IrInst::Call {
                            dst: Some(self.reg(31)),
                            target: Value::Symbol(format!("func_{:X}", target_addr)),
                            args: vec![],
                        },
                    );
                }
                0x04 => {
                    // beq
                    let off = imm << 2;
                    let target_addr = (address as i64 + 4 + off) as u64;
                    let taken = func.add_block(&format!("loc_{:X}", target_addr));
                    let not_taken = func.add_block(&format!("fall_{:X}", address + 4));
                    let cond = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op: OpCode::Eq,
                            lhs: self.reg(rs),
                            rhs: self.reg(rt),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::CBranch {
                            cond,
                            target_true: taken,
                            target_false: not_taken,
                        },
                    );
                    current_block = not_taken;
                }
                0x05 => {
                    // bne
                    let off = imm << 2;
                    let target_addr = (address as i64 + 4 + off) as u64;
                    let taken = func.add_block(&format!("loc_{:X}", target_addr));
                    let not_taken = func.add_block(&format!("fall_{:X}", address + 4));
                    let cond = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op: OpCode::Ne,
                            lhs: self.reg(rs),
                            rhs: self.reg(rt),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::CBranch {
                            cond,
                            target_true: taken,
                            target_false: not_taken,
                        },
                    );
                    current_block = not_taken;
                }
                0x08 | 0x09 => {
                    // addi/addiu
                    let dst = self.reg(rt);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst,
                            op: OpCode::Add,
                            lhs: self.reg(rs),
                            rhs: Value::Const(imm),
                        },
                    );
                }
                0x0C => {
                    // andi
                    let dst = self.reg(rt);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst,
                            op: OpCode::And,
                            lhs: self.reg(rs),
                            rhs: Value::Const(imm & 0xFFFF),
                        },
                    );
                }
                0x0D => {
                    // ori
                    let dst = self.reg(rt);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst,
                            op: OpCode::Or,
                            lhs: self.reg(rs),
                            rhs: Value::Const(imm & 0xFFFF),
                        },
                    );
                }
                0x0F => {
                    // lui
                    let dst = self.reg(rt);
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst,
                            op: OpCode::Copy,
                            src: Value::Const(imm << 16),
                        },
                    );
                }
                0x23 => {
                    // lw
                    let dst = self.reg(rt);
                    let addr = func.alloc_var(if self.is_64bit { Ty::i64() } else { Ty::i32() });
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.reg(rs),
                            rhs: Value::Const(imm),
                        },
                    );
                    func.push_inst(current_block, IrInst::Load { dst, addr, size: 4 });
                }
                0x2B => {
                    // sw
                    let addr = func.alloc_var(if self.is_64bit { Ty::i64() } else { Ty::i32() });
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.reg(rs),
                            rhs: Value::Const(imm),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Store {
                            addr,
                            value: self.reg(rt),
                            size: 4,
                        },
                    );
                }
                _ => {
                    func.push_inst(current_block, IrInst::Nop);
                }
            }

            // Check for terminator and create new block if needed
            if let Some(block) = func.block(current_block) {
                if block.terminator().is_some() && offset + 4 < code.len() {
                    // Only create fallthrough if not already branching to it
                    let has_fallthrough =
                        matches!(block.terminator(), Some(IrInst::CBranch { .. }));
                    if has_fallthrough {
                        // CBranch already has fallthrough, current_block is already set to not_taken
                    } else if matches!(
                        block.terminator(),
                        Some(IrInst::Branch { .. }) | Some(IrInst::IndirectBranch { .. })
                    ) {
                        // Unconditional - need new block for next insn if not already
                        if func
                            .blocks
                            .iter()
                            .any(|b| b.label == format!("bb_{}", offset + 4))
                        {
                            // reuse?
                        } else {
                            current_block = func.add_block(&format!("bb_{}", offset + 4));
                        }
                    }
                }
            }

            offset += 4;
            if func.blocks.len() > 1000 || offset > 100_000 {
                break;
            }
        }

        crate::ir::repair_block_graph(&mut func, parse_block_addr);
        func.build_cfg();
        Ok(func)
    }
}

fn parse_block_addr(label: &str, base_address: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
        // saturating: `o` comes from a (possibly hostile) label string.
        return rest
            .parse::<usize>()
            .ok()
            .map(|o| base_address.saturating_add(o as u64));
    }
    for prefix in ["loc_", "fall_"] {
        if let Some(rest) = label.strip_prefix(prefix) {
            return u64::from_str_radix(rest, 16).ok();
        }
    }
    None
}
