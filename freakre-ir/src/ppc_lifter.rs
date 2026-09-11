//! PowerPC (PPC32/PPC64) lifter — fixed 32-bit big-endian instruction
//! decoder producing IR.
//!
//! Covers the integer subset that dominates real-world firmware: D-form
//! arithmetic (addi/addis/ori/...), loads/stores (lwz/lbz/lhz/stb/...),
//! X-form ALU (add/subf/and/or/xor/slw/srw/sraw/neg/extsh/extsb), rotates
//! (rlwinm), compares (cmp/cmpl), branches (b/bc/bclr/bcctr), and mflr/mtlr/
//! mfctr/mtctr. Unhandled encodings lift as `Nop` (riscv-lifter convention).

use crate::ir::{IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

pub struct PpcLifter {
    is_64bit: bool,
    max_instructions: usize,
}

impl PpcLifter {
    pub fn new(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            max_instructions: 100_000,
        }
    }

    fn word_ty(&self) -> Ty {
        if self.is_64bit {
            Ty::i64()
        } else {
            Ty::i32()
        }
    }

    fn reg(&self, idx: u32) -> Value {
        // r0..r31; ABI aliases (r1=sp, r3-r10=args) stay numeric — the
        // decompiler's param recovery works off the canonical names.
        Value::Register {
            name: format!("r{}", idx),
            ty: self.word_ty(),
        }
    }

    fn sreg(&self, idx: u32) -> Value {
        self.reg(idx)
    }
}

/// Signed 16-bit immediate from a D-form instruction.
fn d_si(word: u32) -> i64 {
    (word & 0xFFFF) as u16 as i16 as i64
}

/// Signed branch displacement (BD field, PPC bits 16-29 = value bits 15-2,
/// word-aligned).
fn b_bd(word: u32) -> i64 {
    let v = ((word >> 2) & 0x3FFF) as i64;
    if v & 0x2000 != 0 {
        v - 0x4000
    } else {
        v
    }
}

/// Signed I-form target offset (LI field, PPC bits 6-29 = value bits 25-2,
/// already byte-scaled by the <<2 in the encoding).
fn i_li(word: u32) -> i64 {
    let v = (word & 0x03FF_FFFC) as i64;
    if v & 0x0200_0000 != 0 {
        v - 0x0400_0000
    } else {
        v
    }
}

impl Lifter for PpcLifter {
    fn arch_name(&self) -> &str {
        if self.is_64bit {
            "ppc64"
        } else {
            "ppc32"
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
            let word = u32::from_be_bytes([
                code[offset],
                code[offset + 1],
                code[offset + 2],
                code[offset + 3],
            ]);
            let address = base_address + offset as u64;
            let opcode = word >> 26;
            // Common field decoders.
            let rt = (word >> 21) & 0x1F;
            let ra = (word >> 16) & 0x1F;
            let rb = (word >> 11) & 0x1F;
            let xo = (word >> 1) & 0x3FF;
            let lk = word & 1;

            match opcode {
                // ── D-form arithmetic ─────────────────────────────
                14 => {
                    // addi (RA=0 → li)
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                }
                15 => {
                    // addis (RA=0 → lis)
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word) << 16),
                        },
                    );
                }
                7 => {
                    // mulli
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Mul,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                }
                12 => {
                    // addic
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                }
                13 => {
                    // addic. — same add, but writes CR0; flags modeled
                    // implicitly by the compare consumers, so plain Add.
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                }
                8 => {
                    // subfic: RT = SI + ~RA + 1 = SI - RA
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(rt),
                            op: OpCode::Sub,
                            lhs: Value::Const(d_si(word)),
                            rhs: self.sreg(ra),
                        },
                    );
                }
                10 => {
                    // cmpli (unsigned) — CR0 flag bits
                    let flag = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: flag.clone(),
                            op: OpCode::LtU,
                            lhs: self.sreg(ra),
                            rhs: Value::Const((word & 0xFFFF) as i64),
                        },
                    );
                    let _ = flag;
                }
                11 => {
                    // cmpi (signed)
                    let flag = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: flag.clone(),
                            op: OpCode::LtS,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                    let _ = flag;
                }
                // ── D-form logical immediates ─────────────────────
                24 => {
                    // ori (RA=0 → nop canonical form ori r0,r0,0)
                    if !(rt == 0 && ra == 0 && word & 0xFFFF == 0) {
                        func.push_inst(
                            current_block,
                            IrInst::Binary {
                                dst: self.sreg(ra),
                                op: OpCode::Or,
                                lhs: self.sreg(ra),
                                rhs: Value::Const((word & 0xFFFF) as i64),
                            },
                        );
                    } else {
                        func.push_inst(current_block, IrInst::Nop);
                    }
                }
                25 => {
                    // oris
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(ra),
                            op: OpCode::Or,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(((word & 0xFFFF) as i64) << 16),
                        },
                    );
                }
                26 => {
                    // xori
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(ra),
                            op: OpCode::Xor,
                            lhs: self.sreg(ra),
                            rhs: Value::Const((word & 0xFFFF) as i64),
                        },
                    );
                }
                27 => {
                    // xoris
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(ra),
                            op: OpCode::Xor,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(((word & 0xFFFF) as i64) << 16),
                        },
                    );
                }
                28 => {
                    // andi.
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(ra),
                            op: OpCode::And,
                            lhs: self.sreg(ra),
                            rhs: Value::Const((word & 0xFFFF) as i64),
                        },
                    );
                }
                29 => {
                    // andis.
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: self.sreg(ra),
                            op: OpCode::And,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(((word & 0xFFFF) as i64) << 16),
                        },
                    );
                }
                // ── Loads / stores (D-form) ───────────────────────
                32 | 34 | 40 => {
                    // lwz / lbz / lhz
                    let size = match opcode {
                        34 => 1,
                        40 => 2,
                        _ => 4,
                    };
                    let addr = func.alloc_var(self.word_ty());
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                    func.push_inst(current_block, IrInst::Load {
                        dst: self.sreg(rt),
                        addr,
                        size,
                    });
                }
                58 => {
                    // ld (PPC64, DS-form: D is 16-bit but low 2 bits are
                    // part of the XO encoding — D<<2)
                    let addr = func.alloc_var(Ty::i64());
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Load {
                            dst: self.sreg(rt),
                            addr,
                            size: 8,
                        },
                    );
                }
                36 | 38 | 44 => {
                    // stw / stb / sth
                    let size = match opcode {
                        38 => 1,
                        44 => 2,
                        _ => 4,
                    };
                    let addr = func.alloc_var(self.word_ty());
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Store {
                            addr,
                            value: self.sreg(rt),
                            size,
                        },
                    );
                }
                62 => {
                    // std (PPC64)
                    let addr = func.alloc_var(Ty::i64());
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: addr.clone(),
                            op: OpCode::Add,
                            lhs: self.sreg(ra),
                            rhs: Value::Const(d_si(word)),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Store {
                            addr,
                            value: self.sreg(rt),
                            size: 8,
                        },
                    );
                }
                // ── Branches ──────────────────────────────────────
                18 => {
                    // b / bl (I-form). AA=absolute is rare in PIC code;
                    // treat as relative (AA bit 30).
                    let _aa = (word >> 30) & 1;
                    let target = address.wrapping_add(i_li(word) as u64);
                    let target_block = func.add_block(&format!("loc_{:X}", target));
                    if lk == 1 {
                        // bl: call — LR is written by the callee convention.
                        func.push_inst(
                            current_block,
                            IrInst::Call {
                                dst: Some(self.sreg(3)),
                                target: Value::Symbol(format!("func_{:X}", target)),
                                args: vec![],
                            },
                        );
                        let next = func.add_block(&format!("bb_{}", offset + 4));
                        func.push_inst(current_block, IrInst::Branch { target: next });
                        current_block = next;
                    } else {
                        func.push_inst(
                            current_block,
                            IrInst::Branch {
                                target: target_block,
                            },
                        );
                    }
                }
                16 => {
                    // bc (B-form): BO/BI conditional branch.
                    let bo = (word >> 21) & 0x1F;
                    let bi = (word >> 16) & 0x1F;
                    let target = (address as i64 + b_bd(word)) as u64;
                    let taken = func.add_block(&format!("loc_{:X}", target));
                    let not_taken = func.add_block(&format!("fall_{:X}", address + 4));
                    if bo & 0x10 != 0 {
                        // Branch always (BO bit 4).
                        func.push_inst(
                            current_block,
                            IrInst::Branch {
                                target: taken,
                            },
                        );
                        current_block = not_taken;
                    } else {
                        // Condition on CR bit BI: 0=LT 1=GT 2=EQ (CR0).
                        // The compare that set CR0 is lifted into a
                        // comparison value; here we materialize the branch
                        // condition from the last compare (structural
                        // approximation used by the riscv/mips lifters).
                        let cond = func.alloc_var(Ty::Bool);
                        let op = match bi & 3 {
                            2 => OpCode::Eq,
                            _ => OpCode::LtS,
                        };
                        let _ = op;
                        // Re-derive from the compare we track per-block:
                        // simplest sound model is a fresh bool source that
                        // the decompiler's flag machinery will fold.
                        func.push_inst(
                            current_block,
                            IrInst::Unary {
                                dst: cond.clone(),
                                op: OpCode::Copy,
                                src: Value::Register {
                                    name: format!("cr{}", bi & 7),
                                    ty: Ty::Bool,
                                },
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
                }
                19 => {
                    // X-form branch-family: bclr (16), bcctr (528), and
                    // condition-register ops.
                    match xo {
                        16 => {
                            // bclr: return (LR) or call via LR when LK=1.
                            if lk == 1 {
                                let target = func.alloc_var(self.word_ty());
                                func.push_inst(
                                    current_block,
                                    IrInst::Unary {
                                        dst: target.clone(),
                                        op: OpCode::Copy,
                                        src: Value::Register {
                                            name: "lr".to_string(),
                                            ty: self.word_ty(),
                                        },
                                    },
                                );
                                func.push_inst(
                                    current_block,
                                    IrInst::IndirectBranch { target },
                                );
                            } else {
                                func.push_inst(
                                    current_block,
                                    IrInst::Return {
                                        value: Some(self.sreg(3)),
                                    },
                                );
                            }
                        }
                        528 => {
                            // bcctr: tail call / jump table dispatch via CTR.
                            let target = func.alloc_var(self.word_ty());
                            func.push_inst(
                                current_block,
                                IrInst::Unary {
                                    dst: target.clone(),
                                    op: OpCode::Copy,
                                    src: Value::Register {
                                        name: "ctr".to_string(),
                                        ty: self.word_ty(),
                                    },
                                },
                            );
                            if lk == 1 {
                                func.push_inst(
                                    current_block,
                                    IrInst::Call {
                                        dst: Some(self.sreg(3)),
                                        target,
                                        args: vec![],
                                    },
                                );
                                func.push_inst(
                                    current_block,
                                    IrInst::Return {
                                        value: Some(self.sreg(3)),
                                    },
                                );
                            } else {
                                func.push_inst(
                                    current_block,
                                    IrInst::IndirectBranch { target },
                                );
                            }
                        }
                        0 => {
                            // mcrf — CR move; modeled as Nop.
                            func.push_inst(current_block, IrInst::Nop);
                        }
                        _ => {
                            func.push_inst(current_block, IrInst::Nop);
                        }
                    }
                }
                // ── X-form ALU (opcode 31) ────────────────────────
                31 => {
                    let dst = self.sreg(rt);
                    let a = self.sreg(ra);
                    let b = self.sreg(rb);
                    match xo {
                        266 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Add, lhs: a, rhs: b }), // add
                        40 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Sub, lhs: b, rhs: a }),   // subf: RT = RB - RA
                        28 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::And, lhs: a, rhs: b }),   // and
                        444 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Or, lhs: a, rhs: b }),    // or
                        316 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Xor, lhs: a, rhs: b }),   // xor
                        476 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Not, lhs: Value::Const(0), rhs: a }), // nand → not(a and b) approximated as Not
                        124 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::And, lhs: a, rhs: b }),   // andc approximated
                        24 => {
                            // slw
                            let sh = func.alloc_var(self.word_ty());
                            func.push_inst(current_block, IrInst::Binary { dst: sh.clone(), op: OpCode::And, lhs: b, rhs: Value::Const(0x3F) });
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Shl, lhs: a, rhs: sh });
                        }
                        536 => {
                            // srw
                            let sh = func.alloc_var(self.word_ty());
                            func.push_inst(current_block, IrInst::Binary { dst: sh.clone(), op: OpCode::And, lhs: b, rhs: Value::Const(0x3F) });
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Shr, lhs: a, rhs: sh });
                        }
                        792 => {
                            // sraw
                            let sh = func.alloc_var(self.word_ty());
                            func.push_inst(current_block, IrInst::Binary { dst: sh.clone(), op: OpCode::And, lhs: b, rhs: Value::Const(0x3F) });
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Sar, lhs: a, rhs: sh });
                        }
                        104 => {
                            // neg
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Sub, lhs: Value::Const(0), rhs: a });
                        }
                        922 => {
                            // extsh
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::And, lhs: a, rhs: Value::Const(0xFFFF) });
                            // width thread continues in the decompiler.
                        }
                        954 => {
                            // extsb
                            func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::And, lhs: a, rhs: Value::Const(0xFF) });
                        }
                        0 => {
                            // cmp (signed, X-form): flag producer
                            let flag = func.alloc_var(Ty::Bool);
                            func.push_inst(current_block, IrInst::Binary { dst: flag, op: OpCode::LtS, lhs: a, rhs: b });
                        }
                        32 => {
                            // cmpl (unsigned)
                            let flag = func.alloc_var(Ty::Bool);
                            func.push_inst(current_block, IrInst::Binary { dst: flag, op: OpCode::LtU, lhs: a, rhs: b });
                        }
                        23 => {
                            // lwzx
                            func.push_inst(current_block, IrInst::Load { dst, addr: a, size: 4 });
                        }
                        87 => {
                            // lbzx
                            func.push_inst(current_block, IrInst::Load { dst, addr: a, size: 1 });
                        }
                        279 => {
                            // lhzx
                            func.push_inst(current_block, IrInst::Load { dst, addr: a, size: 2 });
                        }
                        151 => {
                            // stwx
                            func.push_inst(current_block, IrInst::Store { addr: a, value: dst.clone(), size: 4 });
                        }
                        215 => {
                            // stbx
                            func.push_inst(current_block, IrInst::Store { addr: a, value: dst.clone(), size: 1 });
                        }
                        407 => {
                            // sthx
                            func.push_inst(current_block, IrInst::Store { addr: a, value: dst.clone(), size: 2 });
                        }
                        339 => {
                            // mfspr: mflr (SPR=8) / mfctr (SPR=9)
                            let spr = ((word >> 11) & 0x3FF) >> 5 | (((word >> 11) & 0x3FF) & 0x1F) << 5;
                            let src_name = match spr {
                                8 => "lr",
                                9 => "ctr",
                                _ => "spr",
                            };
                            func.push_inst(
                                current_block,
                                IrInst::Unary {
                                    dst,
                                    op: OpCode::Copy,
                                    src: Value::Register {
                                        name: src_name.to_string(),
                                        ty: self.word_ty(),
                                    },
                                },
                            );
                        }
                        467 => {
                            // mtspr: mtlr / mtctr
                            let spr = ((word >> 11) & 0x3FF) >> 5 | (((word >> 11) & 0x3FF) & 0x1F) << 5;
                            let dst_name = match spr {
                                8 => "lr",
                                9 => "ctr",
                                _ => "spr",
                            };
                            func.push_inst(
                                current_block,
                                IrInst::Unary {
                                    dst: Value::Register {
                                        name: dst_name.to_string(),
                                        ty: self.word_ty(),
                                    },
                                    op: OpCode::Copy,
                                    src: self.sreg(rt),
                                },
                            );
                        }
                        491 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Div, lhs: a, rhs: b }), // divw
                        459 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Div, lhs: a, rhs: b }), // divwu
                        107 => func.push_inst(current_block, IrInst::Binary { dst, op: OpCode::Mul, lhs: a, rhs: b }),  // mulw
                        _ => func.push_inst(current_block, IrInst::Nop),
                    }
                }
                // ── Rotates ───────────────────────────────────────
                21 => {
                    // rlwinm: RA = rot(RS, SH) & mask(MB..ME)
                    // Common special cases: SH=0 → pure AND mask.
                    let sh = (word >> 11) & 0x1F;
                    let mb = (word >> 6) & 0x1F;
                    let me = (word >> 1) & 0x1F;
                    let src = self.sreg(rt); // RS field shares position with RT
                    if sh == 0 && mb <= me {
                        // Contiguous mask (MB..ME) — plain AND. The shift
                        // formula overflows only for the full-width mask.
                        let mask: u32 = if mb == 0 && me == 31 {
                            u32::MAX
                        } else {
                            ((1u32 << (me - mb + 1)) - 1) << (31 - me)
                        };
                        func.push_inst(
                            current_block,
                            IrInst::Binary {
                                dst: self.sreg(ra),
                                op: OpCode::And,
                                lhs: src,
                                rhs: Value::Const(mask as i64),
                            },
                        );
                    } else {
                        // Generic rotate+mask: model the rotate, drop the
                        // mask (width threading in the decompiler recovers
                        // the masking context).
                        func.push_inst(
                            current_block,
                            IrInst::Binary {
                                dst: self.sreg(ra),
                                op: OpCode::Rol,
                                lhs: src,
                                rhs: Value::Const(sh as i64),
                            },
                        );
                    }
                }
                _ => {
                    func.push_inst(current_block, IrInst::Nop);
                }
            }

            // Block-boundary bookkeeping identical to the riscv lifter.
            if let Some(b) = func.block(current_block) {
                if b.terminator().is_some() && offset + 4 < code.len() {
                    let next_label = format!("bb_{}", offset + 4);
                    if !func.blocks.iter().any(|b| b.label == next_label) {
                        let nb = func.add_block(&next_label);
                        let term = func
                            .block(current_block)
                            .and_then(|b| b.terminator().cloned());
                        if !matches!(term, Some(IrInst::CBranch { .. })) {
                            current_block = nb;
                        }
                    }
                }
            }
            offset += 4;
        }

        // Every function must end in a terminator for CFG validity.
        if func
            .block(current_block)
            .is_some_and(|b| b.terminator().is_none())
        {
            func.push_inst(
                current_block,
                IrInst::Return {
                    value: Some(self.sreg(3)),
                },
            );
        }

        crate::ir::repair_block_graph(&mut func, parse_block_addr);
        func.build_cfg();
        Ok(func)
    }
}

fn parse_block_addr(label: &str, base_address: u64) -> Option<u64> {
    if let Some(rest) = label.strip_prefix("bb_") {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn be(opcode: u32, a: u32, b: u32, c: u32) -> [u8; 4] {
        let word = (opcode << 26) | (a << 21) | (b << 16) | c;
        word.to_be_bytes()
    }

    fn lift(code: &[u8]) -> IrFunction {
        let lifter = PpcLifter::new(false);
        lifter.lift_function(code, 0x1000, "t").unwrap()
    }

    #[test]
    fn addi_lifts() {
        // addi r3, r3, 16
        let func = lift(&be(14, 3, 3, 16));
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Binary { op: OpCode::Add, .. }
        ));
    }

    #[test]
    fn lwz_stw_lift() {
        // lwz r3, 16(r1); stw r3, 20(r1)
        let mut code = Vec::new();
        code.extend_from_slice(&be(32, 3, 1, 16));
        code.extend_from_slice(&be(36, 3, 1, 20));
        let func = lift(&code);
        let entry = func.block(func.entry_block).unwrap();
        let has_load = entry
            .insts
            .iter()
            .any(|i| matches!(i, IrInst::Load { size: 4, .. }));
        let has_store = entry
            .insts
            .iter()
            .any(|i| matches!(i, IrInst::Store { size: 4, .. }));
        assert!(has_load && has_store);
    }

    #[test]
    fn bl_becomes_call() {
        // bl .+8 (LK=1)
        let word = (18u32 << 26) | ((8u32 / 4) << 2) | 1;
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.insts.iter().any(|i| i.is_call()));
    }

    #[test]
    fn bclr_is_return() {
        // bclr (opcode 19, XO=16, LK=0)
        let word: u32 = (19 << 26) | (16 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.is_return_block());
    }

    #[test]
    fn bc_branch_always_and_conditional() {
        // bc with BO=20 (always) → unconditional Branch.
        let word: u32 = (16 << 26) | (20 << 21) | ((8u32 / 4) << 2);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.terminator(),
            Some(IrInst::Branch { .. })
        ));

        // bc with BO=12 (conditional on CR) → CBranch.
        let word: u32 = (16 << 26) | (12 << 21) | (2 << 16) | ((8u32 / 4) << 2);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.terminator(),
            Some(IrInst::CBranch { .. })
        ));
    }

    #[test]
    fn rlwinm_and_mask_folds() {
        // rlwinm r3, r3, 0, 24, 31 (SH=0, MB=24, ME=31 → AND 0xFF)
        let word: u32 = (21 << 26) | (3 << 21) | (3 << 16) | (24 << 6) | (31 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(
            entry
                .insts
                .iter()
                .any(|i| matches!(i, IrInst::Binary { op: OpCode::And, rhs: Value::Const(0xFF), .. })),
            "rlwinm(SH=0, 24..31) must fold to AND 0xFF"
        );
    }

    #[test]
    fn xform_alu_ops() {
        // add r3, r4, r5 → X-form opcode 31, XO=266
        let word: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (266 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Binary { op: OpCode::Add, .. }
        ));

        // subf r3, r4, r5 → RT = RB - RA
        let word: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (40 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Binary { op: OpCode::Sub, .. }
        ));
    }

    #[test]
    fn mflr_mtlr_modelled() {
        // mflr r0: opcode 31, XO=339, SPR fields encode 8 (lr)
        let word: u32 = (31 << 26) | (8 << 16) | (339 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            &entry.insts[0],
            IrInst::Unary { src: Value::Register { name, .. }, .. } if name == "lr"
        ));
    }

    #[test]
    fn tail_call_via_bcctr() {
        // bctr (opcode 19, XO=528, LK=0) → IndirectBranch via ctr
        let word: u32 = (19 << 26) | (528 << 1);
        let func = lift(&word.to_be_bytes());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.terminator(),
            Some(IrInst::IndirectBranch { .. })
        ));
    }

    #[test]
    fn sparse_nops_do_not_panic() {
        // Random-ish words — decoder must not panic and must terminate.
        let code: Vec<u8> = (0u32..64)
            .map(|i| (i.wrapping_mul(0x13579BDF)).wrapping_shl(i % 3))
            .flat_map(|w| w.to_be_bytes().to_vec())
            .collect();
        let func = lift(&code);
        let _ = func.blocks.len();
    }
}
