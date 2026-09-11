//! Shared IR-generator logic for `fuzz_decompiler_ir` and `smoke_decompiler_ir`.
//!
//! Builds randomly generated (often malformed) IR functions: dangling block
//! references, cycles, missing terminators, phi nodes with bogus
//! predecessors, huge constants, unicode symbols. Both the libFuzzer target
//! and the standalone smoke runner consume this through the same code path,
//! so any contract violation found by one is reproducible with the other.

/// Deterministic seed for [`build_random_ir`]; any panic is reproducible by
/// logging these four bytes.
pub type Seed = [u8; 4];

/// Tiny deterministic PRNG (xorshift64*), no external deps.
pub struct XorShift(u64);

impl XorShift {
    pub fn from_seed(seed: &Seed) -> Self {
        let mut s = 0x9E3779B97F4A7C15u64;
        for (i, byte) in seed.iter().enumerate() {
            s ^= u64::from(*byte) << (i * 8 % 56);
        }
        XorShift(s.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Uniform value in `0..n` (n must be > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Run the decompiler contract checks on a randomly generated IR function.
///
/// Returns the emitted C on success (`Err` from the decompiler is fine;
/// panics/aborts are the bugs being hunted). The checks assert:
/// - no NUL byte in the emitted C (some pass must not smuggle raw binary
///   through the AST into the listing),
/// - determinism: same input, same output.
pub fn run_contract(func: &freakre_ir::IrFunction, seed: &Seed) -> Result<String, String> {
    match decompiler::decompile_function(func) {
        Ok(c) => {
            if c.as_bytes().contains(&0) {
                return Err(format!(
                    "NUL byte in emitted C (seed {seed:?})"
                ));
            }
            let c2 = decompiler::decompile_function(func)
                .map_err(|e| format!("second run errored where first succeeded: {e}"))?;
            if c2 != c {
                return Err(format!("non-deterministic decompile (seed {seed:?})"));
            }
            // Every temporary `vN` referenced in the emitted C must have a
            // declaration; an undeclared temp means a naming/rewrite leak
            // (params, struct fields, strings, or type narrowing lost it).
            let mut declared: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for line in c.lines() {
                let l = line.trim();
                if let Some(rest) = l.strip_suffix(';') {
                    if let Some(name) = rest.rsplit([' ', '*']).next() {
                        if name.starts_with('v')
                            && name[1..].bytes().all(|b| b.is_ascii_digit())
                            && !name[1..].is_empty()
                        {
                            declared.insert(name);
                        }
                    }
                }
            }
            for tok in c.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
                if tok.len() > 1
                    && tok.starts_with('v')
                    && tok[1..].bytes().all(|b| b.is_ascii_digit())
                    && !declared.contains(tok)
                {
                    return Err(format!(
                        "undeclared temp '{tok}' in emitted C (seed {seed:?})"
                    ));
                }
            }
            Ok(c)
        }
        // Expected failure paths (limits, malformed IR) are not violations.
        Err(e) => Err(format!("rejected: {e}")),
    }
}

pub fn reproduce_c(func: &freakre_ir::IrFunction) -> Result<String, String> {
    decompiler::decompile_function(func).map_err(|e| e.to_string())
}

/// Interpret `data` as a random IR function.
///
/// Block count and instruction mix come from the PRNG; branch targets are
/// deliberately allowed to reference blocks beyond `blocks.len()` (malformed
/// CFG) — the decompiler must reject or contain them, not panic.
pub fn build_random_ir(rng: &mut XorShift, data: &[u8]) -> freakre_ir::IrFunction {
    use freakre_ir::{BlockId, IrFunction, IrInst, OpCode, Ty, Value};

    let mut func = IrFunction::new("fuzz", 0x1000);
    let block_count = 1 + rng.below(12) as usize;
    for i in 0..block_count {
        func.add_block(&format!("b{i}"));
    }
    let entry = BlockId(0);
    func.entry_block = entry;

    if data.is_empty() {
        func.push_inst(entry, IrInst::Return { value: None });
        return func;
    }

    for chunk in data.chunks(3) {
        let block = BlockId(rng.below(block_count as u64) as u32);
        let opcode = chunk[0];
        let a = chunk.get(1).copied().unwrap_or(0);
        let b = chunk.get(2).copied().unwrap_or(0);
        let va = u64::from(a);
        let vb = u64::from(b);
        let val = |n: u64| -> Value {
            match n % 6 {
                0 | 1 => Value::var(n as u32 * 7, Ty::Int(32)),
                2 => Value::Const(n as i64 * 0x01020304),
                3 => Value::reg(if n & 1 == 0 { "rax" } else { "rsp" }, Ty::Int(64)),
                4 => Value::StringRef("s\0tr\u{1F600}ing".into()),
                _ => Value::Symbol("sym#name".into()),
            }
        };
        let dangling = |n: u64| BlockId((n % (block_count as u64 + 3)) as u32);
        let inst = match opcode % 12 {
            0 => IrInst::Binary {
                dst: Value::var(a as u32, Ty::Int(32)),
                op: OpCode::Add,
                lhs: val(va),
                rhs: val(vb),
            },
            1 => IrInst::Load {
                dst: Value::var(a as u32, Ty::Int(32)),
                addr: val(vb),
                size: (va % 9) as u32, // includes 0, 3, 5, 7: bogus widths
            },
            2 => IrInst::Store {
                addr: val(va),
                value: val(vb),
                size: (vb % 9) as u32,
            },
            3 => IrInst::Branch {
                // Dangling target on purpose.
                target: dangling(vb),
            },
            4 => IrInst::CBranch {
                cond: val(va),
                target_true: dangling(vb),
                target_false: dangling(va),
            },
            5 => IrInst::Call {
                dst: Some(Value::var(a as u32, Ty::Int(32))),
                target: val(vb),
                args: vec![val(va), val(vb)],
            },
            6 => IrInst::Return {
                value: Some(val(va)),
            },
            7 => IrInst::Phi {
                dst: Value::var(a as u32, Ty::Int(32)),
                incoming: vec![(dangling(vb), val(va)), (dangling(va), val(vb))],
            },
            8 => IrInst::IndirectBranch { target: val(va) },
            9 => IrInst::Syscall {
                number: Some(Value::Const(vb as i64)),
                args: vec![val(va)],
            },
            10 => IrInst::Unary {
                dst: Value::var(a as u32, Ty::Int(32)),
                op: OpCode::Not,
                src: val(vb),
            },
            _ => IrInst::Nop,
        };
        func.push_inst(block, inst);
    }
    func
}
