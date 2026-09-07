//! Bounded intra-procedural taint analysis for IR.
//!
//! The analysis is intentionally conservative: taint flows through explicit
//! operands and definitions, but never crosses an unknown call implicitly.
//! This makes results useful for explainability without pretending to be a
//! whole-program proof.

use freakre_ir::{IrFunction, IrInst, Value};
use std::collections::{HashMap, HashSet};

pub const DEFAULT_MAX_INSTRUCTIONS: usize = 100_000;
pub const DEFAULT_MAX_STEPS: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSource {
    pub label: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSink {
    pub target: String,
    pub instruction: usize,
    pub tainted_args: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintReport {
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct TaintConfig {
    pub source_symbols: Vec<String>,
    pub sink_symbols: Vec<String>,
    pub max_instructions: usize,
    pub max_steps: usize,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            source_symbols: vec!["recv".into(), "ReadFile".into(), "URLDownloadToFile".into()],
            sink_symbols: vec!["system".into(), "WinExec".into(), "CreateProcess".into(), "execve".into()],
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            max_steps: DEFAULT_MAX_STEPS,
        }
    }
}

fn symbol_name(value: &Value) -> Option<&str> {
    match value {
        Value::Symbol(name) => Some(name.as_str()),
        _ => None,
    }
}

fn matches_symbol(value: &Value, names: &[String]) -> bool {
    symbol_name(value).is_some_and(|name| {
        names.iter().any(|needle| name.eq_ignore_ascii_case(needle))
    })
}

fn tainted(value: &Value, tainted: &HashSet<Value>) -> bool {
    tainted.contains(value)
}

/// Analyze one IR function with explicit budgets.
pub fn analyze_taint(func: &IrFunction, config: &TaintConfig) -> TaintReport {
    let mut report = TaintReport::default();
    let mut tainted_values = HashSet::new();
    let mut aliases: HashMap<Value, Value> = HashMap::new();
    let mut steps = 0usize;
    let mut instruction_index = 0usize;

    for block in &func.blocks {
        for inst in &block.insts {
            instruction_index += 1;
            if instruction_index > config.max_instructions || steps >= config.max_steps {
                report.truncated = true;
                return report;
            }
            steps += 1;

            let inputs = inst.sources();
            let input_tainted = inputs.iter().any(|value| {
                tainted(value, &tainted_values)
                    || aliases.get(value).is_some_and(|aliased| tainted(aliased, &tainted_values))
            });

            if let IrInst::Call { target, args, .. } = inst {
                if matches_symbol(target, &config.source_symbols) {
                    if let Some(dst) = inst.dst().cloned() {
                        tainted_values.insert(dst.clone());
                        report.sources.push(TaintSource {
                            label: symbol_name(target).unwrap_or("source").to_string(),
                            value: dst,
                        });
                    }
                }
                if matches_symbol(target, &config.sink_symbols) {
                    let tainted_args = args.iter().enumerate()
                        .filter(|(_, arg)| tainted(arg, &tainted_values))
                        .map(|(index, _)| index)
                        .collect::<Vec<_>>();
                    if !tainted_args.is_empty() {
                        report.sinks.push(TaintSink {
                            target: symbol_name(target).unwrap_or("sink").to_string(),
                            instruction: instruction_index,
                            tainted_args,
                        });
                    }
                }
            }

            if let Some(dst) = inst.dst().cloned() {
                if input_tainted {
                    tainted_values.insert(dst.clone());
                }
                if inputs.len() == 1 {
                    aliases.insert(dst, inputs[0].clone());
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{IrFunction, Ty};

    #[test]
    fn source_to_sink_is_reported() {
        let mut function = IrFunction::new("taint", 0x1000);
        let block = &mut function.blocks[0];
        block.insts.push(IrInst::Call {
            dst: Some(Value::var(1, Ty::i64())),
            target: Value::Symbol("recv".into()),
            args: vec![],
        });
        block.insts.push(IrInst::Call {
            dst: None,
            target: Value::Symbol("system".into()),
            args: vec![Value::var(1, Ty::i64())],
        });
        let report = analyze_taint(&function, &TaintConfig::default());
        assert_eq!(report.sources.len(), 1);
        assert_eq!(report.sinks.len(), 1);
        assert!(!report.truncated);
    }
}
