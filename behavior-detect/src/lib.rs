//! behavior-detect: graph-based behavioral backdoor detection.
//! Detects TTPs as CFG/DFG patterns over freakre-ir lifted functions:
//! reverse shell dataflow, C2 beacon loops, injector primitive chains.
//! Complements signature layers in backdoor-analyzer with structural
//! invariants that survive obfuscation.
