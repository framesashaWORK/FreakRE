//! Host-function standard library for the sandbox DSL.
//!
//! Pure-computation builtins grouped into four namespaces:
//!
//! | Namespace      | Functions |
//! |----------------|-----------|
//! | String utils   | `len`, `sub`, `find`, `replace`, `upper`, `lower`, `trim`, `split`, `join`, `format_number` |
//! | Data helpers   | `hex_encode`, `hex_decode`, `bytes_to_u32_le`, `u32_to_bytes_le`, `base64_encode`, `base64_decode`, `crc32`, `xor_bytes` |
//! | Pattern helpers| `contains_any`, `count_occurrences`, `extract_between` |
//! | Math/misc      | `min`, `max`, `abs`, `floor`, `ceil`, `tostring` (pretty, tables depth-capped at 3) |
//!
//! Registration/capability contract (mirrors the interpreter's own builtins):
//! every name is listed in [`crate::interpreter::HOST_BUILTINS`], resolved
//! only when no user binding shadows it, gated by
//! [`crate::sandbox::Capabilities::can_call`] and therefore denyable by
//! removing the name from `allowed_functions`. Results pass through
//! `Interpreter::account_result`, which enforces `max_string_len` /
//! `max_table_entries` and charges the memory quota.
//!
//! Byte-oriented helpers treat strings as their UTF-8 byte sequences.
//! Decoding functions (`hex_decode`, `base64_decode`, `xor_bytes`,
//! `u32_to_bytes_le`) must return a string value: decoded bytes that are not
//! valid UTF-8 become U+FFFD replacement characters (lossy), matching how
//! `read_bytes` ingests files. All functions are deterministic and panic-free:
//! bad arguments produce `TypeError`/`RuntimeError` script errors.

use crate::interpreter::{value_to_string, ScriptError, Value};

/// Maximum nesting depth rendered by the pretty `tostring`.
const PRETTY_MAX_DEPTH: usize = 3;

// ── Argument-coercion helpers ─────────────────────────────────────

fn type_error(fn_name: &str, expected: &str, got: &Value) -> ScriptError {
    ScriptError::TypeError(format!(
        "{} expects {}, got {}",
        fn_name,
        expected,
        got.type_name()
    ))
}

fn missing_arg(fn_name: &str, expected: &str) -> ScriptError {
    ScriptError::TypeError(format!("{} expects {}", fn_name, expected))
}

fn arg_str<'a>(
    fn_name: &str,
    args: &'a [Value],
    idx: usize,
    what: &str,
) -> Result<&'a str, ScriptError> {
    match args.get(idx) {
        Some(Value::Str(s)) => Ok(s.as_str()),
        Some(other) => Err(type_error(fn_name, what, other)),
        None => Err(missing_arg(fn_name, what)),
    }
}

fn arg_int(fn_name: &str, args: &[Value], idx: usize, what: &str) -> Result<i64, ScriptError> {
    match args.get(idx) {
        Some(v) => v.as_integer().ok_or_else(|| type_error(fn_name, what, v)),
        None => Err(missing_arg(fn_name, what)),
    }
}

fn arg_num(fn_name: &str, args: &[Value], idx: usize, what: &str) -> Result<f64, ScriptError> {
    match args.get(idx) {
        Some(v) => v.as_number().ok_or_else(|| type_error(fn_name, what, v)),
        None => Err(missing_arg(fn_name, what)),
    }
}

fn arg_table<'a>(
    fn_name: &str,
    args: &'a [Value],
    idx: usize,
    what: &str,
) -> Result<&'a [(Value, Value)], ScriptError> {
    match args.get(idx) {
        Some(Value::Table(t)) => Ok(t),
        Some(other) => Err(type_error(fn_name, what, other)),
        None => Err(missing_arg(fn_name, what)),
    }
}

/// Optional integer argument; a missing slot or explicit `nil` yields
/// `default`. Extra/other types are rejected.
fn opt_int(
    fn_name: &str,
    args: &[Value],
    idx: usize,
    default: i64,
    what: &str,
) -> Result<i64, ScriptError> {
    match args.get(idx) {
        None | Some(Value::Nil) => Ok(default),
        Some(v) => v.as_integer().ok_or_else(|| type_error(fn_name, what, v)),
    }
}

/// Convert a 1-based Lua-style index (negative counts from the end, 0 acts as
/// start/end boundary respectively) to a 0-based position clamped into
/// `0..=len`. Never panics, even for `i64` extremes.
fn normalize_index(raw: i64, len: usize) -> usize {
    let n = len as i128;
    let pos: i128 = if raw > 0 {
        raw as i128 - 1
    } else if raw < 0 {
        n + raw as i128
    } else {
        // 0 behaves like "just past the previous boundary": for starts Lua
        // treats it as 1; for ends it yields an empty range via clamp below.
        0
    };
    pos.clamp(0, n) as usize
}

/// Snap a byte offset forward to the next UTF-8 char boundary.
fn next_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Snap an exclusive end offset backward to the previous char boundary.
fn prev_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

// ── Dispatch ──────────────────────────────────────────────────────

/// Execute a pure stdlib builtin by name. `args` holds already-evaluated
/// script arguments; extra arguments are ignored (Lua-like arity).
pub fn call(name: &str, args: &[Value]) -> Result<Value, ScriptError> {
    match name {
        // ── String utils ──
        "len" => {
            let s = arg_str(name, args, 0, "a string")?;
            Ok(Value::Integer(s.len() as i64))
        }
        "sub" => {
            let s = arg_str(name, args, 0, "a string")?;
            let i = arg_int(name, args, 1, "an integer start index")?;
            let j = opt_int(name, args, 2, -1, "an integer end index")?;
            sub(s, i, j).map(Value::Str)
        }
        "find" => {
            let s = arg_str(name, args, 0, "a string")?;
            let needle = arg_str(name, args, 1, "a string pattern")?;
            let init = opt_int(name, args, 2, 1, "an integer start index")?;
            let from = normalize_index(if init == 0 { 1 } else { init }, s.len());
            match s.get(from..).and_then(|hay| hay.find(needle)) {
                Some(p) => Ok(Value::Integer((p + from + 1) as i64)),
                None => Ok(Value::Nil),
            }
        }
        "replace" => {
            let s = arg_str(name, args, 0, "a string")?;
            let pat = arg_str(name, args, 1, "a string pattern")?;
            let repl = arg_str(name, args, 2, "a string replacement")?;
            let limit_raw = opt_int(name, args, 3, i64::MAX, "an integer limit")?;
            if pat.is_empty() {
                return Err(ScriptError::RuntimeError(
                    "replace: pattern must not be empty".into(),
                ));
            }
            let limit = limit_raw.clamp(0, i64::MAX) as usize;
            let mut out = String::with_capacity(s.len());
            let mut rest = s;
            let mut done = 0usize;
            while done < limit {
                match rest.find(pat) {
                    Some(p) => {
                        out.push_str(&rest[..p]);
                        out.push_str(repl);
                        rest = &rest[p + pat.len()..];
                        done += 1;
                    }
                    None => break,
                }
            }
            out.push_str(rest);
            Ok(Value::Str(out))
        }
        "upper" => {
            let s = arg_str(name, args, 0, "a string")?;
            // ASCII-only for determinism (no locale dependence).
            Ok(Value::Str(s.to_ascii_uppercase()))
        }
        "lower" => {
            let s = arg_str(name, args, 0, "a string")?;
            Ok(Value::Str(s.to_ascii_lowercase()))
        }
        "trim" => {
            let s = arg_str(name, args, 0, "a string")?;
            Ok(Value::Str(s.trim().to_string()))
        }
        "split" => {
            let s = arg_str(name, args, 0, "a string")?;
            let sep = arg_str(name, args, 1, "a string separator")?;
            if sep.is_empty() {
                return Err(ScriptError::RuntimeError(
                    "split: separator must not be empty".into(),
                ));
            }
            let mut entries = Vec::new();
            let mut rest = s;
            let mut idx = 1i64;
            while let Some(p) = rest.find(sep) {
                entries.push((Value::Integer(idx), Value::Str(rest[..p].to_string())));
                rest = &rest[p + sep.len()..];
                idx += 1;
            }
            entries.push((Value::Integer(idx), Value::Str(rest.to_string())));
            Ok(Value::Table(entries))
        }
        "join" => {
            let t = arg_table(name, args, 0, "a table")?;
            let sep = arg_str(name, args, 1, "a string separator")?;
            let mut out = String::new();
            for (k, v) in t {
                // Array part only; nil holes are skipped.
                if matches!(k, Value::Integer(_)) && !matches!(v, Value::Nil) {
                    if !out.is_empty() {
                        out.push_str(sep);
                    }
                    out.push_str(&value_to_string(v));
                }
            }
            Ok(Value::Str(out))
        }
        "format_number" => {
            let n = arg_num(name, args, 0, "a number")?;
            Ok(Value::Str(format_number(n)))
        }

        // ── Data helpers ──
        "hex_encode" => {
            let s = arg_str(name, args, 0, "a string")?;
            let bytes = s.as_bytes();
            let mut out = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                out.push_str(&format!("{:02x}", b));
            }
            Ok(Value::Str(out))
        }
        "hex_decode" => {
            let s = arg_str(name, args, 0, "a string")?;
            if s.len() % 2 != 0 {
                return Err(ScriptError::RuntimeError(
                    "hex_decode: input must contain an even number of hex digits".into(),
                ));
            }
            let bytes = s.as_bytes();
            let mut out = Vec::with_capacity(bytes.len() / 2);
            for pair in bytes.chunks_exact(2) {
                let hi = hex_val(pair[0]).ok_or_else(|| invalid_hex_digit(pair[0]))?;
                let lo = hex_val(pair[1]).ok_or_else(|| invalid_hex_digit(pair[1]))?;
                out.push((hi << 4) | lo);
            }
            // Lossy: non-UTF-8 payloads become U+FFFD (strings are Unicode).
            Ok(Value::Str(String::from_utf8_lossy(&out).into_owned()))
        }
        "bytes_to_u32_le" => {
            let s = arg_str(name, args, 0, "a string")?;
            let off = arg_int(name, args, 1, "an integer offset")?;
            if off < 0 {
                return Err(ScriptError::RuntimeError(
                    "bytes_to_u32_le: offset must not be negative".into(),
                ));
            }
            let off = off as usize;
            if off.checked_add(4).map(|end| end > s.len()).unwrap_or(true) {
                return Err(ScriptError::RuntimeError(format!(
                    "bytes_to_u32_le: offset {} out of range for {}-byte string",
                    off,
                    s.len()
                )));
            }
            let bytes = s.as_bytes();
            Ok(Value::Integer(u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]) as i64))
        }
        "u32_to_bytes_le" => {
            let n = arg_int(name, args, 0, "an integer")?;
            // Lossy for values whose low bytes are not valid UTF-8.
            Ok(Value::Str(
                String::from_utf8_lossy(&(n as u32).to_le_bytes()).into_owned(),
            ))
        }
        "base64_encode" => {
            let s = arg_str(name, args, 0, "a string")?;
            Ok(Value::Str(base64_encode(s.as_bytes())))
        }
        "base64_decode" => {
            let s = arg_str(name, args, 0, "a string")?;
            base64_decode(s).map(Value::Str)
        }
        "crc32" => {
            let s = arg_str(name, args, 0, "a string")?;
            Ok(Value::Integer(crc32(s.as_bytes()) as i64))
        }
        "xor_bytes" => {
            let s = arg_str(name, args, 0, "a string")?;
            let key = arg_str(name, args, 1, "a string key")?;
            if key.is_empty() {
                return Err(ScriptError::RuntimeError(
                    "xor_bytes: key must not be empty".into(),
                ));
            }
            let kb = key.as_bytes();
            let xored: Vec<u8> = s
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ kb[i % kb.len()])
                .collect();
            // Lossy: XOR of arbitrary bytes is usually not valid UTF-8.
            Ok(Value::Str(String::from_utf8_lossy(&xored).into_owned()))
        }

        // ── Pattern helpers ──
        "contains_any" => {
            let s = arg_str(name, args, 0, "a string")?;
            let t = arg_table(name, args, 1, "a table of strings")?;
            let mut item_no = 0usize;
            for (k, v) in t {
                if !matches!(k, Value::Integer(_)) {
                    continue; // keyed entries are ignored, array part only
                }
                item_no += 1;
                match v {
                    Value::Str(item) => {
                        if s.contains(item.as_str()) {
                            return Ok(Value::Bool(true));
                        }
                    }
                    other => {
                        return Err(ScriptError::TypeError(format!(
                            "contains_any: item {} must be a string, got {}",
                            item_no,
                            other.type_name()
                        )));
                    }
                }
            }
            Ok(Value::Bool(false))
        }
        "count_occurrences" => {
            let s = arg_str(name, args, 0, "a string")?;
            let needle = arg_str(name, args, 1, "a string needle")?;
            if needle.is_empty() {
                return Err(ScriptError::RuntimeError(
                    "count_occurrences: needle must not be empty".into(),
                ));
            }
            let mut count = 0usize;
            let mut rest = s;
            while let Some(p) = rest.find(needle) {
                count += 1;
                rest = &rest[p + needle.len()..]; // non-overlapping advance
            }
            Ok(Value::Integer(count as i64))
        }
        "extract_between" => {
            let s = arg_str(name, args, 0, "a string")?;
            let start = arg_str(name, args, 1, "a string start marker")?;
            let end = arg_str(name, args, 2, "a string end marker")?;
            let from = if start.is_empty() {
                0
            } else {
                match s.find(start) {
                    Some(p) => p + start.len(),
                    None => return Ok(Value::Nil),
                }
            };
            let rest = &s[from.min(s.len())..];
            let seg = if end.is_empty() {
                rest
            } else {
                match rest.find(end) {
                    // An end marker glued to the start carries no information
                    // (empty segment); take the whole rest instead of
                    // returning a useless empty string.
                    Some(0) => rest,
                    Some(p) => &rest[..p],
                    None => return Ok(Value::Nil),
                }
            };
            Ok(Value::Str(seg.to_string()))
        }

        // ── Math/misc ──
        "min" => extremum(args, core::cmp::Ordering::Less),
        "max" => extremum(args, core::cmp::Ordering::Greater),
        "abs" => match args.first() {
            Some(Value::Integer(n)) => n
                .checked_abs()
                .map(Value::Integer)
                .ok_or_else(|| ScriptError::RuntimeError("integer overflow".into())),
            Some(Value::Number(f)) => Ok(Value::Number(f.abs())),
            Some(other) => Err(type_error(name, "a number", other)),
            None => Err(missing_arg(name, "a number")),
        },
        "floor" | "ceil" => {
            let f = arg_num(name, args, 0, "a number")?;
            let r = if name == "floor" { f.floor() } else { f.ceil() };
            // Saturating cast keeps this panic-free for extreme magnitudes.
            Ok(Value::Integer(r as i64))
        }
        "tostring" => {
            let v = args.first().cloned().unwrap_or(Value::Nil);
            Ok(Value::Str(pretty_tostring(&v)))
        }
        _ => Err(ScriptError::RuntimeError(format!(
            "unknown builtin '{}'",
            name
        ))),
    }
}

/// Shared min/max fold over numeric arguments. Keeps integer precision when
/// every operand is an integer; NaN operands are a clean runtime error.
fn extremum(args: &[Value], want: core::cmp::Ordering) -> Result<Value, ScriptError> {
    let name = if want == core::cmp::Ordering::Less {
        "min"
    } else {
        "max"
    };
    if args.is_empty() {
        return Err(missing_arg(name, "at least one number"));
    }
    let mut all_int = true;
    let mut ints = Vec::with_capacity(args.len());
    let mut floats = Vec::with_capacity(args.len());
    for v in args {
        match v {
            Value::Integer(n) => {
                ints.push(*n);
                floats.push(*n as f64);
            }
            Value::Number(f) => {
                all_int = false;
                ints.push(0);
                floats.push(*f);
            }
            other => return Err(type_error(name, "numbers", other)),
        }
    }
    if all_int {
        let mut best = ints[0];
        for &n in &ints[1..] {
            if n.cmp(&best) == want {
                best = n;
            }
        }
        return Ok(Value::Integer(best));
    }
    let mut best: f64 = floats[0];
    for &f in &floats[1..] {
        match best.partial_cmp(&f) {
            Some(ord) if ord != want => best = f,
            Some(_) => {}
            None => {
                return Err(ScriptError::RuntimeError(format!(
                    "{}: cannot compare NaN",
                    name
                )))
            }
        }
    }
    Ok(Value::Number(best))
}

fn format_number(n: f64) -> String {
    if n.is_nan() {
        return "nan".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "inf".into() } else { "-inf".into() };
    }
    // Integral values render without a fractional tail; Rust's shortest
    // round-trip float Display handles everything else deterministically.
    if n == n.trunc() && n.abs() < 1e15 {
        return format!("{}", n as i64);
    }
    format!("{}", n)
}

fn sub(s: &str, i: i64, j: i64) -> Result<String, ScriptError> {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let start = normalize_index(i, n);
    // End index is inclusive and 1-based like the start; convert to an
    // exclusive bound. Negative j counts from the end (-1 = last byte).
    let end_exclusive: usize = if j < 0 {
        (n as i128 + j as i128 + 1).clamp(0, n as i128) as usize
    } else if j == 0 {
        0
    } else {
        (j as i128).clamp(0, n as i128) as usize
    };
    if start >= end_exclusive {
        return Ok(String::new());
    }
    let a = next_boundary(s, start);
    let b = prev_boundary(s, end_exclusive);
    if a >= b {
        return Ok(String::new());
    }
    Ok(s[a..b].to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn invalid_hex_digit(b: u8) -> ScriptError {
    let shown = if b.is_ascii_graphic() || b.is_ascii_whitespace() {
        format!("'{}'", b as char)
    } else {
        format!("byte {}", b)
    };
    ScriptError::RuntimeError(format!("hex_decode: invalid hex digit {}", shown))
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let group = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(group >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(group >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(group >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[group as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Result<String, ScriptError> {
    if s.len() % 4 == 1 {
        return Err(ScriptError::RuntimeError(
            "base64_decode: invalid input length".into(),
        ));
    }
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 4 * 3);
    let mut padding_seen = false;
    for &b in s.as_bytes() {
        if b == b'=' {
            padding_seen = true;
            continue;
        }
        if padding_seen {
            return Err(ScriptError::RuntimeError(
                "base64_decode: data after padding character".into(),
            ));
        }
        let v = b64_val(b).ok_or_else(|| {
            ScriptError::RuntimeError(format!(
                "base64_decode: invalid character '{}'",
                printable_byte(b)
            ))
        })?;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn b64_val(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a') as u32 + 26),
        b'0'..=b'9' => Some((b - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn printable_byte(b: u8) -> String {
    if b.is_ascii_graphic() {
        format!("'{}'", b as char)
    } else {
        format!("byte {}", b)
    }
}

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    })
}

/// IEEE CRC-32 (zlib-compatible).
pub fn crc32(bytes: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ── Pretty tostring ───────────────────────────────────────────────

/// Render any value readably: strings quoted and escaped, tables as
/// `{elem, key = value, [key] = value}` with nesting capped at
/// [`PRETTY_MAX_DEPTH`] levels (deeper tables render as `{...}`).
pub fn pretty_tostring(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, v, 1);
    out
}

fn write_pretty(out: &mut String, v: &Value, depth: usize) {
    match v {
        Value::Table(entries) => {
            if depth > PRETTY_MAX_DEPTH {
                out.push_str("{...}");
                return;
            }
            // A table at the last full level that itself contains tables
            // would push real content past the cap — collapse it instead.
            // (Keeps `{a = {b = {c = 1}}}` fully rendered while
            // `{a = {b = {c = {}}}}` becomes `{a = {b = {...}}}`.)
            if depth == PRETTY_MAX_DEPTH
                && entries
                    .iter()
                    .any(|(_, val)| matches!(val, Value::Table(_)))
            {
                out.push_str("{...}");
                return;
            }
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                match k {
                    // Consecutive array keys render bare: {10, 20}
                    Value::Integer(n) if *n == i as i64 + 1 => {}
                    Value::Str(ks) if is_identifier_key(ks) => {
                        out.push_str(ks);
                        out.push_str(" = ");
                    }
                    other => {
                        out.push('[');
                        write_pretty(out, other, depth + 1);
                        out.push_str("] = ");
                    }
                }
                write_pretty(out, val, depth + 1);
            }
            out.push('}');
        }
        Value::Str(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        other => out.push_str(&format!("{}", other)),
    }
}

fn is_identifier_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use crate::interpreter::Value;
    use crate::sandbox::{Capabilities, SandboxConfig};
    use crate::{run, ScriptError};

    fn r(src: &str) -> Value {
        run(src, &SandboxConfig::default(), &Capabilities::default())
            .unwrap_or_else(|e| panic!("script failed: {} -- {}", src, e))
    }

    fn rs(src: &str) -> String {
        match r(src) {
            Value::Str(s) => s,
            other => panic!("expected string from {:?}, got {:?}", src, other),
        }
    }

    fn ri(src: &str) -> i64 {
        r(src)
            .as_integer()
            .unwrap_or_else(|| panic!("expected integer from {:?}", src))
    }

    fn err(src: &str) -> ScriptError {
        run(src, &SandboxConfig::default(), &Capabilities::default())
            .expect_err("expected script error")
    }

    fn elem(src: &str) -> Value {
        // src must return a table; fetch its element 1..n via wrapper below
        r(src)
    }

    // ── Namespace: string utils ───────────────────────────────────

    #[test]
    fn test_len_and_sub() {
        assert_eq!(ri("return len('héllo')"), 6); // é is 2 bytes
        assert_eq!(rs("return sub('hello world', 7)"), "world");
        assert_eq!(rs("return sub('hello', 2, 3)"), "el");
        assert_eq!(rs("return sub('hello', -3)"), "llo");
        assert_eq!(rs("return sub('hello', -3, -1)"), "llo");
        assert_eq!(rs("return sub('привет', 1, 2)"), "п"); // byte snap to boundary
        assert_eq!(rs("return sub('abc', 99)"), "");
        assert_eq!(rs("return sub('abc', 2, 1)"), "");
        assert_eq!(rs("return sub('abc', 1, 0)"), "");
        assert_eq!(ri("return len(sub('', 1, 1))"), 0);
    }

    #[test]
    fn test_find_replace_case_trim() {
        assert_eq!(ri("return find('hello world', 'world')"), 7);
        assert_eq!(ri("return find('aaa', 'aa', 2)"), 2);
        assert!(matches!(r("return find('hello', 'zz')"), Value::Nil));
        assert_eq!(rs("return replace('a.b.a', '.', '-')"), "a-b-a");
        assert_eq!(rs("return replace('a.b.a', '.', '-', 1)"), "a-b.a");
        assert_eq!(rs("return replace('aaa', 'b', 'x')"), "aaa"); // no-op when absent
        assert_eq!(rs("return upper('aBc1')"), "ABC1");
        assert_eq!(rs("return lower('AbC1')"), "abc1");
        assert_eq!(rs("return trim('  hi \\t ')"), "hi");
    }

    #[test]
    fn test_split_join_format_number() {
        let parts = match elem("return split('a,,b', ',')") {
            Value::Table(t) => t,
            other => panic!("expected table, got {:?}", other),
        };
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[0].1, Value::Str(s) if s == "a"));
        assert!(matches!(&parts[1].1, Value::Str(s) if s.is_empty()));
        assert!(matches!(&parts[2].1, Value::Str(s) if s == "b"));
        assert!(matches!(
            elem("return split('nosuchsep', ',')"),
            Value::Table(ref t) if t.len() == 1 && matches!(&t[0].1, Value::Str(s) if s == "nosuchsep")
        ));
        assert_eq!(rs("return join({'a', 'b', 'c'}, '-')"), "a-b-c");
        assert_eq!(rs("return join({}, ',')"), "");
        // nil holes are skipped by design
        assert_eq!(rs("return join({'a', nil, 'c'}, '')"), "ac");
        assert_eq!(rs("return format_number(42)"), "42");
        assert_eq!(rs("return format_number(3.14)"), "3.14");
        assert_eq!(rs("return format_number(-0.5)"), "-0.5");
        assert_eq!(rs("return format_number(1000000)"), "1000000");
    }

    #[test]
    fn test_string_utils_malformed_args() {
        assert!(matches!(err("return len()"), ScriptError::TypeError(_)));
        assert!(
            matches!(err("return len(5)"), ScriptError::TypeError(ref m) if m.contains("got integer"))
        );
        assert!(matches!(
            err("return sub('abc')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return sub(1, 2)"), ScriptError::TypeError(_)));
        assert!(matches!(
            err("return find('abc', 2)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return find()"), ScriptError::TypeError(_)));
        assert!(matches!(
            err("return replace('a', '', 'x')"),
            ScriptError::RuntimeError(ref m) if m.contains("pattern must not be empty")
        ));
        assert!(matches!(
            err("return replace('a', '.')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return upper(1)"), ScriptError::TypeError(_)));
        assert!(matches!(
            err("return lower(nil)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return trim(true)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return split('a,b', '')"),
            ScriptError::RuntimeError(ref m) if m.contains("separator")
        ));
        assert!(matches!(
            err("return split('a', 3)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return join('ab', '-')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return join({'a'})"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return format_number('x')"),
            ScriptError::TypeError(_)
        ));
        // Malformed args never panic even at index extremes.
        assert!(run(
            "return sub('abc', -9999999999999999999999, 1)",
            &SandboxConfig::default(),
            &Capabilities::default()
        )
        .is_err()); // lex error, not panic
    }

    // ── Namespace: data helpers ───────────────────────────────────

    #[test]
    fn test_hex_roundtrip() {
        assert_eq!(rs("return hex_encode('ABC')"), "414243");
        assert_eq!(rs("return hex_encode('')"), "");
        assert_eq!(rs("return hex_decode('414243')"), "ABC");
        assert_eq!(
            rs("return hex_decode('414243') == hex_decode(hex_encode('ABC')) and 'ok' or 'bad'"),
            "ok"
        );
    }

    #[test]
    fn test_base64_vectors() {
        assert_eq!(rs("return base64_encode('hello')"), "aGVsbG8=");
        assert_eq!(rs("return base64_decode('aGVsbG8=')"), "hello");
        assert_eq!(rs("return base64_encode('ABC')"), "QUJD");
        assert_eq!(rs("return base64_decode('QUJD')"), "ABC");
        // Tolerates unpadded input.
        assert_eq!(rs("return base64_decode('QUI=')"), "AB");
        assert_eq!(rs("return base64_decode('QUI')"), "AB");
        assert_eq!(rs("return base64_encode('')"), "");
    }

    #[test]
    fn test_crc32_known_value() {
        // zlib-compatible IEEE CRC-32 of "hello"
        assert_eq!(ri("return crc32('hello')"), 907060870);
        assert_eq!(ri("return crc32('')"), 0);
    }

    #[test]
    fn test_xor_and_u32_words() {
        // 0x20 toggles ASCII case; XOR is self-inverse for clean payloads.
        assert_eq!(rs("return xor_bytes('ABC', ' ')"), "abc");
        assert_eq!(
            rs("return xor_bytes(xor_bytes('payload!', 'key'), 'key')"),
            "payload!"
        );
        // 16909060 == 0x01020304 -> bytes 04 03 02 01 (valid UTF-8)
        assert_eq!(
            ri("return bytes_to_u32_le(u32_to_bytes_le(16909060), 0)"),
            16909060
        );
        assert_eq!(
            ri("return bytes_to_u32_le('AAAA' .. u32_to_bytes_le(16909060), 4)"),
            16909060
        );
    }

    #[test]
    fn test_data_helpers_malformed_args() {
        assert!(matches!(
            err("return hex_decode('abc')"),
            ScriptError::RuntimeError(ref m) if m.contains("even number")
        ));
        assert!(matches!(
            err("return hex_decode('zz')"),
            ScriptError::RuntimeError(ref m) if m.contains("invalid hex digit")
        ));
        assert!(matches!(
            err("return hex_decode(5)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return hex_encode(1)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return bytes_to_u32_le('ab', 0)"),
            ScriptError::RuntimeError(ref m) if m.contains("out of range")
        ));
        assert!(matches!(
            err("return bytes_to_u32_le(u32_to_bytes_le(0), -1)"),
            ScriptError::RuntimeError(ref m) if m.contains("negative")
        ));
        assert!(matches!(
            err("return bytes_to_u32_le('abcd')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return u32_to_bytes_le('x')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return u32_to_bytes_le()"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return xor_bytes('a', '')"),
            ScriptError::RuntimeError(ref m) if m.contains("key must not be empty")
        ));
        assert!(matches!(
            err("return xor_bytes(1, 'k')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return base64_decode('!!!!')"),
            ScriptError::RuntimeError(ref m) if m.contains("invalid character")
        ));
        assert!(matches!(
            err("return base64_decode('A')"),
            ScriptError::RuntimeError(ref m) if m.contains("invalid input length")
        ));
        assert!(matches!(
            err("return base64_decode('AB=A')"),
            ScriptError::RuntimeError(ref m) if m.contains("after padding")
        ));
        assert!(matches!(
            err("return base64_decode(7)"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return crc32({})"), ScriptError::TypeError(_)));
    }

    #[test]
    fn test_lossy_decoding_is_documented_behavior() {
        // 0xFF / 0xFFFF are not valid UTF-8: they surface as U+FFFD, exactly
        // like read_bytes ingestion. No panics, deterministic output.
        assert_eq!(rs("return hex_decode('ff')"), "\u{FFFD}");
        assert_eq!(rs("return hex_decode('ffff')"), "\u{FFFD}\u{FFFD}");
    }

    // ── Namespace: pattern helpers ────────────────────────────────

    #[test]
    fn test_contains_any() {
        assert_eq!(
            ri("return contains_any('hello world', {'xyz', 'wor'}) and 1 or 0"),
            1
        );
        assert_eq!(ri("return contains_any('hello', {'xyz'}) and 1 or 0"), 0);
        assert_eq!(ri("return contains_any('hello', {}) and 1 or 0"), 0);
        // Keyed entries are ignored; only the array part participates.
        assert_eq!(ri("return contains_any('ab', {x = 'a'}) and 1 or 0"), 0);
    }

    #[test]
    fn test_count_and_extract() {
        assert_eq!(ri("return count_occurrences('aaaa', 'aa')"), 2); // non-overlapping
        assert_eq!(ri("return count_occurrences('ababab', 'aba')"), 1);
        assert_eq!(ri("return count_occurrences('xyz', 'q')"), 0);
        assert_eq!(
            rs("return extract_between('<a>content<b>', '<a>', '<b>')"),
            "content"
        );
        assert!(matches!(
            r("return extract_between('abc', 'x', 'y')"),
            Value::Nil
        ));
        assert!(matches!(
            r("return extract_between('abc', 'a', 'z')"),
            Value::Nil
        ));
        assert_eq!(rs("return extract_between('a=1;', '=', ';')"), "1");
    }

    #[test]
    fn test_pattern_helpers_malformed_args() {
        assert!(matches!(
            err("return contains_any('s', {1})"),
            ScriptError::TypeError(ref m) if m.contains("item 1 must be a string")
        ));
        assert!(matches!(
            err("return contains_any('s', 'notatable')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return contains_any(1, {})"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return count_occurrences('abc', '')"),
            ScriptError::RuntimeError(ref m) if m.contains("needle must not be empty")
        ));
        assert!(matches!(
            err("return count_occurrences('abc')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return extract_between(1, 'a', 'b')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return extract_between('abc', 2, 'b')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(
            err("return extract_between('abc', 'a')"),
            ScriptError::TypeError(_)
        ));
    }

    // ── Namespace: math/misc ──────────────────────────────────────

    #[test]
    fn test_math_extremum_abs_rounding() {
        assert_eq!(ri("return min(3, 1, 2)"), 1);
        assert_eq!(ri("return max(3, 1, 2)"), 3);
        assert_eq!(r("return max(1, 2.5)").as_number(), Some(2.5));
        assert_eq!(r("return min(-1.5, -2)").as_number(), Some(-2.0));
        assert_eq!(ri("return min(42)"), 42); // single operand
        assert_eq!(ri("return abs(-5)"), 5);
        assert_eq!(ri("return abs(5)"), 5);
        assert_eq!(r("return abs(-2.25)").as_number(), Some(2.25));
        assert_eq!(ri("return floor(2.7)"), 2);
        assert_eq!(ri("return ceil(2.1)"), 3);
        assert_eq!(ri("return floor(4)"), 4);
        assert_eq!(ri("return floor(-2.5)"), -3);
    }

    #[test]
    fn test_math_malformed_args() {
        assert!(
            matches!(err("return min()"), ScriptError::TypeError(ref m) if m.contains("at least one"))
        );
        assert!(matches!(
            err("return max(1, 'x')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return abs('x')"), ScriptError::TypeError(_)));
        assert!(matches!(err("return abs()"), ScriptError::TypeError(_)));
        assert!(matches!(
            err("return floor('x')"),
            ScriptError::TypeError(_)
        ));
        assert!(matches!(err("return ceil({})"), ScriptError::TypeError(_)));
        assert!(matches!(
            err("local m = -1 * 9223372036854775807 - 1\nreturn abs(m)"),
            ScriptError::RuntimeError(ref m) if m.contains("overflow")
        )); // abs(i64::MIN) errors instead of wrapping
        assert!(matches!(
            err("return min(1, (-8) ^ 0.5)"),
            ScriptError::RuntimeError(ref m) if m.contains("NaN")
        ));
    }

    #[test]
    fn test_pretty_tostring() {
        assert_eq!(rs("return tostring(42)"), "42");
        assert_eq!(rs("return tostring(1.5)"), "1.5");
        assert_eq!(rs("return tostring(true)"), "true");
        assert_eq!(rs("return tostring()"), "nil");
        assert_eq!(rs("return tostring('hi')"), "\"hi\"");
        assert_eq!(rs("return tostring('line1\\nline2')"), "\"line1\\nline2\"");
        assert_eq!(rs("return tostring({})"), "{}");
        assert_eq!(rs("return tostring({1, 2})"), "{1, 2}");
        assert_eq!(rs("return tostring({10, 20, x = 1})"), "{10, 20, x = 1}");
        assert_eq!(
            rs("return tostring({['my-key'] = 1})"),
            "{[\"my-key\"] = 1}"
        );
        assert_eq!(rs("return tostring({[true] = 1})"), "{[true] = 1}");
        assert_eq!(
            rs("return tostring({version = 2, tags = {'re', 'auto'}})"),
            "{version = 2, tags = {\"re\", \"auto\"}}"
        );
        // Depth cap: tables nested deeper than 3 levels render as {...}.
        assert_eq!(
            rs("return tostring({a = {b = {c = 1}}})"),
            "{a = {b = {c = 1}}}"
        );
        assert_eq!(
            rs("return tostring({a = {b = {c = {}}}})"),
            "{a = {b = {...}}}"
        );
        assert_eq!(rs("return tostring({f = print})",), "{f = <function>}");
    }

    // ── Capabilities ──────────────────────────────────────────────

    #[test]
    fn test_default_caps_allow_stdlib() {
        // Implicitly covered by every happy-path test above; this one pins
        // one representative per namespace explicitly.
        assert_eq!(ri("return len('ab')"), 2);
        assert_eq!(ri("return crc32('')"), 0);
        assert_eq!(ri("return count_occurrences('aa', 'a')"), 2);
        assert_eq!(ri("return max(1, 2)"), 2);
        assert_eq!(rs("return tostring({1})"), "{1}");
    }

    #[test]
    fn test_capability_denied_per_namespace() {
        let mut caps = Capabilities::default();
        caps.allowed_functions.clear();
        let cfg = SandboxConfig::default();
        for src in [
            "return len('ab')",
            "return sub('ab', 1)",
            "return hex_encode('ab')",
            "return crc32('ab')",
            "return xor_bytes('a', 'k')",
            "return contains_any('ab', {'a'})",
            "return count_occurrences('ab', 'a')",
            "return extract_between('abc', 'a', 'c')",
            "return min(1, 2)",
            "return abs(-1)",
            "return tostring({})",
        ] {
            match run(src, &cfg, &caps) {
                Err(ScriptError::CapabilityDenied(_)) => {}
                other => panic!(
                    "expected CapabilityDenied for {:?}, got {:?}",
                    src,
                    other.map(|v| v.type_name())
                ),
            }
        }
        // File I/O stays gated by its own flag, independent of the whitelist.
        assert!(matches!(
            run("return read_bytes('x')", &cfg, &caps),
            Err(ScriptError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn test_selective_denial_only_blocks_named_function() {
        let mut caps = Capabilities::default();
        caps.allowed_functions.remove("len");
        let cfg = SandboxConfig::default();
        assert!(matches!(
            run("return len('ab')", &cfg, &caps),
            Err(ScriptError::CapabilityDenied(name)) if name == "len"
        ));
        // Sibling builtins keep working.
        assert!(matches!(
            run("return upper('ab')", &cfg, &caps),
            Ok(Value::Str(ref s)) if s == "AB"
        ));
        // User functions with the same name are unaffected (env lookup first).
        assert_eq!(
            run(
                "function len(s) return 99 end\nreturn len('ab')",
                &cfg,
                &caps
            )
            .unwrap()
            .as_integer(),
            Some(99)
        );
    }

    // ── Sandbox limits & integration ─────────────────────────────

    #[test]
    fn test_result_respects_string_length_limit() {
        let cfg = SandboxConfig {
            max_string_len: 8,
            ..Default::default()
        };
        assert!(matches!(
            run(
                "return join({'aaaa', 'bbbb'}, '-')",
                &cfg,
                &Capabilities::default()
            ),
            Err(ScriptError::StringLengthLimit)
        ));
        assert!(matches!(
            run(
                "return hex_encode('0123456789abcdef')",
                &cfg,
                &Capabilities::default()
            ),
            Err(ScriptError::StringLengthLimit)
        ));
    }

    #[test]
    fn test_result_respects_memory_limit() {
        let cfg = SandboxConfig {
            max_memory: 16,
            ..Default::default()
        };
        // Output (32 bytes) exceeds the quota: charged through account_result.
        assert!(matches!(
            run(
                "return hex_encode('0123456789abcdef')",
                &cfg,
                &Capabilities::default()
            ),
            Err(ScriptError::MemoryLimit)
        ));
    }

    #[test]
    fn test_result_respects_table_limit() {
        let cfg = SandboxConfig {
            max_table_entries: 2,
            ..Default::default()
        };
        assert!(matches!(
            run(
                "return split('a,b,c,d', ',')",
                &cfg,
                &Capabilities::default()
            ),
            Err(ScriptError::TableSizeLimit)
        ));
    }

    #[test]
    fn test_user_binding_shadows_builtin() {
        assert_eq!(
            rs("function sub(s, a, b) return 'X' end\nreturn sub('a', 1, 2)"),
            "X"
        );
        assert_eq!(ri("local len = 5\nreturn len"), 5);
    }

    #[test]
    fn test_namespaces_compose_in_script() {
        // Example-shaped end-to-end script over all four namespaces.
        let src = "\
local blob = 'MZ....PE...payload'
if sub(blob, 1, 2) ~= upper('mz') then return 'header' end
local body = extract_between(blob, 'PE', '...')
if not contains_any(body, {'payload'}) then return 'body' end
local hits = count_occurrences(blob, '..')
local words = {}
for i = 0, 3 do
  words[i + 1] = format_number(bytes_to_u32_le('AAAA' .. u32_to_bytes_le(hits + i), 4))
end
return join(words, '|') .. '|' .. tostring({hits = hits, ok = true})";
        let v = r(src);
        match v {
            Value::Str(ref s) => {
                assert_eq!(s, "3|4|5|6|{hits = 3, ok = true}");
            }
            other => panic!("expected string, got {:?}", other),
        }
    }
}
