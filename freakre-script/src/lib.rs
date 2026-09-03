//! freakre-script: Sandboxed Lua-like DSL interpreter.
//! - Capability-based security (whitelist API)
//! - Instruction counter + memory quota
//! - Deterministic (no RNG, no time, no env)
//! - No eval, no dynamic dispatch, no closures
//!
//! ## Host-function stdlib
//!
//! Pure builtins are grouped into four namespaces. They follow the same
//! registration/capability contract as the interpreter's own builtins: each
//! name lives in `interpreter::HOST_BUILTINS`, is callable by bare name only
//! when no user binding shadows it, and is gated by
//! `Capabilities::can_call` (i.e. it must be listed in
//! `Capabilities::allowed_functions`, which the default set does). Removing a
//! name from the whitelist makes calls fail with `CapabilityDenied`. File I/O
//! (`read_bytes`/`write_bytes`) stays gated behind `allow_file_io`.
//!
//! | Function | Signature | Description |
//! |----------|-----------|-------------|
//! | `len` | `len(s)` | Byte length of `s` |
//! | `sub` | `sub(s, i[, j])` | 1-based byte-range substring; negative indices count from end; default `j = -1` |
//! | `find` | `find(s, needle[, init])` | 1-based byte index of first `needle` at/after `init`, or `nil` |
//! | `replace` | `replace(s, pat, repl[, n])` | Replace up to `n` occurrences (default all), non-overlapping |
//! | `upper` / `lower` | `(s)` | ASCII case conversion (deterministic, locale-free) |
//! | `trim` | `trim(s)` | Strip surrounding whitespace |
//! | `split` | `split(s, sep)` | Table of parts (array keys `1..n`); errors on empty separator |
//! | `join` | `join(t, sep)` | Concatenate array-part elements (nil holes skipped) with `sep` |
//! | `format_number` | `format_number(n)` | Canonical numeric rendering (`42`, `3.14`, `nan`, `inf`) |
//! | `hex_encode` / `hex_decode` | `(s)` | Lowercase hex round-trip; decode rejects odd length/bad digits |
//! | `bytes_to_u32_le` | `(s, off)` | Little-endian u32 at byte offset; range-checked |
//! | `u32_to_bytes_le` | `(n)` | 4-byte little-endian encoding as a string |
//! | `base64_encode` / `base64_decode` | `(s)` | Local standard-alphabet base64 (padded); decoder rejects invalid chars |
//! | `crc32` | `crc32(s)` | IEEE CRC-32 as non-negative integer |
//! | `xor_bytes` | `xor_bytes(s, key)` | Repeating-key XOR over UTF-8 bytes; empty key is an error |
//! | `contains_any` | `contains_any(s, t)` | True if any string in array-part of `t` occurs in `s` |
//! | `count_occurrences` | `(s, needle)` | Non-overlapping substring count |
//! | `extract_between` | `(s, start, end)` | Text after `start` up to next `end` (`nil` when markers are missing; an `end` glued to `start` yields the whole rest) |
//! | `min` / `max` | `(...)` | Variadic extremum; integer-precise for all-integer input; NaN is an error |
//! | `abs` | `abs(n)` | Absolute value (integer overflow is an error, not a wrap) |
//! | `floor` / `ceil` | `(n)` | Round to integer |
//! | `tostring` | `tostring(v)` | Pretty rendering; tables `{key = value, ...}` nested at most 3 levels, deeper shown as `{...}` |
//!
//! Byte-oriented decoders must return string values: decoded bytes that are
//! not valid UTF-8 become U+FFFD replacement characters (same lossy policy as
//! `read_bytes`). Every builtin enforces sandbox limits on its result
//! (`max_string_len`, `max_table_entries`) and charges the memory quota.
//!
//! Example script:
//!
//! ```lua
//! -- Pure stdlib below runs with default capabilities.
//! local blob = 'MZ....PE..payload'
//!
//! print(sub(blob, 1, 2))                    -- MZ
//! print(hex_encode('ABC'))                  -- 414243
//! print(base64_encode('ABC'))               -- QUJD
//! print(crc32(blob))
//!
//! local parts = split('init,text,data', ',')
//! print(join(parts, '|'))                   -- init|text|data
//!
//! local body = extract_between(blob, 'PE', '...')
//! if contains_any(body, {'payload'}) then
//!   print(count_occurrences(blob, '..'))
//! end
//!
//! -- Binary inspection via u32 words
//! local word = bytes_to_u32_le(u32_to_bytes_le(16909060), 0)
//! print(format_number(word))                -- 16909060
//!
//! -- Pretty tables, depth-capped at 3 levels
//! print(tostring({version = 2, tags = {'re', 'auto'}}))
//! ```

pub mod lexer;
pub mod ast;
pub mod parser;
pub mod interpreter;
pub mod stdlib;
pub mod sandbox;

pub use interpreter::{Interpreter, ScriptError};
pub use sandbox::{Capabilities, SandboxConfig};
pub use ast::Stmt;

/// Run a script with the given config and capabilities.
pub fn run(
    source: &str,
    config: &SandboxConfig,
    caps: &Capabilities,
) -> Result<interpreter::Value, ScriptError> {
    let tokens = lexer::tokenize(source)?;
    let stmts = parser::parse(&tokens)?;
    let mut interp = Interpreter::new(config.clone(), caps.clone());
    interp.execute(&stmts)
}
