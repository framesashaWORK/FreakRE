//! AST types for YARA-lite rules.

/// A single parsed rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub strings: Vec<StringDef>,
    pub condition: Condition,
    /// `private rule` — matches but is not reported in scan output.
    pub is_private: bool,
    /// `global rule` — must match for ANY other rule to match.
    pub is_global: bool,
}

/// A string definition inside a rule.
#[derive(Debug, Clone)]
pub struct StringDef {
    pub identifier: String, // e.g. "$s1", "$hex"
    pub pattern: Pattern,
    pub modifiers: Modifiers,
}

/// Pattern kind.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Plain text or regex string: $s = "text" [nocase] [wide] [ascii]
    Text(TextPattern),
    /// Hex pattern with wildcards: { 4D 5A ?? 90 }
    Hex(HexPattern),
}

#[derive(Debug, Clone)]
pub struct TextPattern {
    /// Pattern bytes exactly as they must appear in the scanned data.
    /// Quoted strings support `\xNN` escapes producing arbitrary raw bytes
    /// (including >= 0x80), which a `String` could not represent losslessly.
    pub value: Vec<u8>,
    pub is_regex: bool,
}

#[derive(Debug, Clone)]
pub struct HexPattern {
    /// Tokens: literal bytes or wildcards.
    pub tokens: Vec<HexToken>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HexToken {
    Literal(u8),
    /// Single-byte wildcard `??`
    Wildcard,
    /// Nibble wildcard: `?A` or `A?` — stored as (mask, value)
    /// mask bits = 1 means "don't care", value bits are the fixed part.
    NibbleWildcard {
        mask: u8,
        value: u8,
    },
    /// Alternation: `(4D | 5A | ??)` — matches any of the alternatives.
    Alternation(Vec<HexToken>),
    /// Jump: `[N-M]` — skip N to M bytes between hex tokens.
    Jump {
        min: usize,
        max: usize,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Modifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    /// XOR modifier: match pattern XORed with any single-byte key (0-255).
    pub xor: bool,
    /// Base64 modifier: match the pattern's base64 encodings (all three
    /// alignments) instead of the raw bytes.
    pub base64: bool,
    /// `at` modifier: pattern must match at this exact offset.
    pub at: Option<usize>,
    /// `in` modifier: pattern must match within this range.
    pub range: Option<(usize, usize)>,
}

/// Condition expression tree.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Boolean AND
    And(Box<Condition>, Box<Condition>),
    /// Boolean OR
    Or(Box<Condition>, Box<Condition>),
    /// Boolean NOT
    Not(Box<Condition>),
    /// `true` / `false` literals
    Bool(bool),
    /// Reference to a string identifier: `$s1`
    StringMatch(String),
    /// Count of matches: `#s1`
    StringCount(String),
    /// `all of them`, `any of them`, `N of them`
    OfThem(OfKind),
    /// `all of ($a, $b)`
    OfSet(OfKind, Vec<String>),
    /// `$s at <offset>`
    At(String, usize),
    /// `$s in (<start>..<end>)`
    In(String, usize, usize),
    /// `$s at <variable_offset>` — offset from int expression
    AtExpr(String, Box<IntExpr>),
    /// `$s in (<start_expr>..<end_expr>)` — range from int expressions
    InExpr(String, Box<IntExpr>, Box<IntExpr>),
    /// `$s contains "substring"`
    Contains(String, String),
    /// `$s istype "string"` or `$s istype "integer"`
    IsType(String, String),
    /// `$s == "exact match"` — exact equality
    Eq(String, String),
    /// `any of ($a, $b) at <offset>` — not supported yet, placeholder
    /// Integer comparison: `#s > 3`, `filesize < 1024`, `uint16(0) == 0x5A4D`
    IntComp(IntCompOp, Box<IntExpr>, Box<IntExpr>),
    /// `pe.number_of_sections > 5` — PE module query
    PeNumberSections(IntCompOp, Box<IntExpr>),
    /// `pe.imports("kernel32.dll")`
    PeImports(String),
    /// `pe.imports("kernel32.dll", "VirtualAlloc")` — dll AND function
    PeImportsFunc(String, String),
    /// `pe.sections($sec_name)` — section exists
    PeSections(String),
    /// `$s matches /regex/` — at least one match of $s satisfies the regex
    Matches(String, String),
    /// `for any of ($a*) : ( $ at 0 )` — quantified iteration over strings.
    /// `$` inside the body refers to the current string.
    ForOf(OfKind, ForSet, Box<Condition>),
    /// `for any i in (1..#s) : ( @s[i] < 100 )` — quantified integer range.
    ForIntRange(OfKind, String, Box<IntExpr>, Box<IntExpr>, Box<Condition>),
}

/// Target set of a `for ... of` expression.
#[derive(Debug, Clone)]
pub enum ForSet {
    Them,
    /// Explicit identifiers; entries may end with `*` for wildcard prefixes.
    List(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum OfKind {
    All,
    Any,
    Exactly(usize),
}

#[derive(Debug, Clone)]
pub enum IntCompOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
pub enum IntExpr {
    Literal(usize),
    Count(String),       // #s
    Filesize,            // filesize keyword
    MatchOffset(String), // @s[1] — offset of first match
    /// `uint8(offset)` — read unsigned 8-bit integer at offset
    Uint8(Box<IntExpr>),
    /// `uint16(offset)` — read unsigned 16-bit LE integer at offset
    Uint16(Box<IntExpr>),
    /// `uint32(offset)` — read unsigned 32-bit LE integer at offset
    Uint32(Box<IntExpr>),
    /// `int8(offset)` — read signed 8-bit integer at offset
    Int8(Box<IntExpr>),
    /// `int16(offset)` — read signed 16-bit LE integer at offset
    Int16(Box<IntExpr>),
    /// `int32(offset)` — read signed 32-bit LE integer at offset
    Int32(Box<IntExpr>),
    /// `entrypoint` — PE entry point file offset (or 0 if not PE)
    Entrypoint,
    /// `offset` — alias for entrypoint (YARA compat)
    Offset,
    /// `pe.number_of_sections` — PE section count
    PeNumberOfSections,
    /// String length: `$s` as int expression
    StringLength(String),
    /// `math.hash(offset, length)` — custom hash
    MathHash(Box<IntExpr>, Box<IntExpr>),
    /// Arithmetic: +, -, *, /
    Add(Box<IntExpr>, Box<IntExpr>),
    Sub(Box<IntExpr>, Box<IntExpr>),
    Mul(Box<IntExpr>, Box<IntExpr>),
    Div(Box<IntExpr>, Box<IntExpr>),
    /// Bitwise AND: `pe.characteristics & pe.DLL`
    BitAnd(Box<IntExpr>, Box<IntExpr>),
    /// Parenthesized
    Paren(Box<IntExpr>),
    /// Floating-point literal (entropy thresholds: `> 7.0`)
    Float(f64),
    /// Loop variable reference inside `for ... i in (...)` bodies
    Var(String),
    /// `@s[i]` — offset of the i-th match (1-based), index is an expression
    MatchOffsetN(String, Box<IntExpr>),
    /// `math.entropy(offset, length)` — Shannon entropy, 0.0..8.0
    Entropy(Box<IntExpr>, Box<IntExpr>),
    /// `pe.machine` — COFF machine type
    PeMachine,
    /// `pe.timestamp` — COFF timestamp
    PeTimestamp,
    /// `pe.entry_point` — entry point RVA
    PeEntryPoint,
    /// `pe.subsystem` — optional-header subsystem
    PeSubsystem,
    /// `pe.characteristics` — COFF characteristics flags
    PeCharacteristics,
    /// `pe.is_pe()` — 1 when the buffer is a valid PE
    PeIsPe,
    /// `pe.MACHINE_I386` / `pe.SUBSYSTEM_WINDOWS_GUI` / `pe.DLL` constants
    PeConst(String),
}

impl Condition {
    /// Collect all string identifiers referenced in this condition.
    pub fn referenced_strings(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_refs(&mut out);
        out.sort();
        out.dedup();
        out
    }

    /// Substitute `Var(var)` with `val` inside every integer expression.
    /// Used by `for <var> in (a..b)` evaluation: the body is cloned per
    /// iteration and the loop variable is replaced by its current value.
    pub fn subst_var(&mut self, var: &str, val: i64) {
        match self {
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.subst_var(var, val);
                b.subst_var(var, val);
            }
            Condition::Not(c) => c.subst_var(var, val),
            Condition::AtExpr(_, e) => subst_int(e, var, val),
            Condition::InExpr(_, s, e) => {
                subst_int(s, var, val);
                subst_int(e, var, val);
            }
            Condition::IntComp(_, a, b) => {
                subst_int(a, var, val);
                subst_int(b, var, val);
            }
            Condition::PeNumberSections(_, rhs) => subst_int(rhs, var, val),
            Condition::ForOf(_, _, body) => body.subst_var(var, val),
            // A same-named inner loop shadows the outer binding: only
            // substitute when the name differs.
            Condition::ForIntRange(_, inner_var, start, end, body) if inner_var != var => {
                subst_int(start, var, val);
                subst_int(end, var, val);
                body.subst_var(var, val);
            }
            _ => {}
        }
    }

    /// Substitute the bare `$` (current-string reference of an enclosing
    /// `for ... of`) with the concrete string identifier `sid`.
    pub fn subst_current(&mut self, sid: &str) {
        match self {
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.subst_current(sid);
                b.subst_current(sid);
            }
            Condition::Not(c) => c.subst_current(sid),
            Condition::StringMatch(s) | Condition::StringCount(s) => {
                if s == "$" {
                    *s = sid.to_string();
                }
            }
            Condition::At(s, _) | Condition::AtExpr(s, _) => {
                if s == "$" {
                    *s = sid.to_string();
                }
            }
            Condition::In(s, _, _) | Condition::InExpr(s, _, _) => {
                if s == "$" {
                    *s = sid.to_string();
                }
            }
            Condition::Contains(s, _) | Condition::IsType(s, _) | Condition::Eq(s, _) => {
                if s == "$" {
                    *s = sid.to_string();
                }
            }
            Condition::Matches(s, _) => {
                if s == "$" {
                    *s = sid.to_string();
                }
            }
            Condition::IntComp(_, a, b) => {
                subst_int_current(a, sid);
                subst_int_current(b, sid);
            }
            Condition::PeNumberSections(_, rhs) => subst_int_current(rhs, sid),
            Condition::ForOf(_, _, body) => body.subst_current(sid),
            Condition::ForIntRange(_, _, start, end, body) => {
                subst_int_current(start, sid);
                subst_int_current(end, sid);
                body.subst_current(sid);
            }
            _ => {}
        }
    }

    fn collect_refs<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_refs(out);
                b.collect_refs(out);
            }
            Condition::Not(c) => c.collect_refs(out),
            Condition::StringMatch(s) | Condition::StringCount(s) => {
                // `$` refers to the current string of an enclosing `for of`
                // — not a rule-level definition.
                if s != "$" {
                    out.push(s.as_str());
                }
            }
            Condition::At(s, _) | Condition::AtExpr(s, _) => {
                if s != "$" {
                    out.push(s.as_str());
                }
            }
            Condition::In(s, _, _) | Condition::InExpr(s, _, _) => {
                if s != "$" {
                    out.push(s.as_str());
                }
            }
            Condition::Contains(s, _) | Condition::IsType(s, _) | Condition::Eq(s, _) => {
                if s != "$" {
                    out.push(s.as_str());
                }
            }
            Condition::Matches(s, _) => {
                if s != "$" {
                    out.push(s.as_str());
                }
            }
            Condition::IntComp(_, a, b) => {
                a.collect_string_refs(out);
                b.collect_string_refs(out);
            }
            Condition::OfSet(_, ids) => {
                for id in ids {
                    // Wildcard entries ($a*) are prefix references checked
                    // separately at compile time.
                    if !id.ends_with('*') {
                        out.push(id.as_str());
                    }
                }
            }
            Condition::ForOf(_, set, body) => {
                if let ForSet::List(ids) = set {
                    for id in ids {
                        if !id.ends_with('*') {
                            out.push(id.as_str());
                        }
                    }
                }
                body.collect_refs(out);
            }
            Condition::ForIntRange(_, _, start, end, body) => {
                start.collect_string_refs(out);
                end.collect_string_refs(out);
                body.collect_refs(out);
            }
            Condition::PeNumberSections(_, rhs) => {
                rhs.collect_string_refs(out);
            }
            _ => {}
        }
    }
}

/// Replace `Var(var)` with `Literal(val)` inside an integer expression tree.
fn subst_int(e: &mut IntExpr, var: &str, val: i64) {
    match e {
        IntExpr::Var(name) if name == var => *e = IntExpr::Literal(val as usize),
        IntExpr::Uint8(inner)
        | IntExpr::Uint16(inner)
        | IntExpr::Uint32(inner)
        | IntExpr::Int8(inner)
        | IntExpr::Int16(inner)
        | IntExpr::Int32(inner)
        | IntExpr::Paren(inner) => subst_int(inner, var, val),
        IntExpr::MatchOffsetN(_, idx) => subst_int(idx, var, val),
        IntExpr::MathHash(a, b) | IntExpr::Entropy(a, b) => {
            subst_int(a, var, val);
            subst_int(b, var, val);
        }
        IntExpr::Add(a, b)
        | IntExpr::Sub(a, b)
        | IntExpr::Mul(a, b)
        | IntExpr::Div(a, b)
        | IntExpr::BitAnd(a, b) => {
            subst_int(a, var, val);
            subst_int(b, var, val);
        }
        _ => {}
    }
}

/// Replace `$` string references with the concrete current-string id.
fn subst_int_current(e: &mut IntExpr, sid: &str) {
    match e {
        IntExpr::Count(id) | IntExpr::MatchOffset(id) | IntExpr::StringLength(id) => {
            if id == "$" {
                *id = sid.to_string();
            }
        }
        IntExpr::MatchOffsetN(id, _) => {
            if id == "$" {
                *id = sid.to_string();
            }
        }
        IntExpr::Uint8(inner)
        | IntExpr::Uint16(inner)
        | IntExpr::Uint32(inner)
        | IntExpr::Int8(inner)
        | IntExpr::Int16(inner)
        | IntExpr::Int32(inner)
        | IntExpr::Paren(inner) => subst_int_current(inner, sid),
        IntExpr::MathHash(a, b) | IntExpr::Entropy(a, b) => {
            subst_int_current(a, sid);
            subst_int_current(b, sid);
        }
        IntExpr::Add(a, b)
        | IntExpr::Sub(a, b)
        | IntExpr::Mul(a, b)
        | IntExpr::Div(a, b)
        | IntExpr::BitAnd(a, b) => {
            subst_int_current(a, sid);
            subst_int_current(b, sid);
        }
        _ => {}
    }
}

impl IntExpr {
    fn collect_string_refs<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            IntExpr::Count(id) | IntExpr::MatchOffset(id) | IntExpr::StringLength(id) => {
                if id != "$" {
                    out.push(id.as_str());
                }
            }
            IntExpr::MatchOffsetN(id, idx) => {
                if id != "$" {
                    out.push(id.as_str());
                }
                idx.collect_string_refs(out);
            }
            IntExpr::Uint8(inner) | IntExpr::Uint16(inner) | IntExpr::Uint32(inner) => {
                inner.collect_string_refs(out)
            }
            IntExpr::Int8(inner) | IntExpr::Int16(inner) | IntExpr::Int32(inner) => {
                inner.collect_string_refs(out)
            }
            IntExpr::Add(a, b)
            | IntExpr::Sub(a, b)
            | IntExpr::Mul(a, b)
            | IntExpr::Div(a, b)
            | IntExpr::BitAnd(a, b) => {
                a.collect_string_refs(out);
                b.collect_string_refs(out);
            }
            IntExpr::Paren(inner) => inner.collect_string_refs(out),
            IntExpr::MathHash(offset, len) | IntExpr::Entropy(offset, len) => {
                offset.collect_string_refs(out);
                len.collect_string_refs(out);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_referenced_strings() {
        let cond = Condition::And(
            Box::new(Condition::StringMatch("$a".into())),
            Box::new(Condition::IntComp(
                IntCompOp::Gt,
                Box::new(IntExpr::Count("$b".into())),
                Box::new(IntExpr::Literal(2)),
            )),
        );
        let refs = cond.referenced_strings();
        assert_eq!(refs, vec!["$a", "$b"]);
    }
}
