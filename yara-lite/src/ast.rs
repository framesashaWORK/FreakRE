//! AST types for YARA-lite rules.

/// A single parsed rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub strings: Vec<StringDef>,
    pub condition: Condition,
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
    NibbleWildcard { mask: u8, value: u8 },
}

#[derive(Debug, Clone, Default)]
pub struct Modifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
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
    /// Integer comparison: `#s > 3`, `filesize < 1024`, `uint16(0) == 0x5A4D`
    IntComp(IntCompOp, Box<IntExpr>, Box<IntExpr>),
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
    Count(String),        // #s
    Filesize,             // filesize keyword
    MatchOffset(String),  // @s[1] — offset of first match
    /// `uint8(offset)` — read unsigned 8-bit integer at offset
    Uint8(Box<IntExpr>),
    /// `uint16(offset)` — read unsigned 16-bit LE integer at offset
    Uint16(Box<IntExpr>),
    /// `uint32(offset)` — read unsigned 32-bit LE integer at offset
    Uint32(Box<IntExpr>),
    /// `entrypoint` — PE entry point file offset (or 0 if not PE)
    Entrypoint,
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

    fn collect_refs<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_refs(out);
                b.collect_refs(out);
            }
            Condition::Not(c) => c.collect_refs(out),
            Condition::StringMatch(s) | Condition::StringCount(s) => out.push(s.as_str()),
            Condition::At(s, _) | Condition::In(s, _, _) => out.push(s.as_str()),
            Condition::IntComp(_, a, b) => {
                a.collect_string_refs(out);
                b.collect_string_refs(out);
            }
            Condition::OfSet(_, ids) => {
                for id in ids {
                    out.push(id.as_str());
                }
            }
            _ => {}
        }
    }
}

impl IntExpr {
    fn collect_string_refs<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            IntExpr::Count(id) | IntExpr::MatchOffset(id) => out.push(id.as_str()),
            IntExpr::Uint8(inner) | IntExpr::Uint16(inner) | IntExpr::Uint32(inner) => {
                inner.collect_string_refs(out)
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
