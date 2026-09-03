//! Parser for YARA-lite rule syntax.
//!
//! Supported subset:
//! ```text
//! rule name : tag1 tag2 {
//!     strings:
//!         $s1 = "text" nocase wide ascii fullword
//!         $h1 = { 4D 5A ?? 90 }
//!     condition:
//!         all of them
//! }
//! ```

use crate::ast::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("expected '{0}', found '{1}' at position {2}")]
    Expected(String, String, usize),
    #[error("invalid hex token at position {0}: {1}")]
    InvalidHex(usize, String),
    #[error("unknown modifier '{0}' at position {1}")]
    UnknownModifier(String, usize),
    #[error("syntax error at position {0}: {1}")]
    Syntax(usize, String),
}

type Result<T> = std::result::Result<T, ParseError>;

/// Parse a single rule from text.
pub fn parse_rule(input: &str) -> Result<Rule> {
    let mut p = Parser::new(input);
    p.parse_rule()
}

/// Parse multiple rules from text (separated by whitespace).
pub fn parse_rules(input: &str) -> Result<Vec<Rule>> {
    let mut p = Parser::new(input);
    let mut rules = Vec::new();
    while !p.at_end() {
        p.skip_ws();
        if p.at_end() {
            break;
        }
        rules.push(p.parse_rule()?);
    }
    Ok(rules)
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek_char(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek_char() {
            if c.is_whitespace() {
                self.advance(c.len_utf8());
            } else if self.remaining().starts_with("//") {
                // line comment
                if let Some(nl) = self.remaining().find('\n') {
                    self.advance(nl + 1);
                } else {
                    self.pos = self.input.len();
                }
            } else if self.remaining().starts_with("/*") {
                if let Some(end) = self.remaining()[2..].find("*/") {
                    self.advance(end + 4);
                } else {
                    self.pos = self.input.len();
                }
            } else {
                break;
            }
        }
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<()> {
        self.skip_ws();
        if self.remaining().starts_with(kw) {
            // Make sure it's not a prefix of a longer identifier
            let after = &self.remaining()[kw.len()..];
            let next_is_boundary = after
                .chars()
                .next()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);
            if next_is_boundary {
                self.advance(kw.len());
                return Ok(());
            }
        }
        Err(ParseError::Expected(
            kw.into(),
            self.peek_token_preview(),
            self.pos,
        ))
    }

    fn peek_token_preview(&self) -> String {
        let r = self.remaining().trim_start();
        let raw_end = r
            .find(|c: char| c.is_whitespace() || c == '{' || c == '}' || c == ':')
            .unwrap_or(r.len());
        let mut end = raw_end.min(20);
        while end > 0 && !r.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            "<eof>".into()
        } else {
            r[..end].into()
        }
    }

    fn expect_char(&mut self, ch: char) -> Result<()> {
        self.skip_ws();
        match self.peek_char() {
            Some(c) if c == ch => {
                self.advance(ch.len_utf8());
                Ok(())
            }
            Some(c) => Err(ParseError::Expected(
                ch.to_string(),
                c.to_string(),
                self.pos,
            )),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn read_identifier(&mut self) -> Result<String> {
        self.skip_ws();
        let start = self.pos;
        let rest = self.remaining();
        let len = rest
            .char_indices()
            .find(|(_, c)| !c.is_alphanumeric() && *c != '_')
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        if len == 0 {
            return Err(ParseError::Syntax(
                self.pos,
                "expected identifier".into(),
            ));
        }
        self.advance(len);
        Ok(self.input[start..start + len].to_string())
    }

    fn read_quoted_string(&mut self) -> Result<String> {
        self.expect_char('"')?;
        let start = self.pos;
        loop {
            if self.at_end() {
                return Err(ParseError::UnexpectedEof);
            }
            let c = self.peek_char().unwrap();
            if c == '"' {
                let val = self.input[start..self.pos].to_string();
                self.advance(1);
                return Ok(val);
            }
            self.advance(c.len_utf8());
        }
    }

    fn read_string_identifier(&mut self) -> Result<String> {
        self.skip_ws();
        if !self.remaining().starts_with('$') {
            return Err(ParseError::Expected(
                "$identifier".into(),
                self.peek_token_preview(),
                self.pos,
            ));
        }
        let start = self.pos;
        self.advance(1); // skip '$'
        let rest = &self.input[self.pos..];
        let len = rest
            .char_indices()
            .find(|(_, c)| !c.is_alphanumeric() && *c != '_')
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        if len == 0 {
            return Err(ParseError::Syntax(self.pos, "empty string identifier".into()));
        }
        self.advance(len);
        Ok(self.input[start..self.pos].to_string())
    }

    // ─── Rule parsing ──────────────────────────────────────

    fn parse_rule(&mut self) -> Result<Rule> {
        self.expect_keyword("rule")?;
        let name = self.read_identifier()?;

        // Optional tags
        let mut tags = Vec::new();
        self.skip_ws();
        if self.peek_char() == Some(':') {
            self.advance(1);
            loop {
                self.skip_ws();
                if self.peek_char() == Some('{') {
                    break;
                }
                tags.push(self.read_identifier()?);
            }
        }

        self.expect_char('{')?;

        // Sections
        let mut strings = Vec::new();
        let mut condition = Condition::Bool(false);

        loop {
            self.skip_ws();
            if self.peek_char() == Some('}') {
                self.advance(1);
                break;
            }
            if self.remaining().starts_with("strings") {
                self.advance("strings".len());
                self.expect_char(':')?;
                strings = self.parse_strings_section()?;
            } else if self.remaining().starts_with("condition") {
                self.advance("condition".len());
                self.expect_char(':')?;
                condition = self.parse_condition()?;
            } else {
                return Err(ParseError::Syntax(
                    self.pos,
                    format!("unexpected token in rule body: {}", self.peek_token_preview()),
                ));
            }
        }

        Ok(Rule {
            name,
            tags,
            strings,
            condition,
        })
    }

    // ─── Strings section ───────────────────────────────────

    fn parse_strings_section(&mut self) -> Result<Vec<StringDef>> {
        let mut defs = Vec::new();
        loop {
            self.skip_ws();
            if !self.remaining().starts_with('$') {
                break;
            }
            defs.push(self.parse_string_def()?);
        }
        Ok(defs)
    }

    fn parse_string_def(&mut self) -> Result<StringDef> {
        let identifier = self.read_string_identifier()?;
        self.skip_ws();
        self.expect_char('=')?;
        self.skip_ws();

        let pattern = if self.peek_char() == Some('"') || self.peek_char() == Some('/') {
            Pattern::Text(self.parse_text_pattern()?)
        } else if self.peek_char() == Some('{') {
            Pattern::Hex(self.parse_hex_pattern()?)
        } else {
            return Err(ParseError::Syntax(
                self.pos,
                "expected string or hex pattern".into(),
            ));
        };

        let modifiers = self.parse_modifiers()?;

        Ok(StringDef {
            identifier,
            pattern,
            modifiers,
        })
    }

    fn parse_text_pattern(&mut self) -> Result<TextPattern> {
        self.skip_ws();
        if self.peek_char() == Some('/') {
            // Regex pattern
            self.advance(1);
            let start = self.pos;
            let mut escaped = false;
            loop {
                if self.at_end() {
                    return Err(ParseError::UnexpectedEof);
                }
                let c = self.peek_char().unwrap();
                if escaped {
                    escaped = false;
                    self.advance(c.len_utf8());
                } else if c == '\\' {
                    escaped = true;
                    self.advance(1);
                } else if c == '/' {
                    let value = self.input.as_bytes()[start..self.pos].to_vec();
                    self.advance(1);
                    return Ok(TextPattern {
                        value,
                        is_regex: true,
                    });
                } else {
                    self.advance(c.len_utf8());
                }
            }
        } else {
            // Quoted string
            self.expect_char('"')?;
            let start = self.pos;
            let mut escaped = false;
            loop {
                if self.at_end() {
                    return Err(ParseError::UnexpectedEof);
                }
                let c = self.peek_char().unwrap();
                if escaped {
                    escaped = false;
                    self.advance(c.len_utf8());
                } else if c == '\\' {
                    escaped = true;
                    self.advance(1);
                } else if c == '"' {
                    let raw = &self.input[start..self.pos];
                    let value = unescape_string(raw);
                    self.advance(1);
                    return Ok(TextPattern {
                        value,
                        is_regex: false,
                    });
                } else {
                    self.advance(c.len_utf8());
                }
            }
        }
    }

    fn parse_hex_pattern(&mut self) -> Result<HexPattern> {
        self.expect_char('{')?;
        let mut tokens = Vec::new();
        loop {
            self.skip_ws();
            if self.peek_char() == Some('}') {
                self.advance(1);
                break;
            }
            tokens.push(self.parse_hex_token()?);
        }
        Ok(HexPattern { tokens })
    }

    fn parse_hex_token(&mut self) -> Result<HexToken> {
        self.skip_ws();
        let rest = self.remaining();

        // Alternation: ( token | token | ... )
        if rest.starts_with('(') {
            self.advance(1);
            let mut alternatives = Vec::new();
            loop {
                self.skip_ws();
                if self.peek_char() == Some(')') {
                    self.advance(1);
                    break;
                }
                let token = self.parse_hex_token()?;
                alternatives.push(token);
                self.skip_ws();
                if self.peek_char() == Some('|') {
                    self.advance(1);
                }
            }
            if alternatives.is_empty() {
                return Err(ParseError::InvalidHex(self.pos, "empty alternation".into()));
            }
            return Ok(HexToken::Alternation(alternatives));
        }

        // Jump: [N-M] or [N] or [N-] (unbounded)
        if rest.starts_with('[') {
            self.advance(1);
            self.skip_ws();
            let min = self.read_usize()?;
            self.skip_ws();
            let max = if self.peek_char() == Some('-') {
                self.advance(1);
                self.skip_ws();
                if self.peek_char() == Some(']') {
                    // [N-] means N to unbounded (use usize::MAX as sentinel)
                    usize::MAX
                } else {
                    self.read_usize()?
                }
            } else {
                min // [N] means exactly N
            };
            self.skip_ws();
            self.expect_char(']')?;
            return Ok(HexToken::Jump { min, max });
        }

        // Regular hex tokens
        if rest.len() < 2 {
            return Err(ParseError::InvalidHex(self.pos, "incomplete hex byte".into()));
        }
        let hi = rest.as_bytes()[0];
        let lo = rest.as_bytes()[1];

        match (hi, lo) {
            (b'?', b'?') => {
                self.advance(2);
                Ok(HexToken::Wildcard)
            }
            (b'?', _) => {
                let lo_val = hex_digit(lo).ok_or_else(|| {
                    ParseError::InvalidHex(self.pos, format!("invalid nibble '{}'", lo as char))
                })?;
                self.advance(2);
                Ok(HexToken::NibbleWildcard {
                    mask: 0xF0,
                    value: lo_val,
                })
            }
            (_, b'?') => {
                let hi_val = hex_digit(hi).ok_or_else(|| {
                    ParseError::InvalidHex(self.pos, format!("invalid nibble '{}'", hi as char))
                })?;
                self.advance(2);
                Ok(HexToken::NibbleWildcard {
                    mask: 0x0F,
                    value: hi_val << 4,
                })
            }
            _ => {
                let h = hex_digit(hi).ok_or_else(|| {
                    ParseError::InvalidHex(self.pos, format!("invalid hex digit '{}'", hi as char))
                })?;
                let l = hex_digit(lo).ok_or_else(|| {
                    ParseError::InvalidHex(self.pos, format!("invalid hex digit '{}'", lo as char))
                })?;
                self.advance(2);
                Ok(HexToken::Literal((h << 4) | l))
            }
        }
    }

    fn parse_modifiers(&mut self) -> Result<Modifiers> {
        let mut mods = Modifiers::default();
        loop {
            self.skip_ws();
            // Read one whole identifier word so prefixes like `nocasewide`
            // never match as `nocase` + `wide` (real YARA rejects them).
            let rest = self.remaining();
            let word_len = rest
                .char_indices()
                .find(|(_, c)| !c.is_alphanumeric() && *c != '_')
                .map(|(i, _)| i)
                .unwrap_or(rest.len());
            if word_len == 0 {
                break;
            }
            match &rest[..word_len] {
                "nocase" => mods.nocase = true,
                "wide" => mods.wide = true,
                "ascii" => mods.ascii = true,
                "fullword" => mods.fullword = true,
                "xor" => mods.xor = true,
                "at" => {
                    self.advance(word_len);
                    self.skip_ws();
                    mods.at = Some(self.read_usize()?);
                    continue;
                }
                "in" => {
                    self.advance(word_len);
                    self.skip_ws();
                    self.expect_char('(')?;
                    let start = self.read_usize()?;
                    self.skip_ws();
                    self.expect_char('.')?;
                    self.expect_char('.')?;
                    let end = self.read_usize()?;
                    self.expect_char(')')?;
                    mods.range = Some((start, end));
                    continue;
                }
                // Section keywords legitimately follow a modifier list.
                "condition" | "strings" => break,
                unknown => {
                    return Err(ParseError::UnknownModifier(
                        unknown.to_string(),
                        self.pos,
                    ));
                }
            }
            self.advance(word_len);
        }
        // Default: ascii if neither ascii nor wide specified
        if !mods.wide && !mods.ascii {
            mods.ascii = true;
        }
        Ok(mods)
    }

    // ─── Condition parsing ─────────────────────────────────

    fn parse_condition(&mut self) -> Result<Condition> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Condition> {
        self.parse_or_expr_inner(0)
    }

    fn parse_or_expr_inner(&mut self, depth: usize) -> Result<Condition> {
        const MAX_EXPR_DEPTH: usize = 64;
        if depth > MAX_EXPR_DEPTH {
            return Err(ParseError::Syntax(self.pos, "expression nesting too deep".into()));
        }
        let mut left = self.parse_and_expr_inner(depth + 1)?;
        loop {
            self.skip_ws();
            if self.try_keyword("or") {
                let right = self.parse_and_expr_inner(depth + 1)?;
                left = Condition::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<Condition> {
        self.parse_and_expr_inner(0)
    }

    fn parse_and_expr_inner(&mut self, depth: usize) -> Result<Condition> {
        const MAX_EXPR_DEPTH: usize = 64;
        if depth > MAX_EXPR_DEPTH {
            return Err(ParseError::Syntax(self.pos, "expression nesting too deep".into()));
        }
        let mut left = self.parse_not_expr_inner(depth + 1)?;
        loop {
            self.skip_ws();
            if self.try_keyword("and") {
                let right = self.parse_not_expr_inner(depth + 1)?;
                left = Condition::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_not_expr(&mut self) -> Result<Condition> {
        self.parse_not_expr_inner(0)
    }

    fn parse_not_expr_inner(&mut self, depth: usize) -> Result<Condition> {
        const MAX_EXPR_DEPTH: usize = 64;
        if depth > MAX_EXPR_DEPTH {
            return Err(ParseError::Syntax(self.pos, "expression nesting too deep (possible infinite recursion)".into()));
        }
        self.skip_ws();
        if self.try_keyword("not") {
            let inner = self.parse_not_expr_inner(depth + 1)?;
            Ok(Condition::Not(Box::new(inner)))
        } else {
            self.parse_primary_inner(depth + 1)
        }
    }

    /// Try to consume a keyword followed by a non-identifier boundary.
    /// Returns true and advances if matched, false otherwise.
    fn try_keyword(&mut self, kw: &str) -> bool {
        if self.remaining().starts_with(kw) {
            let after = &self.remaining()[kw.len()..];
            let next_is_boundary = after
                .chars()
                .next()
                .map(|c| !c.is_alphanumeric() && c != '_')
                .unwrap_or(true);
            if next_is_boundary {
                self.advance(kw.len());
                return true;
            }
        }
        false
    }

    fn parse_primary(&mut self) -> Result<Condition> {
        self.parse_primary_inner(0)
    }

    fn parse_primary_inner(&mut self, depth: usize) -> Result<Condition> {
        const MAX_EXPR_DEPTH: usize = 64;
        if depth > MAX_EXPR_DEPTH {
            return Err(ParseError::Syntax(self.pos, "expression nesting too deep".into()));
        }
        self.skip_ws();

        // Parenthesized expression
        if self.peek_char() == Some('(') {
            self.advance(1);
            let cond = self.parse_or_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            return Ok(cond);
        }

        // Boolean literals (must terminate at an identifier boundary so
        // identifiers like `truexyy` are rejected instead of absorbed).
        if self.try_keyword("true") {
            return Ok(Condition::Bool(true));
        }
        if self.try_keyword("false") {
            return Ok(Condition::Bool(false));
        }

        // N of them / all of them / any of them
        let of_kind = if self.try_keyword("all") {
            Some(OfKind::All)
        } else if self.try_keyword("any") {
            Some(OfKind::Any)
        } else {
            None
        };
        if let Some(kind) = of_kind {
            return self.parse_of_suffix(kind);
        }
        if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            // Could be "N of them" or integer literal
            let saved = self.pos;
            let num = self.read_usize()?;
            self.skip_ws();
            if self.try_keyword("of") {
                return self.parse_of_tail(OfKind::Exactly(num));
            }
            // Not "of", restore and treat as int literal in comparison
            self.pos = saved;
        }

        // String count: #s
        if self.peek_char() == Some('#') {
            let id = self.read_count_identifier()?;
            self.skip_ws();
            // Check for comparison
            if let Some(op) = self.try_parse_comp_op() {
                let rhs = self.parse_int_expr()?;
                return Ok(Condition::IntComp(
                    op,
                    Box::new(IntExpr::Count(id)),
                    Box::new(rhs),
                ));
            }
            return Ok(Condition::StringCount(id));
        }

        // String reference with optional `at` / `in`
        if self.peek_char() == Some('$') {
            let id = self.read_string_identifier()?;
            self.skip_ws();
            if self.try_keyword("at") {
                self.skip_ws();
                // Check if next token is a number literal or an int expression
                if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false)
                    || self.peek_char() == Some('#')
                    || self.peek_char() == Some('$')
                    || self.peek_char() == Some('@')
                    || self.peek_char() == Some('u')
                    || self.peek_char() == Some('i')
                    || self.peek_char() == Some('o')
                {
                    // Variable offset: $s at @s[1] or $s at uint16(0x100)
                    let offset_expr = self.parse_int_expr()?;
                    return Ok(Condition::AtExpr(id, Box::new(offset_expr)));
                }
                let offset = self.read_usize()?;
                return Ok(Condition::At(id, offset));
            }
            if self.try_keyword("in") {
                self.expect_char('(')?;
                let start = self.parse_int_expr()?;
                self.skip_ws();
                self.expect_char('.')?;
                self.expect_char('.')?;
                let end = self.parse_int_expr()?;
                self.expect_char(')')?;
                return Ok(Condition::InExpr(id, Box::new(start), Box::new(end)));
            }
            if self.try_keyword("contains") {
                self.skip_ws();
                let substr = self.read_quoted_string()?;
                return Ok(Condition::Contains(id, substr));
            }
            if self.try_keyword("istype") {
                self.skip_ws();
                let type_name = self.read_quoted_string()?;
                return Ok(Condition::IsType(id, type_name));
            }
            return Ok(Condition::StringMatch(id));
        }

        // filesize comparison
        if self.try_keyword("filesize") {
            self.skip_ws();
            if let Some(op) = self.try_parse_comp_op() {
                let rhs = self.parse_int_expr()?;
                return Ok(Condition::IntComp(
                    op,
                    Box::new(IntExpr::Filesize),
                    Box::new(rhs),
                ));
            }
            return Err(ParseError::Syntax(
                self.pos,
                "filesize must be used in comparison".into(),
            ));
        }

        if self.remaining().starts_with("uint8(")
            || self.remaining().starts_with("uint16(")
            || self.remaining().starts_with("uint32(")
            || self.remaining().starts_with("int8(")
            || self.remaining().starts_with("int16(")
            || self.remaining().starts_with("int32(")
        {
            let lhs = self.parse_int_expr()?;
            self.skip_ws();
            if let Some(op) = self.try_parse_comp_op() {
                let rhs = self.parse_int_expr()?;
                return Ok(Condition::IntComp(op, Box::new(lhs), Box::new(rhs)));
            }
            return Err(ParseError::Syntax(
                self.pos,
                "uintN/intN(...) must be used in comparison".into(),
            ));
        }

        // pe.number_of_sections
        if self.remaining().starts_with("pe.") {
            self.advance(3);
            if self.try_keyword("number_of_sections") {
                self.skip_ws();
                if let Some(op) = self.try_parse_comp_op() {
                    let rhs = self.parse_int_expr()?;
                    return Ok(Condition::PeNumberSections(op, Box::new(rhs)));
                }
                return Err(ParseError::Syntax(
                    self.pos,
                    "pe.number_of_sections must be used in comparison".into(),
                ));
            }
            if self.try_keyword("imports") {
                self.skip_ws();
                self.expect_char('(')?;
                let dll_name = self.read_quoted_string()?;
                self.expect_char(')')?;
                return Ok(Condition::PeImports(dll_name));
            }
            if self.try_keyword("sections") {
                self.skip_ws();
                self.expect_char('(')?;
                let sec_name = self.read_quoted_string()?;
                self.expect_char(')')?;
                return Ok(Condition::PeSections(sec_name));
            }
            return Err(ParseError::Syntax(
                self.pos,
                format!("unknown pe. property: {}", self.peek_token_preview()),
            ));
        }

        // math.hash(offset, length)
        if self.remaining().starts_with("math.") {
            self.advance(5);
            if self.try_keyword("hash") {
                self.skip_ws();
                self.expect_char('(')?;
                let offset_expr = self.parse_int_expr()?;
                self.skip_ws();
                self.expect_char(',')?;
                let len_expr = self.parse_int_expr()?;
                self.expect_char(')')?;
                let lhs = IntExpr::MathHash(Box::new(offset_expr), Box::new(len_expr));
                self.skip_ws();
                if let Some(op) = self.try_parse_comp_op() {
                    let rhs = self.parse_int_expr()?;
                    return Ok(Condition::IntComp(op, Box::new(lhs), Box::new(rhs)));
                }
                // Standalone: math.hash(0, 4) means > 0 implicitly
                return Ok(Condition::IntComp(
                    IntCompOp::Gt,
                    Box::new(lhs),
                    Box::new(IntExpr::Literal(0)),
                ));
            }
            return Err(ParseError::Syntax(
                self.pos,
                format!("unknown math. function: {}", self.peek_token_preview()),
            ));
        }

        if self.remaining().starts_with("entrypoint") {
            self.advance(10);
            self.skip_ws();
            if let Some(op) = self.try_parse_comp_op() {
                let rhs = self.parse_int_expr()?;
                return Ok(Condition::IntComp(
                    op,
                    Box::new(IntExpr::Entrypoint),
                    Box::new(rhs),
                ));
            }
            return Err(ParseError::Syntax(
                self.pos,
                "entrypoint must be used in comparison".into(),
            ));
        }

        // `offset` keyword (alias for entrypoint)
        if self.try_keyword("offset") {
            self.skip_ws();
            if let Some(op) = self.try_parse_comp_op() {
                let rhs = self.parse_int_expr()?;
                return Ok(Condition::IntComp(
                    op,
                    Box::new(IntExpr::Offset),
                    Box::new(rhs),
                ));
            }
            return Err(ParseError::Syntax(
                self.pos,
                "offset must be used in comparison".into(),
            ));
        }

        Err(ParseError::Syntax(
            self.pos,
            format!("unexpected token: {}", self.peek_token_preview()),
        ))
    }

    /// `all|any|N of ...` — consumes the `of` keyword, then the target.
    fn parse_of_suffix(&mut self, kind: OfKind) -> Result<Condition> {
        self.skip_ws();
        self.expect_keyword("of")?;
        self.parse_of_tail(kind)
    }

    /// Target of an `of` expression with `of` already consumed.
    fn parse_of_tail(&mut self, kind: OfKind) -> Result<Condition> {
        self.skip_ws();
        if self.try_keyword("them") {
            Ok(Condition::OfThem(kind))
        } else if self.peek_char() == Some('(') {
            self.advance(1);
            let mut ids = Vec::new();
            loop {
                self.skip_ws();
                if self.peek_char() == Some(')') {
                    self.advance(1);
                    break;
                }
                ids.push(self.read_string_identifier()?);
                self.skip_ws();
                if self.peek_char() == Some(',') {
                    self.advance(1);
                }
            }
            Ok(Condition::OfSet(kind, ids))
        } else {
            Err(ParseError::Syntax(
                self.pos,
                "expected 'them' or '(' after 'of'".into(),
            ))
        }
    }

    fn try_parse_comp_op(&mut self) -> Option<IntCompOp> {
        self.skip_ws();
        let rest = self.remaining();
        if rest.starts_with(">=") {
            self.advance(2);
            Some(IntCompOp::Ge)
        } else if rest.starts_with("<=") {
            self.advance(2);
            Some(IntCompOp::Le)
        } else if rest.starts_with("!=") {
            self.advance(2);
            Some(IntCompOp::Ne)
        } else if rest.starts_with("==") {
            self.advance(2);
            Some(IntCompOp::Eq)
        } else if rest.starts_with('>') {
            self.advance(1);
            Some(IntCompOp::Gt)
        } else if rest.starts_with('<') {
            self.advance(1);
            Some(IntCompOp::Lt)
        } else {
            None
        }
    }

    fn parse_int_expr(&mut self) -> Result<IntExpr> {
        self.parse_int_expr_inner(0)
    }

    fn parse_int_expr_inner(&mut self, depth: usize) -> Result<IntExpr> {
        const MAX_INT_DEPTH: usize = 128;
        if depth > MAX_INT_DEPTH {
            return Err(ParseError::Syntax(
                self.pos,
                "integer expression nesting too deep".into(),
            ));
        }
        self.skip_ws();

        // Parenthesized integer expression — early return
        if self.peek_char() == Some('(') {
            self.advance(1);
            let inner = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            let mut left = IntExpr::Paren(Box::new(inner));
            self.maybe_parse_bin_ops(&mut left, depth)?;
            return Ok(left);
        }

        // String match offset: @s or @s[N] — early return
        if self.peek_char() == Some('@') {
            self.advance(1);
            let id = self.read_string_identifier()?;
            self.skip_ws();
            if self.peek_char() == Some('[') {
                self.advance(1);
                let _index = self.read_usize()?;
                self.expect_char(']')?;
            }
            return Ok(IntExpr::MatchOffset(id));
        }

        let mut left = if self.peek_char() == Some('#') {
            let id = self.read_count_identifier()?;
            IntExpr::Count(id)
        } else if self.remaining().starts_with("filesize") {
            self.advance(8);
            IntExpr::Filesize
        } else if self.remaining().starts_with("entrypoint") {
            self.advance(10);
            IntExpr::Entrypoint
        } else if self.try_keyword("offset") {
            IntExpr::Offset
        } else if self.remaining().starts_with("uint8(") {
            self.advance(6);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Uint8(Box::new(offset))
        } else if self.remaining().starts_with("uint16(") {
            self.advance(7);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Uint16(Box::new(offset))
        } else if self.remaining().starts_with("uint32(") {
            self.advance(7);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Uint32(Box::new(offset))
        } else if self.remaining().starts_with("int8(") {
            self.advance(5);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Int8(Box::new(offset))
        } else if self.remaining().starts_with("int16(") {
            self.advance(6);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Int16(Box::new(offset))
        } else if self.remaining().starts_with("int32(") {
            self.advance(6);
            let offset = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::Int32(Box::new(offset))
        } else if self.remaining().starts_with("math.hash(") {
            self.advance(10);
            let offset_expr = self.parse_int_expr_inner(depth + 1)?;
            self.skip_ws();
            self.expect_char(',')?;
            let len_expr = self.parse_int_expr_inner(depth + 1)?;
            self.expect_char(')')?;
            IntExpr::MathHash(Box::new(offset_expr), Box::new(len_expr))
        } else if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            let n = self.read_usize()?;
            self.skip_ws();
            let rest = self.remaining();
            if rest.starts_with("KB") || rest.starts_with("kb") {
                self.advance(2);
                IntExpr::Literal(n * 1024)
            } else if rest.starts_with("MB") || rest.starts_with("mb") {
                self.advance(2);
                IntExpr::Literal(n * 1024 * 1024)
            } else if rest.starts_with("GB") || rest.starts_with("gb") {
                self.advance(2);
                IntExpr::Literal(n * 1024 * 1024 * 1024)
            } else {
                IntExpr::Literal(n)
            }
        } else if self.peek_char() == Some('-') {
            self.advance(1);
            let inner = self.parse_int_expr_inner(depth + 1)?;
            IntExpr::Sub(Box::new(IntExpr::Literal(0)), Box::new(inner))
        } else {
            return Err(ParseError::Syntax(
                self.pos,
                format!("expected integer expression, got '{}'", self.peek_token_preview()),
            ));
        };

        self.maybe_parse_bin_ops(&mut left, depth)?;
        Ok(left)
    }

    fn maybe_parse_bin_ops(&mut self, left: &mut IntExpr, depth: usize) -> Result<()> {
        loop {
            self.skip_ws();
            let rest = self.remaining();
            if rest.starts_with('+') {
                self.advance(1);
                let rhs = self.parse_int_expr_inner(depth + 1)?;
                *left = IntExpr::Add(Box::new(left.clone()), Box::new(rhs));
            } else if let Some(after_minus) = rest.strip_prefix('-') {
                let first_non_ws = after_minus.trim_start();
                if first_non_ws.starts_with(|c: char| c.is_ascii_digit() || c == '(' || c == '$' || c == '#' || c == '@')
                    || first_non_ws.starts_with("uint8")
                    || first_non_ws.starts_with("uint16")
                    || first_non_ws.starts_with("uint32")
                    || first_non_ws.starts_with("int8")
                    || first_non_ws.starts_with("int16")
                    || first_non_ws.starts_with("int32")
                    || first_non_ws.starts_with("filesize")
                    || first_non_ws.starts_with("entrypoint")
                    || first_non_ws.starts_with("offset")
                    || first_non_ws.starts_with("math.")
                {
                    self.advance(1);
                    let rhs = self.parse_int_expr_inner(depth + 1)?;
                    *left = IntExpr::Sub(Box::new(left.clone()), Box::new(rhs));
                } else {
                    break;
                }
            } else if rest.starts_with('*') {
                self.advance(1);
                let rhs = self.parse_int_expr_inner(depth + 1)?;
                *left = IntExpr::Mul(Box::new(left.clone()), Box::new(rhs));
            } else if rest.starts_with('/') {
                self.advance(1);
                let rhs = self.parse_int_expr_inner(depth + 1)?;
                *left = IntExpr::Div(Box::new(left.clone()), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(())
    }

    fn read_usize(&mut self) -> Result<usize> {
        self.skip_ws();
        let start = self.pos;
        let rest = self.remaining();

        // Hex literal: 0x...
        if rest.starts_with("0x") || rest.starts_with("0X") {
            self.advance(2);
            let hex_start = self.pos;
            let hex_rest = &self.input[hex_start..];
            let len = hex_rest
                .char_indices()
                .find(|(_, c)| !c.is_ascii_hexdigit())
                .map(|(i, _)| i)
                .unwrap_or(hex_rest.len());
            if len == 0 {
                return Err(ParseError::Syntax(self.pos, "expected hex digits after 0x".into()));
            }
            self.advance(len);
            let hex_str = &self.input[hex_start..hex_start + len];
            let val = usize::from_str_radix(hex_str, 16)
                .map_err(|_| ParseError::Syntax(start, "invalid hex number".into()))?;
            return Ok(val);
        }

        let len = rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        if len == 0 {
            return Err(ParseError::Syntax(self.pos, "expected number".into()));
        }
        self.advance(len);
        let mut val: usize = self.input[start..start + len]
            .parse()
            .map_err(|_| ParseError::Syntax(start, "invalid number".into()))?;

        // Check for KB/MB/GB suffix with overflow protection
        self.skip_ws();
        let rest_after = self.remaining();
        if rest_after.starts_with("KB") || rest_after.starts_with("kb") {
            self.advance(2);
            val = val.checked_mul(1024)
                .ok_or_else(|| ParseError::Syntax(start, "size suffix overflow (KB)".into()))?;
        } else if rest_after.starts_with("MB") || rest_after.starts_with("mb") {
            self.advance(2);
            val = val.checked_mul(1024 * 1024)
                .ok_or_else(|| ParseError::Syntax(start, "size suffix overflow (MB)".into()))?;
        } else if rest_after.starts_with("GB") || rest_after.starts_with("gb") {
            self.advance(2);
            val = val.checked_mul(1024 * 1024 * 1024)
                .ok_or_else(|| ParseError::Syntax(start, "size suffix overflow (GB)".into()))?;
        }

        Ok(val)
    }

    fn read_count_identifier(&mut self) -> Result<String> {
        self.skip_ws();
        if !self.remaining().starts_with('#') {
            return Err(ParseError::Expected("#id".into(), self.peek_token_preview(), self.pos));
        }
        self.advance(1);
        let start = self.pos;
        // Allow $ prefix optionally: both #s and #$s
        if self.peek_char() == Some('$') {
            self.advance(1);
        }
        let rest = &self.input[self.pos..];
        let len = rest
            .char_indices()
            .find(|(_, c)| !c.is_alphanumeric() && *c != '_')
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        if len == 0 {
            return Err(ParseError::Syntax(self.pos, "empty count identifier".into()));
        }
        self.advance(len);
        let raw = &self.input[start..self.pos];
        // Normalize to $-prefixed
        if raw.starts_with('$') {
            Ok(raw.to_string())
        } else {
            Ok(format!("${}", raw))
        }
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode YARA-style escapes into the literal byte sequence to match.
/// `\xNN` yields the raw byte NN for any value (including >= 0x80); other
/// escapes and plain characters are pushed as their UTF-8 encoding.
fn unescape_string(s: &str) -> Vec<u8> {
    fn push_char(out: &mut Vec<u8>, c: char) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }

    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('0') => out.push(0),
                Some('x') => match (chars.next(), chars.next()) {
                    (Some(h), Some(l)) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                        let byte =
                            hex_digit(h as u8).unwrap() << 4 | hex_digit(l as u8).unwrap();
                        out.push(byte);
                    }
                    // Malformed \x escape: emit it literally.
                    (h, l) => {
                        out.push(b'\\');
                        out.push(b'x');
                        if let Some(h) = h {
                            push_char(&mut out, h);
                        }
                        if let Some(l) = l {
                            push_char(&mut out, l);
                        }
                    }
                },
                Some(other) => push_char(&mut out, other),
                None => out.push(b'\\'),
            }
        } else {
            push_char(&mut out, c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let input = r#"
        rule test_mz {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }
        "#;
        let rule = parse_rule(input).unwrap();
        assert_eq!(rule.name, "test_mz");
        assert_eq!(rule.strings.len(), 1);
        matches!(rule.condition, Condition::At(ref id, 0) if id == "$mz");
    }

    #[test]
    fn test_parse_text_string_with_modifiers() {
        let input = r#"
        rule test_str {
            strings:
                $s = "malware" nocase wide
            condition:
                any of them
        }
        "#;
        let rule = parse_rule(input).unwrap();
        assert!(rule.strings[0].modifiers.nocase);
        assert!(rule.strings[0].modifiers.wide);
    }

    #[test]
    fn test_unescape_hex_escapes() {
        let input = r#"
        rule hx {
            strings:
                $a = "\x41\x42"
                $b = "\xE9\xFF"
            condition:
                any of them
        }
        "#;
        let rule = parse_rule(input).unwrap();
        match &rule.strings[0].pattern {
            Pattern::Text(tp) => assert_eq!(tp.value, b"AB"),
            _ => panic!("expected text pattern"),
        }
        match &rule.strings[1].pattern {
            Pattern::Text(tp) => assert_eq!(tp.value, vec![0xE9, 0xFF]),
            _ => panic!("expected text pattern"),
        }
    }

    #[test]
    fn test_parse_hex_wildcards() {
        let input = r#"
        rule test_hex {
            strings:
                $h = { 4D 5A ?? 90 ?A B? }
            condition:
                all of them
        }
        "#;
        let rule = parse_rule(input).unwrap();
        if let Pattern::Hex(hex) = &rule.strings[0].pattern {
            assert_eq!(hex.tokens.len(), 6);
            assert_eq!(hex.tokens[0], HexToken::Literal(0x4D));
            assert_eq!(hex.tokens[2], HexToken::Wildcard);
            assert_eq!(
                hex.tokens[4],
                HexToken::NibbleWildcard {
                    mask: 0xF0,
                    value: 0x0A
                }
            );
            assert_eq!(
                hex.tokens[5],
                HexToken::NibbleWildcard {
                    mask: 0x0F,
                    value: 0xB0
                }
            );
        } else {
            panic!("expected hex pattern");
        }
    }

    #[test]
    fn test_parse_complex_condition() {
        let input = r#"
        rule complex {
            strings:
                $a = "foo"
                $b = "bar"
                $c = { CC CC }
            condition:
                ($a or $b) and #c > 2
        }
        "#;
        let rule = parse_rule(input).unwrap();
        assert!(matches!(rule.condition, Condition::And(_, _)));
    }

    #[test]
    fn test_parse_multiple_rules() {
        let input = r#"
        rule a { strings: $s = "x" condition: $s }
        rule b { strings: $s = "y" condition: $s }
        "#;
        let rules = parse_rules(input).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "a");
        assert_eq!(rules[1].name, "b");
    }

    #[test]
    fn test_int_expr_depth_limit() {
        let deep = format!("{}0{}", "uint8(".repeat(200), ")".repeat(200));
        let input = format!("rule r {{ condition: filesize < {} }}", deep);
        assert!(parse_rule(&input).is_err());

        let shallow = "rule r2 { condition: filesize < uint8(uint8(0)) }";
        assert!(parse_rule(shallow).is_ok());
    }

    #[test]
    fn test_preview_multibyte_no_panic() {
        let input = format!("rule r {{ strings: {} }}", "б".repeat(30));
        assert!(parse_rule(&input).is_err());
    }

    #[test]
    fn test_modifier_tokens_require_word_boundaries() {
        // `nocasewide` must NOT silently mean nocase + wide.
        let input = r#"
        rule glued_mods {
            strings:
                $s = "x" nocasewide
            condition:
                $s
        }
        "#;
        assert!(matches!(
            parse_rule(input),
            Err(ParseError::UnknownModifier(m, _)) if m == "nocasewide"
        ));

        for bad in ["widex", "ascii2", "fullwords", "nocaseee"] {
            let src = format!(
                "rule m {{ strings: $s = \"x\" {} condition: $s }}",
                bad
            );
            assert!(
                matches!(parse_rule(&src), Err(ParseError::UnknownModifier(_, _))),
                "'{}' should be rejected as an unknown modifier",
                bad
            );
        }
    }

    #[test]
    fn test_all_known_modifiers_parse_exactly() {
        let input = r#"
        rule mods {
            strings:
                $s = "x" nocase wide ascii fullword
            condition:
                $s
        }
        "#;
        let rule = parse_rule(input).unwrap();
        let m = &rule.strings[0].modifiers;
        assert!(m.nocase && m.wide && m.ascii && m.fullword);
    }

    #[test]
    fn test_modifier_list_stops_at_section_keyword() {
        let input = r#"
        rule stop_at_condition {
            strings:
                $s = "x" ascii
            condition:
                $s
        }
        "#;
        assert!(parse_rule(input).is_ok());
    }

    #[test]
    fn test_keywords_require_token_boundaries() {
        // Identifiers that merely start with a keyword must not be absorbed.
        let src = "rule k { condition: truexyy }";
        assert!(parse_rule(src).is_err());

        let src = "rule k { condition: falsepositive }";
        assert!(parse_rule(src).is_err());

        // `allofthem` is a single identifier in real YARA, not three tokens.
        let src = "rule k { condition: allofthem }";
        assert!(parse_rule(src).is_err());

        let src = "rule k { strings: $a = \"x\" condition: anyof ($a) }";
        assert!(parse_rule(src).is_err());
    }

    #[test]
    fn test_keyword_conditions_still_parse_with_boundaries() {
        for cond in ["true", "false", "all of them", "any of them", "1 of them"] {
            let src = format!("rule ok {{ strings: $a = \"x\" condition: {} }}", cond);
            assert!(parse_rule(&src).is_ok(), "'{}' should parse", cond);
        }

        let with_set = r#"
        rule set {
            strings:
                $a = "x"
                $b = "y"
            condition:
                all of ($a, $b)
        }
        "#;
        assert!(parse_rule(with_set).is_ok());
    }
}
