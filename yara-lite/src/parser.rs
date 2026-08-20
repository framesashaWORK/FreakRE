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
        let end = r
            .find(|c: char| c.is_whitespace() || c == '{' || c == '}' || c == ':')
            .unwrap_or(r.len())
            .min(20);
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
                    let value = self.input[start..self.pos].to_string();
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
            let rest = self.remaining();
            if rest.starts_with("nocase") {
                mods.nocase = true;
                self.advance(6);
            } else if rest.starts_with("wide") {
                mods.wide = true;
                self.advance(4);
            } else if rest.starts_with("ascii") {
                mods.ascii = true;
                self.advance(5);
            } else if rest.starts_with("fullword") {
                mods.fullword = true;
                self.advance(8);
            } else {
                break;
            }
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

        // Boolean literals
        if self.remaining().starts_with("true") {
            self.advance(4);
            return Ok(Condition::Bool(true));
        }
        if self.remaining().starts_with("false") {
            self.advance(5);
            return Ok(Condition::Bool(false));
        }

        // N of them / all of them / any of them
        if self.remaining().starts_with("all") || self.remaining().starts_with("any") {
            return self.parse_of_them();
        }
        if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            // Could be "N of them" or integer literal
            let saved = self.pos;
            let num = self.read_usize()?;
            self.skip_ws();
            if self.remaining().starts_with("of") {
                self.advance(2);
                return self.parse_of_suffix(OfKind::Exactly(num));
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
            if self.remaining().starts_with("at") {
                self.advance(2);
                let offset = self.read_usize()?;
                return Ok(Condition::At(id, offset));
            }
            if self.remaining().starts_with("in") {
                self.advance(2);
                self.expect_char('(')?;
                let start = self.read_usize()?;
                self.skip_ws();
                self.expect_char('.')?;
                self.expect_char('.')?;
                let end = self.read_usize()?;
                self.expect_char(')')?;
                return Ok(Condition::In(id, start, end));
            }
            return Ok(Condition::StringMatch(id));
        }

        // filesize comparison
        if self.remaining().starts_with("filesize") {
            self.advance(8);
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

        Err(ParseError::Syntax(
            self.pos,
            format!("unexpected token: {}", self.peek_token_preview()),
        ))
    }

    fn parse_of_them(&mut self) -> Result<Condition> {
        let kind = if self.remaining().starts_with("all") {
            self.advance(3);
            OfKind::All
        } else {
            self.advance(3); // "any"
            OfKind::Any
        };
        self.skip_ws();
        self.expect_keyword("of")?;
        self.skip_ws();
        if self.remaining().starts_with("them") {
            self.advance(4);
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

    fn parse_of_suffix(&mut self, kind: OfKind) -> Result<Condition> {
        self.skip_ws();
        if self.remaining().starts_with("them") {
            self.advance(4);
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
        self.skip_ws();

        // Parenthesized integer expression
        if self.peek_char() == Some('(') {
            self.advance(1);
            let inner = self.parse_int_expr()?;
            self.expect_char(')')?;
            return Ok(inner);
        }

        if self.peek_char() == Some('#') {
            let id = self.read_count_identifier()?;
            Ok(IntExpr::Count(id))
        } else if self.remaining().starts_with("filesize") {
            self.advance(8);
            Ok(IntExpr::Filesize)
        } else if self.remaining().starts_with("entrypoint") {
            self.advance(10);
            Ok(IntExpr::Entrypoint)
        } else if self.remaining().starts_with("uint8(") {
            self.advance(6);
            let offset = self.parse_int_expr()?;
            self.expect_char(')')?;
            Ok(IntExpr::Uint8(Box::new(offset)))
        } else if self.remaining().starts_with("uint16(") {
            self.advance(7);
            let offset = self.parse_int_expr()?;
            self.expect_char(')')?;
            Ok(IntExpr::Uint16(Box::new(offset)))
        } else if self.remaining().starts_with("uint32(") {
            self.advance(7);
            let offset = self.parse_int_expr()?;
            self.expect_char(')')?;
            Ok(IntExpr::Uint32(Box::new(offset)))
        } else if self.peek_char().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            let n = self.read_usize()?;
            Ok(IntExpr::Literal(n))
        } else {
            Err(ParseError::Syntax(
                self.pos,
                format!("expected integer expression, got '{}'", self.peek_token_preview()),
            ))
        }
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
            val = val.checked_mul(1024usize.checked_mul(1024).unwrap().checked_mul(1024).unwrap())
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

fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('0') => out.push('\0'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
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
            assert_eq!(hex.tokens.len(), 5);
            assert_eq!(hex.tokens[0], HexToken::Literal(0x4D));
            assert_eq!(hex.tokens[2], HexToken::Wildcard);
            assert_eq!(
                hex.tokens[3],
                HexToken::NibbleWildcard {
                    mask: 0xF0,
                    value: 0x0A
                }
            );
            assert_eq!(
                hex.tokens[4],
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
}
