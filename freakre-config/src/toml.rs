//! Minimal TOML parser for config files.
//! Supports: tables, arrays, strings, integers, floats, booleans.
//! No datetime, no inline tables, no dotted keys.
//!
//! Duplicate root-level keys: last definition wins (replace policy).
//! A `[table]` header colliding with an already-defined non-table value
//! is a hard parse error (reported at the position where the conflict
//! is detected).

use crate::{ParseError, Value};

const MAX_DEPTH: usize = 64;

pub fn parse(input: &str) -> Result<Value, ParseError> {
    let mut p = Parser::new(input);
    p.parse_document()
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0, line: 1, col: 1 }
    }

    fn error(&self, msg: &str) -> ParseError {
        ParseError { message: msg.to_string(), line: self.line, col: self.col }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' { self.line += 1; self.col = 1; } else { self.col += 1; }
        Some(b)
    }

    fn skip_ws_no_newline(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) { self.advance(); }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            self.skip_ws_no_newline();
            if self.peek() == Some(b'#') {
                while let Some(b) = self.peek() {
                    self.advance();
                    if b == b'\n' { break; }
                }
            } else if self.peek() == Some(b'\n') || self.peek() == Some(b'\r') {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn parse_document(&mut self) -> Result<Value, ParseError> {
        let mut root = Vec::<(String, Value)>::new();
        let mut current_table_path: Vec<String> = Vec::new();
        let mut current_pairs: Vec<(String, Value)> = Vec::new();

        self.skip_ws_and_comments();

        while self.pos < self.input.len() {
            self.skip_ws_and_comments();
            if self.pos >= self.input.len() { break; }

            match self.peek() {
                Some(b'[') => {
                    // Save previous table
                    if !current_table_path.is_empty() || !current_pairs.is_empty() {
                        self.insert_table(&mut root, &current_table_path, Value::Object(current_pairs.clone()))?;
                        current_pairs.clear();
                    }
                    current_table_path = self.parse_table_header()?;
                }
                Some(_) => {
                    let (key, val) = self.parse_key_value()?;
                    current_pairs.push((key, val));
                    self.skip_ws_no_newline();
                    if self.peek() == Some(b'#') {
                        while let Some(b) = self.peek() {
                            self.advance();
                            if b == b'\n' { break; }
                        }
                    }
                }
                None => break,
            }
        }

        // Save last table
        if !current_table_path.is_empty() || !current_pairs.is_empty() {
            self.insert_table(&mut root, &current_table_path, Value::Object(current_pairs))?;
        }

        Ok(Value::Object(root))
    }

    fn insert_table(
        &mut self,
        root: &mut Vec<(String, Value)>,
        path: &[String],
        value: Value,
    ) -> Result<(), ParseError> {
        if path.is_empty() {
            // Root-level pairs: merge into root, last definition wins.
            if let Value::Object(pairs) = value {
                for (k, v) in pairs {
                    match root.iter_mut().find(|(ek, _)| *ek == k) {
                        Some(slot) => slot.1 = v,
                        None => root.push((k, v)),
                    }
                }
            }
            return Ok(());
        }

        let segment = &path[0];
        let is_last = path.len() == 1;

        if is_last {
            return match root.iter().position(|(k, _)| k == segment) {
                Some(pos) => match (&mut root[pos].1, value) {
                    (Value::Object(existing_pairs), Value::Object(new_pairs)) => {
                        for (k, v) in new_pairs {
                            match existing_pairs.iter_mut().find(|(ek, _)| *ek == k) {
                                Some(slot) => slot.1 = v,
                                None => existing_pairs.push((k, v)),
                            }
                        }
                        Ok(())
                    }
                    _ => Err(self.error(&format!(
                        "cannot redefine '{}' as a table: key already holds a value",
                        segment
                    ))),
                },
                None => {
                    root.push((segment.clone(), value));
                    Ok(())
                }
            };
        }

        // Navigate or create intermediate table
        let idx = match root.iter().position(|(k, _)| k == segment) {
            Some(pos) => pos,
            None => {
                root.push((segment.clone(), Value::Object(Vec::new())));
                root.len() - 1
            }
        };
        match root[idx].1 {
            Value::Object(ref mut child) => self.insert_table(child, &path[1..], value),
            _ => Err(self.error(&format!(
                "cannot extend '{}': key already holds a value",
                segment
            ))),
        }
    }

    fn parse_table_header(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect_byte(b'[')?;
        self.skip_ws_no_newline();
        let mut path = Vec::new();
        loop {
            let key = self.parse_bare_or_quoted_key()?;
            path.push(key);
            self.skip_ws_no_newline();
            if self.peek() == Some(b'.') {
                self.advance();
                self.skip_ws_no_newline();
            } else {
                break;
            }
        }
        self.skip_ws_no_newline();
        self.expect_byte(b']')?;
        Ok(path)
    }

    fn parse_key_value(&mut self) -> Result<(String, Value), ParseError> {
        let key = self.parse_bare_or_quoted_key()?;
        self.skip_ws_no_newline();
        self.expect_byte(b'=')?;
        self.skip_ws_no_newline();
        let val = self.parse_value(0)?;
        Ok((key, val))
    }

    fn parse_bare_or_quoted_key(&mut self) -> Result<String, ParseError> {
        if self.peek() == Some(b'"') {
            self.parse_basic_string()
        } else {
            self.parse_bare_key()
        }
    }

    fn parse_bare_key(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'A'..=b'Z') | Some(b'a'..=b'z') | Some(b'0'..=b'9') | Some(b'-') | Some(b'_')) {
            self.advance();
        }
        if self.pos == start {
            return Err(self.error("expected key"));
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn expect_byte(&mut self, ch: u8) -> Result<(), ParseError> {
        match self.advance() {
            Some(b) if b == ch => Ok(()),
            Some(b) => Err(self.error(&format!("expected '{}', got '{}'", ch as char, b as char))),
            None => Err(self.error(&format!("expected '{}', got EOF", ch as char))),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("max nesting depth exceeded"));
        }
        match self.peek() {
            Some(b'"') => self.parse_basic_string().map(Value::Str),
            Some(b'\'') => self.parse_literal_string().map(Value::Str),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'[') => self.parse_array(depth),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b) => Err(self.error(&format!("unexpected character '{}'", b as char))),
            None => Err(self.error("unexpected EOF")),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String, ParseError> {
        self.expect_byte(b'"')?;
        let mut s = String::new();
        loop {
            let seg_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' {
                    break;
                }
                self.advance();
            }
            if self.pos > seg_start {
                s.push_str(&self.input[seg_start..self.pos]);
            }
            match self.advance() {
                Some(b'"') => return Ok(s),
                Some(b'\\') => match self.advance() {
                    Some(b'n') => s.push('\n'),
                    Some(b't') => s.push('\t'),
                    Some(b'r') => s.push('\r'),
                    Some(b'\\') => s.push('\\'),
                    Some(b'"') => s.push('"'),
                    _ => return Err(self.error("invalid escape in string")),
                },
                _ => return Err(self.error("unterminated string")),
            }
        }
    }

    fn parse_literal_string(&mut self) -> Result<String, ParseError> {
        self.expect_byte(b'\'')?;
        let start = self.pos;
        loop {
            match self.advance() {
                Some(b'\'') => return Ok(self.input[start..self.pos - 1].to_string()),
                Some(_) => {}
                None => return Err(self.error("unterminated literal string")),
            }
        }
    }

    fn parse_bool(&mut self) -> Result<Value, ParseError> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4; self.col += 4;
            Ok(Value::Bool(true))
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5; self.col += 5;
            Ok(Value::Bool(false))
        } else {
            Err(self.error("invalid boolean"))
        }
    }

    fn parse_number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        let mut is_float = false;

        if self.peek() == Some(b'-') || self.peek() == Some(b'+') { self.advance(); }
        while matches!(self.peek(), Some(b'0'..=b'9') | Some(b'_')) { self.advance(); }

        if self.peek() == Some(b'.') {
            is_float = true;
            self.advance();
            while matches!(self.peek(), Some(b'0'..=b'9') | Some(b'_')) { self.advance(); }
        }

        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.advance();
            if matches!(self.peek(), Some(b'+') | Some(b'-')) { self.advance(); }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        }

        let raw: String = self.input[start..self.pos].chars().filter(|c| *c != '_').collect();
        if is_float {
            match raw.parse::<f64>() {
                Ok(f) if f.is_finite() => Ok(Value::Float(f)),
                Ok(_) => Err(self.error("float overflow")),
                Err(_) => Err(self.error("invalid float")),
            }
        } else {
            match raw.parse::<i64>() {
                Ok(n) => Ok(Value::Integer(n)),
                Err(_) => match raw.parse::<f64>() {
                    Ok(f) if f.is_finite() => Ok(Value::Float(f)),
                    _ => Err(self.error("invalid integer")),
                },
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect_byte(b'[')?;
        let mut arr = Vec::new();
        self.skip_ws_and_comments();
        if self.peek() == Some(b']') {
            self.advance();
            return Ok(Value::Array(arr));
        }
        loop {
            self.skip_ws_and_comments();
            arr.push(self.parse_value(depth + 1)?);
            self.skip_ws_and_comments();
            match self.peek() {
                Some(b',') => { self.advance(); }
                Some(b']') => { self.advance(); return Ok(Value::Array(arr)); }
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_toml() {
        let input = r#"
title = "Test"
debug = true
port = 8080

[database]
host = "localhost"
port = 5432
"#;
        let v = parse(input).unwrap();
        assert_eq!(v.get("title").and_then(|v| v.as_str()), Some("Test"));
        assert_eq!(v.get("debug").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(v.get("port").and_then(|v| v.as_i64()), Some(8080));
        let db = v.get("database").unwrap();
        assert_eq!(db.get("host").and_then(|v| v.as_str()), Some("localhost"));
        assert_eq!(db.get("port").and_then(|v| v.as_i64()), Some(5432));
    }

    #[test]
    fn test_parse_array() {
        let v = parse("items = [1, 2, 3]").unwrap();
        let arr = v.get("items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_utf8_basic_string() {
        let v = parse(r#"title = "Привет 🌍"
name = "naïve""#)
            .unwrap();
        assert_eq!(v.get("title").and_then(|v| v.as_str()), Some("Привет 🌍"));
        assert_eq!(v.get("name").and_then(|v| v.as_str()), Some("naïve"));
    }

    #[test]
    fn test_table_conflict_with_scalar() {
        let err = parse("a = 1\n[a]\nb = 2\n").unwrap_err();
        assert!(
            err.message.contains("already holds a value"),
            "unexpected error: {}",
            err
        );
        assert!(err.line >= 1 && err.col >= 1);
    }

    #[test]
    fn test_nested_table_conflict_with_scalar() {
        assert!(parse("a = 1\n[a.b]\nc = 2\n").is_err());
    }

    #[test]
    fn test_table_over_array_conflict() {
        assert!(parse("a = [1, 2]\n[a]\nb = 3\n").is_err());
    }

    #[test]
    fn test_duplicate_root_keys_last_wins() {
        let v = parse("x = 1\nx = 2\n").unwrap();
        assert_eq!(v.get("x").and_then(|v| v.as_i64()), Some(2));
        if let Value::Object(pairs) = &v {
            assert_eq!(pairs.iter().filter(|(k, _)| k == "x").count(), 1);
        } else {
            panic!("expected root object");
        }
    }

    #[test]
    fn test_repeated_table_header_merges_last_wins() {
        let v = parse("[t]\nk = 1\n\n[t]\nk = 2\nj = 3\n").unwrap();
        let t = v.get("t").unwrap();
        assert_eq!(t.get("k").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(t.get("j").and_then(|v| v.as_i64()), Some(3));
    }

    #[test]
    fn test_number_policies() {
        assert!(parse("big = 1e999").is_err());
        let v = parse("big = 9223372036854775808").unwrap();
        match v.get("big") {
            Some(Value::Float(f)) => assert_eq!(*f, 9223372036854775808.0),
            other => panic!("expected float fallback, got {:?}", other),
        }
    }
}
