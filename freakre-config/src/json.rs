//! Minimal recursive-descent JSON parser. Strict mode, depth-limited.
//!
//! Duplicate object keys: last definition wins (earlier entries replaced).
//! Numbers: integer literals outside i64 range fall back to f64; float
//! literals that overflow to infinity are a parse error.

use crate::{ParseError, Value};

const MAX_DEPTH: usize = 128;

pub fn parse(input: &str) -> Result<Value, ParseError> {
    let mut p = Parser::new(input);
    let val = p.parse_value(0)?;
    p.skip_ws();
    if p.pos < p.input.len() {
        return Err(p.error("trailing data after JSON value"));
    }
    Ok(val)
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
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, ch: u8) -> Result<(), ParseError> {
        self.skip_ws();
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
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(Value::Str),
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b) => Err(self.error(&format!("unexpected character '{}'", b as char))),
            None => Err(self.error("unexpected EOF")),
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut s = String::new();
        loop {
            let seg_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
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
                    Some(b'"') => s.push('"'),
                    Some(b'\\') => s.push('\\'),
                    Some(b'/') => s.push('/'),
                    Some(b'b') => s.push('\u{0008}'),
                    Some(b'f') => s.push('\u{000C}'),
                    Some(b'n') => s.push('\n'),
                    Some(b'r') => s.push('\r'),
                    Some(b't') => s.push('\t'),
                    Some(b'u') => {
                        let cp = self.parse_hex4()?;
                        // Handle surrogate pairs
                        if (0xD800..=0xDBFF).contains(&cp) {
                            self.expect(b'\\')?;
                            self.expect(b'u')?;
                            let lo = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err(self.error("invalid surrogate pair"));
                            }
                            let combined = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            s.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                        } else {
                            s.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                    }
                    _ => return Err(self.error("invalid escape sequence")),
                },
                Some(_) => return Err(self.error("control character in string")),
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, ParseError> {
        let mut val = 0u32;
        for _ in 0..4 {
            let b = self.advance().ok_or_else(|| self.error("unexpected EOF in hex escape"))?;
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(self.error("invalid hex digit")),
            };
            val = val * 16 + digit as u32;
        }
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        let mut is_float = false;

        if self.peek() == Some(b'-') { self.advance(); }
        if self.peek() == Some(b'0') {
            self.advance();
        } else if matches!(self.peek(), Some(b'1'..=b'9')) {
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        } else {
            return Err(self.error("invalid number"));
        }

        if self.peek() == Some(b'.') {
            is_float = true;
            self.advance();
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("expected digit after decimal point"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        }

        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.advance();
            if matches!(self.peek(), Some(b'+') | Some(b'-')) { self.advance(); }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("expected digit in exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.advance(); }
        }

        let num_str = &self.input[start..self.pos];
        if is_float {
            match num_str.parse::<f64>() {
                Ok(f) if f.is_finite() => Ok(Value::Float(f)),
                Ok(_) => Err(self.error("float overflow")),
                Err(_) => Err(self.error("invalid float")),
            }
        } else {
            match num_str.parse::<i64>() {
                Ok(n) => Ok(Value::Integer(n)),
                Err(_) => match num_str.parse::<f64>() {
                    Ok(f) if f.is_finite() => Ok(Value::Float(f)),
                    _ => Err(self.error("invalid integer")),
                },
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

    fn parse_null(&mut self) -> Result<Value, ParseError> {
        if self.input[self.pos..].starts_with("null") {
            self.pos += 4; self.col += 4;
            Ok(Value::Null)
        } else {
            Err(self.error("invalid null"))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.advance();
            return Ok(Value::Array(arr));
        }
        loop {
            arr.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => { self.advance(); }
                Some(b']') => { self.advance(); return Ok(Value::Array(arr)); }
                _ => return Err(self.error("expected ',' or ']' in array")),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.advance();
            return Ok(Value::Object(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.expect(b':')?;
            let val = self.parse_value(depth + 1)?;
            match pairs.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = val,
                None => pairs.push((key, val)),
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => { self.advance(); }
                Some(b'}') => { self.advance(); return Ok(Value::Object(pairs)); }
                _ => return Err(self.error("expected ',' or '}' in object")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let v = parse(r#"{"name": "test", "count": 42, "active": true}"#).unwrap();
        assert_eq!(v.get("name").and_then(|v| v.as_str()), Some("test"));
        assert_eq!(v.get("count").and_then(|v| v.as_i64()), Some(42));
        assert_eq!(v.get("active").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_parse_nested() {
        let v = parse(r#"{"a": [1, 2, {"b": "c"}]}"#).unwrap();
        let arr = v.get("a").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_parse_escapes() {
        let v = parse(r#""hello\nworld\t\"""#).unwrap();
        assert_eq!(v.as_str(), Some("hello\nworld\t\""));
    }

    #[test]
    fn test_depth_limit() {
        let deep = format!("{}42{}", "[".repeat(200), "]".repeat(200));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn test_utf8_strings() {
        let v = parse(r#"{"ru": "Привет мир", "emoji": "🚀🌍", "mixed": "café ü"}"#).unwrap();
        assert_eq!(v.get("ru").and_then(|v| v.as_str()), Some("Привет мир"));
        assert_eq!(v.get("emoji").and_then(|v| v.as_str()), Some("🚀🌍"));
        assert_eq!(v.get("mixed").and_then(|v| v.as_str()), Some("café ü"));
    }

    #[test]
    fn test_utf8_escapes_and_surrogate_pair() {
        let v = parse(r#""кир😀""#).unwrap();
        assert_eq!(v.as_str(), Some("кир\u{1F600}"));
    }

    #[test]
    fn test_duplicate_keys_last_wins() {
        let v = parse(r#"{"a": 1, "b": {"x": 1}, "a": 2, "b": {"y": 2}}"#).unwrap();
        assert_eq!(v.get("a").and_then(|v| v.as_i64()), Some(2));
        let b = v.get("b").unwrap();
        assert!(b.get("x").is_none());
        assert_eq!(b.get("y").and_then(|v| v.as_i64()), Some(2));
    }

    #[test]
    fn test_big_int_falls_back_to_float() {
        let v = parse("9223372036854775808").unwrap();
        match v {
            Value::Float(f) => assert_eq!(f, 9223372036854775808.0),
            other => panic!("expected float fallback, got {:?}", other),
        }
        match parse("-9223372036854775809").unwrap() {
            Value::Float(f) => assert_eq!(f, -9223372036854775809.0),
            other => panic!("expected float fallback, got {:?}", other),
        }
    }

    #[test]
    fn test_float_overflow_is_error() {
        assert!(parse("1e999").is_err());
        assert!(parse("-1e999").is_err());
        assert!(parse("1e308").is_ok());
        assert!(parse("-1.5e308").is_ok());
    }
}
