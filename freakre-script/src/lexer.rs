//! Lexer for the sandbox DSL.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    Number(f64),
    Integer(i64),
    StringLit(String),
    True,
    False,
    Nil,

    // Identifiers & keywords
    Ident(String),
    Local,
    Function,
    End,
    If,
    Then,
    Elseif,
    Else,
    While,
    Do,
    For,
    In,
    Repeat,
    Until,
    Return,
    Break,
    And,
    Or,
    Not,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Hash,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    Assign, // =
    DotDot, // ..
    Dot,    // .
    Colon,  // :
    Comma,
    Semicolon,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,

    Eof,
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl core::fmt::Display for LexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Lex error at {}:{}: {}",
            self.line, self.col, self.message
        )
    }
}

impl std::error::Error for LexError {}

pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut pos = 0;
    let mut line = 1usize;
    let mut col = 1usize;

    while pos < bytes.len() {
        // Skip whitespace
        if bytes[pos] == b' ' || bytes[pos] == b'\t' || bytes[pos] == b'\r' {
            pos += 1;
            col += 1;
            continue;
        }
        if bytes[pos] == b'\n' {
            pos += 1;
            line += 1;
            col = 1;
            continue;
        }

        // Skip comments (-- to end of line)
        if pos + 1 < bytes.len() && bytes[pos] == b'-' && bytes[pos + 1] == b'-' {
            pos += 2;
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }

        let start_col = col;

        // Numbers
        if bytes[pos].is_ascii_digit()
            || (bytes[pos] == b'.' && pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_digit())
        {
            let start = pos;
            let mut is_float = false;
            if bytes[pos] == b'0'
                && pos + 1 < bytes.len()
                && (bytes[pos + 1] == b'x' || bytes[pos + 1] == b'X')
            {
                // Hex
                pos += 2;
                while pos < bytes.len() && (bytes[pos].is_ascii_hexdigit() || bytes[pos] == b'_') {
                    pos += 1;
                }
                let hex_str: String = input[start + 2..pos]
                    .chars()
                    .filter(|c| *c != '_')
                    .collect();
                let val = i64::from_str_radix(&hex_str, 16).map_err(|_| LexError {
                    message: "invalid hex number".into(),
                    line,
                    col: start_col,
                })?;
                tokens.push(Token::Integer(val));
                col += pos - start;
                continue;
            }
            while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'.' {
                is_float = true;
                pos += 1;
                while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
                    pos += 1;
                }
            }
            if pos < bytes.len() && (bytes[pos] == b'e' || bytes[pos] == b'E') {
                is_float = true;
                pos += 1;
                if pos < bytes.len() && (bytes[pos] == b'+' || bytes[pos] == b'-') {
                    pos += 1;
                }
                while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
            }
            let num_str: String = input[start..pos].chars().filter(|c| *c != '_').collect();
            if is_float {
                let val = num_str.parse::<f64>().map_err(|_| LexError {
                    message: "invalid float".into(),
                    line,
                    col: start_col,
                })?;
                tokens.push(Token::Number(val));
            } else {
                let val = num_str.parse::<i64>().map_err(|_| LexError {
                    message: "invalid integer".into(),
                    line,
                    col: start_col,
                })?;
                tokens.push(Token::Integer(val));
            }
            col += pos - start;
            continue;
        }

        // Strings
        if bytes[pos] == b'"' || bytes[pos] == b'\'' {
            let quote = bytes[pos];
            let start_pos = pos;
            pos += 1;
            // Collect raw content bytes; escapes expand to their byte values.
            // Non-ASCII sequences are preserved verbatim and decoded as UTF-8
            // at the end (byte-as-char casting produced mojibake).
            let mut buf: Vec<u8> = Vec::new();
            loop {
                if pos >= bytes.len() {
                    return Err(LexError {
                        message: "unterminated string".into(),
                        line,
                        col,
                    });
                }
                if bytes[pos] == quote {
                    pos += 1;
                    break;
                }
                if bytes[pos] == b'\\' {
                    pos += 1;
                    if pos >= bytes.len() {
                        return Err(LexError {
                            message: "unterminated escape".into(),
                            line,
                            col,
                        });
                    }
                    match bytes[pos] {
                        b'n' => buf.push(b'\n'),
                        b't' => buf.push(b'\t'),
                        b'r' => buf.push(b'\r'),
                        b'\\' => buf.push(b'\\'),
                        b'"' => buf.push(b'"'),
                        b'\'' => buf.push(b'\''),
                        b'0' => buf.push(0),
                        other => {
                            buf.push(b'\\');
                            buf.push(other);
                        }
                    }
                } else {
                    buf.push(bytes[pos]);
                }
                pos += 1;
            }
            let s = String::from_utf8_lossy(&buf).into_owned();
            tokens.push(Token::StringLit(s));
            col += pos - start_pos; // approximate (bytes, not display width)
            continue;
        }

        // Identifiers and keywords
        if bytes[pos].is_ascii_alphabetic() || bytes[pos] == b'_' {
            let start = pos;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
            let word = &input[start..pos];
            let tok = match word {
                "local" => Token::Local,
                "function" => Token::Function,
                "end" => Token::End,
                "if" => Token::If,
                "then" => Token::Then,
                "elseif" => Token::Elseif,
                "else" => Token::Else,
                "while" => Token::While,
                "do" => Token::Do,
                "for" => Token::For,
                "in" => Token::In,
                "repeat" => Token::Repeat,
                "until" => Token::Until,
                "return" => Token::Return,
                "break" => Token::Break,
                "and" => Token::And,
                "or" => Token::Or,
                "not" => Token::Not,
                "true" => Token::True,
                "false" => Token::False,
                "nil" => Token::Nil,
                _ => Token::Ident(word.to_string()),
            };
            tokens.push(tok);
            col += pos - start;
            continue;
        }

        // Operators and punctuation
        let tok = match bytes[pos] {
            b'+' => Token::Plus,
            b'-' => Token::Minus,
            b'*' => Token::Star,
            b'/' => Token::Slash,
            b'%' => Token::Percent,
            b'^' => Token::Caret,
            b'#' => Token::Hash,
            b'(' => Token::LParen,
            b')' => Token::RParen,
            b'[' => Token::LBracket,
            b']' => Token::RBracket,
            b'{' => Token::LBrace,
            b'}' => Token::RBrace,
            b',' => Token::Comma,
            b';' => Token::Semicolon,
            b':' => Token::Colon,
            b'.' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'.' {
                    pos += 1;
                    Token::DotDot
                } else {
                    Token::Dot
                }
            }
            b'=' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    pos += 1;
                    Token::Eq
                } else {
                    Token::Assign
                }
            }
            b'~' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    pos += 1;
                    Token::Neq
                } else {
                    return Err(LexError {
                        message: "unexpected char '~'".to_string(),
                        line,
                        col,
                    });
                }
            }
            b'<' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    pos += 1;
                    Token::Lte
                } else {
                    Token::Lt
                }
            }
            b'>' => {
                if pos + 1 < bytes.len() && bytes[pos + 1] == b'=' {
                    pos += 1;
                    Token::Gte
                } else {
                    Token::Gt
                }
            }
            c => {
                return Err(LexError {
                    message: format!("unexpected char '{}'", c as char),
                    line,
                    col,
                });
            }
        };
        tokens.push(tok);
        pos += 1;
        col += 1;
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tokens() {
        let tokens = tokenize("local x = 42").unwrap();
        assert_eq!(tokens[0], Token::Local);
        assert_eq!(tokens[1], Token::Ident("x".into()));
        assert_eq!(tokens[2], Token::Assign);
        assert_eq!(tokens[3], Token::Integer(42));
    }

    #[test]
    fn test_string() {
        let tokens = tokenize("\"hello\\nworld\"").unwrap();
        assert_eq!(tokens[0], Token::StringLit("hello\nworld".into()));
    }

    #[test]
    fn test_non_ascii_string() {
        // Audit #6: bytes must decode as UTF-8, not byte-as-char mojibake.
        let tokens = tokenize("'привет мир'").unwrap();
        assert_eq!(tokens[0], Token::StringLit("привет мир".into()));

        let tokens = tokenize("\"日本語\\nテスト\"").unwrap();
        assert_eq!(tokens[0], Token::StringLit("日本語\nテスト".into()));
    }

    #[test]
    fn test_comment_skip() {
        let tokens = tokenize("x -- comment\ny").unwrap();
        assert_eq!(tokens[0], Token::Ident("x".into()));
        assert_eq!(tokens[1], Token::Ident("y".into()));
    }
}
