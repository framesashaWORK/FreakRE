//! Recursive descent parser for the sandbox DSL.

use crate::lexer::Token;
use crate::ast::*;

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Parse error: {}", self.message)
    }
}

impl std::error::Error for ParseError {}

const MAX_DEPTH: usize = 256;

pub fn parse(tokens: &[Token]) -> Result<Vec<Stmt>, ParseError> {
    let mut p = Parser { tokens, pos: 0, depth: 0, loop_depth: 0 };
    p.parse_block()
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    depth: usize,
    /// Tracks enclosing loop nesting within the current function body.
    /// Reset to 0 when a function body is parsed so `break` cannot be
    /// compiled outside a loop (prevents cross-function control flow).
    loop_depth: usize,
}

impl<'a> Parser<'a> {
    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError { message: "maximum nesting depth exceeded".into() });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn peek_at(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        let tok = self.advance();
        if core::mem::discriminant(&tok) == core::mem::discriminant(expected) {
            Ok(())
        } else {
            Err(ParseError { message: format!("expected {:?}, got {:?}", expected, tok) })
        }
    }

    fn at_end(&self) -> bool {
        matches!(self.peek(), Token::Eof | Token::End | Token::Else | Token::Elseif | Token::Until)
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.enter()?;
        let result = self.parse_block_inner();
        self.leave();
        result
    }

    fn parse_block_inner(&mut self) -> Result<Vec<Stmt>, ParseError> {
        let mut stmts = Vec::new();
        while !self.at_end() {
            // Skip semicolons
            if matches!(self.peek(), Token::Semicolon) {
                self.advance();
                continue;
            }
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek().clone() {
            Token::Local => self.parse_local(),
            Token::If => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::Return => self.parse_return(),
            Token::Break => {
                self.advance();
                // Compile-time check: break must be enclosed by a loop in the
                // SAME function body (loop_depth resets at function bodies).
                if self.loop_depth == 0 {
                    return Err(ParseError { message: "break outside loop".into() });
                }
                Ok(Stmt::Break)
            }
            Token::Function => self.parse_func_def(),
            _ => {
                let expr = self.parse_expr()?;
                // Check for assignment
                if matches!(self.peek(), Token::Assign) {
                    self.advance();
                    let value = self.parse_expr()?;
                    Ok(Stmt::Assign { target: expr, value })
                } else {
                    Ok(Stmt::ExprStmt(expr))
                }
            }
        }
    }

    fn parse_local(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'local'
        if matches!(self.peek(), Token::Function) {
            return self.parse_func_def();
        }
        let name = match self.advance() {
            Token::Ident(n) => n,
            other => return Err(ParseError { message: format!("expected identifier after 'local', got {:?}", other) }),
        };
        let value = if matches!(self.peek(), Token::Assign) {
            self.advance();
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Stmt::LocalAssign { name, value })
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'if'
        let cond = self.parse_expr()?;
        self.expect(&Token::Then)?;
        let then_body = self.parse_block()?;

        let mut elseifs = Vec::new();
        while matches!(self.peek(), Token::Elseif) {
            self.advance();
            let econd = self.parse_expr()?;
            self.expect(&Token::Then)?;
            let ebody = self.parse_block()?;
            elseifs.push((econd, ebody));
        }

        let else_body = if matches!(self.peek(), Token::Else) {
            self.advance();
            Some(self.parse_block()?)
        } else {
            None
        };

        self.expect(&Token::End)?;
        Ok(Stmt::If { cond, then_body, elseifs, else_body })
    }

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'while'
        let cond = self.parse_expr()?;
        self.expect(&Token::Do)?;
        self.loop_depth += 1;
        let body = self.parse_block();
        self.loop_depth -= 1;
        let body = body?;
        self.expect(&Token::End)?;
        Ok(Stmt::While { cond, body })
    }

    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'for'
        let var = match self.advance() {
            Token::Ident(n) => n,
            other => return Err(ParseError { message: format!("expected var name in for, got {:?}", other) }),
        };
        self.expect(&Token::Assign)?;
        let start = self.parse_expr()?;
        self.expect(&Token::Comma)?;
        let stop = self.parse_expr()?;
        let step = if matches!(self.peek(), Token::Comma) {
            self.advance();
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(&Token::Do)?;
        self.loop_depth += 1;
        let body = self.parse_block();
        self.loop_depth -= 1;
        let body = body?;
        self.expect(&Token::End)?;
        Ok(Stmt::ForNumeric { var, start, stop, step, body })
    }

    fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'return'
        let mut values = Vec::new();
        if !self.at_end() && !matches!(self.peek(), Token::Semicolon) {
            values.push(self.parse_expr()?);
            while matches!(self.peek(), Token::Comma) {
                self.advance();
                values.push(self.parse_expr()?);
            }
        }
        Ok(Stmt::Return { values })
    }

    fn parse_func_def(&mut self) -> Result<Stmt, ParseError> {
        self.advance(); // consume 'function' or already consumed 'local'
        let name = match self.advance() {
            Token::Ident(n) => n,
            other => return Err(ParseError { message: format!("expected function name, got {:?}", other) }),
        };
        self.expect(&Token::LParen)?;
        let mut params = Vec::new();
        if !matches!(self.peek(), Token::RParen) {
            if let Token::Ident(p) = self.advance() {
                params.push(p);
            }
            while matches!(self.peek(), Token::Comma) {
                self.advance();
                if let Token::Ident(p) = self.advance() {
                    params.push(p);
                }
            }
        }
        self.expect(&Token::RParen)?;
        // Function bodies are loop boundaries: `break` inside a function can
        // never target a loop in the calling function.
        let saved_loop_depth = self.loop_depth;
        self.loop_depth = 0;
        let body = self.parse_block();
        self.loop_depth = saved_loop_depth;
        let body = body?;
        self.expect(&Token::End)?;
        Ok(Stmt::FuncDef { name, params, body })
    }

    // ── Expression parsing (precedence climbing) ──────────────────

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let result = self.parse_or();
        self.leave();
        result
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp { left: Box::new(left), op: BinOp::Or, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_comparison()?;
        while matches!(self.peek(), Token::And) {
            self.advance();
            let right = self.parse_comparison()?;
            left = Expr::BinOp { left: Box::new(left), op: BinOp::And, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_concat()?;
        loop {
            let op = match self.peek() {
                Token::Eq => BinOp::Eq,
                Token::Neq => BinOp::Neq,
                Token::Lt => BinOp::Lt,
                Token::Gt => BinOp::Gt,
                Token::Lte => BinOp::Lte,
                Token::Gte => BinOp::Gte,
                _ => break,
            };
            self.advance();
            let right = self.parse_concat()?;
            left = Expr::BinOp { left: Box::new(left), op, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_concat(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_additive()?;
        while matches!(self.peek(), Token::DotDot) {
            self.advance();
            let right = self.parse_additive()?;
            left = Expr::BinOp { left: Box::new(left), op: BinOp::Concat, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_multiplicative()?;
            left = Expr::BinOp { left: Box::new(left), op, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                Token::Percent => BinOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::BinOp { left: Box::new(left), op, right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let result = self.parse_unary_inner();
        self.leave();
        result
    }

    fn parse_unary_inner(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Token::Minus => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::UnOp { op: UnOp::Neg, operand: Box::new(operand) })
            }
            Token::Not => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::UnOp { op: UnOp::Not, operand: Box::new(operand) })
            }
            Token::Hash => {
                self.advance();
                let operand = self.parse_unary()?;
                Ok(Expr::UnOp { op: UnOp::Len, operand: Box::new(operand) })
            }
            _ => self.parse_pow(),
        }
    }

    /// Exponentiation: right-associative and binding tighter than unary
    /// minus (Lua semantics): `-2^2 == -(2^2)`, `2^3^2 == 2^(3^2)`.
    fn parse_pow(&mut self) -> Result<Expr, ParseError> {
        let base = self.parse_postfix()?;
        if matches!(self.peek(), Token::Caret) {
            self.advance();
            let exp = self.parse_pow()?;
            Ok(Expr::BinOp { left: Box::new(base), op: BinOp::Pow, right: Box::new(exp) })
        } else {
            Ok(base)
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek() {
                Token::LParen => {
                    self.advance();
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Token::RParen) {
                        args.push(self.parse_expr()?);
                        while matches!(self.peek(), Token::Comma) {
                            self.advance();
                            args.push(self.parse_expr()?);
                        }
                    }
                    self.expect(&Token::RParen)?;
                    expr = Expr::Call { func: Box::new(expr), args };
                }
                Token::LBracket => {
                    self.advance();
                    let key = self.parse_expr()?;
                    self.expect(&Token::RBracket)?;
                    expr = Expr::Index { table: Box::new(expr), key: Box::new(key) };
                }
                Token::Dot => {
                    self.advance();
                    let name = match self.advance() {
                        Token::Ident(n) => n,
                        other => return Err(ParseError { message: format!("expected field name, got {:?}", other) }),
                    };
                    expr = Expr::Field { table: Box::new(expr), name };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.advance() {
            Token::Nil => Ok(Expr::Nil),
            Token::True => Ok(Expr::Bool(true)),
            Token::False => Ok(Expr::Bool(false)),
            Token::Integer(n) => Ok(Expr::Integer(n)),
            Token::Number(n) => Ok(Expr::Number(n)),
            Token::StringLit(s) => Ok(Expr::StringLit(s)),
            Token::Ident(name) => Ok(Expr::Ident(name)),
            Token::LParen => {
                let expr = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }
            Token::LBrace => {
                let mut entries = Vec::new();
                if !matches!(self.peek(), Token::RBrace) {
                    entries.push(self.parse_table_entry()?);
                    while matches!(self.peek(), Token::Comma | Token::Semicolon) {
                        self.advance();
                        if matches!(self.peek(), Token::RBrace) { break; }
                        entries.push(self.parse_table_entry()?);
                    }
                }
                self.expect(&Token::RBrace)?;
                Ok(Expr::Table(entries))
            }
            other => Err(ParseError { message: format!("unexpected token {:?}", other) }),
        }
    }

    /// One entry of a table constructor.
    ///
    /// `name = value` stores the key as a literal string — the name is NOT an
    /// expression to evaluate (evaluating it as `Expr::Ident` produced
    /// UndefinedVariable or looked up the wrong key). Positional elements are
    /// stored with a None key and get sequential integer indices.
    fn parse_table_entry(&mut self) -> Result<(Option<Expr>, Expr), ParseError> {
        // Lookahead: `Ident =` marks a named key, not an assignment expression.
        if let (Token::Ident(name), Token::Assign) = (self.peek().clone(), self.peek_at(1).clone()) {
            self.advance(); // consume Ident
            self.advance(); // consume '='
            let val = self.parse_expr()?;
            return Ok((Some(Expr::StringLit(name)), val));
        }
        let expr = self.parse_expr()?;
        if matches!(self.peek(), Token::Assign) {
            // `[k] = v` general form is not part of this grammar.
            return Err(ParseError { message: "invalid table key: only 'name = value' names keys".into() });
        }
        Ok((None, expr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    #[test]
    fn test_parse_assignment() {
        let tokens = tokenize("x = 42").unwrap();
        let stmts = parse(&tokens).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_if() {
        let tokens = tokenize("if x > 0 then y = 1 else y = 0 end").unwrap();
        let stmts = parse(&tokens).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_function_call() {
        let tokens = tokenize("print(x + 1)").unwrap();
        let stmts = parse(&tokens).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_table_named_keys_are_literals() {
        // Audit #3: `name` in {name = value} is a string key, not an Ident.
        let tokens = tokenize("local t = {a = 1, 5, b = 'x'}").unwrap();
        let stmts = parse(&tokens).unwrap();
        match &stmts[0] {
            Stmt::LocalAssign { value: Some(Expr::Table(entries)), .. } => {
                assert_eq!(entries.len(), 3);
                assert!(matches!(&entries[0].0, Some(Expr::StringLit(s)) if s == "a"));
                assert!(entries[1].0.is_none());
                assert!(matches!(&entries[2].0, Some(Expr::StringLit(s)) if s == "b"));
            }
            other => panic!("expected table constructor, got {:?}", other),
        }
    }

    #[test]
    fn test_caret_precedence() {
        // Audit #4: ^ right-assoc, binds tighter than unary minus.
        fn expr_of(src: &str) -> Expr {
            let tokens = tokenize(src).unwrap();
            match parse(&tokens).unwrap().remove(0) {
                Stmt::ExprStmt(e) => e,
                other => panic!("expected expr stmt, got {:?}", other),
            }
        }

        // -2^2 == -(2^2)
        match expr_of("-2^2") {
            Expr::UnOp { op: UnOp::Neg, operand } => {
                assert!(matches!(*operand, Expr::BinOp { op: BinOp::Pow, .. }));
            }
            other => panic!("expected negated pow, got {:?}", other),
        }

        // 2^3^2 == 2^(3^2): right operand of the outer pow is itself a pow.
        match expr_of("2^3^2") {
            Expr::BinOp { op: BinOp::Pow, right, .. } => {
                assert!(matches!(*right, Expr::BinOp { op: BinOp::Pow, .. }));
            }
            other => panic!("expected pow, got {:?}", other),
        }
    }

    #[test]
    fn test_break_outside_loop_rejected() {
        for src in ["break", "function f() break end", "if true then break end"] {
            let tokens = tokenize(src).unwrap();
            let err = parse(&tokens).unwrap_err();
            assert!(err.message.contains("break outside loop"), "src: {}", src);
        }
    }

    #[test]
    fn test_break_inside_loop_accepted() {
        let tokens = tokenize("while true do if x then break end end").unwrap();
        assert!(parse(&tokens).is_ok());
    }
}
