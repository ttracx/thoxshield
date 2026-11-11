// Minimal order-preserving JSON parser/serializer. Enough for Safetensors
// headers (objects, arrays, strings, numbers, bools, null). Numbers are kept
// as raw literals so tensor offsets/sizes round-trip byte-exact in value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

pub struct Parser<'a> { b: &'a [u8], i: usize }
impl<'a> Parser<'a> {
    pub fn parse(text: &'a str) -> Result<Json, String> {
        let mut p = Parser { b: text.as_bytes(), i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() { return Err(format!("trailing bytes at {}", p.i)); }
        Ok(v)
    }
    fn ws(&mut self) { while self.i < self.b.len() && matches!(self.b[self.i], b' '|b'\t'|b'\n'|b'\r') { self.i += 1; } }
    fn peek(&self) -> Option<u8> { self.b.get(self.i).copied() }
    fn value(&mut self) -> Result<Json, String> {
        match self.peek().ok_or("eof")? {
            b'{' => {
                self.i += 1; let mut out = Vec::new(); self.ws();
                if self.peek() == Some(b'}') { self.i += 1; return Ok(Json::Obj(out)); }
                loop {
                    self.ws(); let k = match self.value()? { Json::Str(s) => s, _ => return Err("object key must be string".into()) };
                    self.ws(); if self.peek() != Some(b':') { return Err("expected ':'".into()); } self.i += 1; self.ws();
                    let v = self.value()?; out.push((k, v)); self.ws();
                    match self.peek() { Some(b',') => { self.i += 1; } Some(b'}') => { self.i += 1; break; } _ => return Err("expected ',' or '}'".into()) }
                }
                Ok(Json::Obj(out))
            }
            b'[' => {
                self.i += 1; let mut out = Vec::new(); self.ws();
                if self.peek() == Some(b']') { self.i += 1; return Ok(Json::Arr(out)); }
                loop {
                    self.ws(); out.push(self.value()?); self.ws();
                    match self.peek() { Some(b',') => { self.i += 1; } Some(b']') => { self.i += 1; break; } _ => return Err("expected ',' or ']'".into()) }
                }
                Ok(Json::Arr(out))
            }
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => { self.lit("true")?; Ok(Json::Bool(true)) }
            b'f' => { self.lit("false")?; Ok(Json::Bool(false)) }
            b'n' => { self.lit("null")?; Ok(Json::Null) }
            _ => {
                let start = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'0'..=b'9'|b'-'|b'+'|b'.'|b'e'|b'E') { self.i += 1; }
                if start == self.i { return Err(format!("unexpected byte at {}", self.i)); }
                Ok(Json::Num(String::from_utf8_lossy(&self.b[start..self.i]).into_owned()))
            }
        }
    }
    fn lit(&mut self, s: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(s.as_bytes()) { self.i += s.len(); Ok(()) } else { Err(format!("bad literal at {}", self.i)) }
    }
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') { return Err("expected string".into()); }
        self.i += 1; let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?; self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?; self.i += 1;
                    match e {
                        b'"' => out.push('"'), b'\\' => out.push('\\'), b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'), b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'), b'r' => out.push('\r'), b't' => out.push('\t'),
                        b'u' => {
                            let hex = |p: &mut Self| -> Result<u32, String> {
                                let s = p.b.get(p.i..p.i+4).ok_or("bad \\u")?;
                                let v = u32::from_str_radix(std::str::from_utf8(s).map_err(|_| "bad \\u")?, 16).map_err(|_| "bad \\u")?;
                                p.i += 4; Ok(v)
                            };
                            let mut cp = hex(self)?;
                            if (0xD800..0xDC00).contains(&cp)
                                && self.b.get(self.i) == Some(&b'\\') && self.b.get(self.i+1) == Some(&b'u') {
                                    self.i += 2; let lo = hex(self)?;
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                }
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // Reassemble UTF-8 by collecting the raw byte run up to the next quote/backslash.
                    let start = self.i - 1; let mut end = self.i;
                    while end < self.b.len() && !matches!(self.b[end], b'"'|b'\\') { end += 1; }
                    out.push_str(&String::from_utf8_lossy(&self.b[start..end]));
                    self.i = end;
                }
            }
        }
        Ok(out)
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"'); out
}

pub fn stringify(v: &Json) -> String {
    match v {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => n.clone(),
        Json::Str(s) => escape(s),
        Json::Arr(a) => format!("[{}]", a.iter().map(stringify).collect::<Vec<_>>().join(",")),
        Json::Obj(o) => format!("{{{}}}", o.iter().map(|(k, val)| format!("{}:{}", escape(k), stringify(val))).collect::<Vec<_>>().join(",")),
    }
}

impl Json {
    pub fn get_mut_obj<'a>(&'a mut self, key: &str) -> Option<&'a mut Json> {
        if let Json::Obj(entries) = self {
            if let Some(pos) = entries.iter().position(|(k, _)| k == key) {
                return Some(&mut entries[pos].1);
            }
        }
        None
    }
    pub fn obj_insert(&mut self, key: &str, val: Json) {
        if let Json::Obj(entries) = self {
            if let Some(pos) = entries.iter().position(|(k, _)| k == key) { entries[pos].1 = val; }
            else { entries.push((key.to_string(), val)); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let src = r#"{"a":[1,2.5,-3e2],"b":{"c":"x\"y é"},"d":null}"#;
        let v = Parser::parse(src).unwrap();
        assert_eq!(stringify(&v), src.replace(" é", " é"));
        let v2 = Parser::parse(&stringify(&v)).unwrap();
        assert_eq!(v, v2);
    }
}
