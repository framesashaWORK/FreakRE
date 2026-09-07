//! Split a .fsig file into N sequential chunks (each keeps the header).
//! Usage: splitn <input.fsig> <out-prefix> <chunks>
//! Writes <out-prefix>-00.fsig .. <out-prefix>-NN.fsig.
use std::io::{BufRead, BufReader, BufWriter, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input = &args[1];
    let prefix = &args[2];
    let chunks: usize = args[3].parse().expect("chunks");
    let f = std::fs::File::open(input).expect("open input");
    let mut header = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line.expect("read");
        if line.starts_with('#') {
            header.push(line);
        } else if !line.trim().is_empty() {
            entries.push(line);
        }
    }
    let per = entries.len().div_ceil(chunks);
    for (i, part) in entries.chunks(per).enumerate() {
        let path = format!("{prefix}-{i:02}.fsig");
        let o = std::fs::File::create(&path).expect("create");
        let mut w = BufWriter::new(o);
        for h in &header {
            writeln!(w, "{h}").expect("write");
        }
        for e in part {
            writeln!(w, "{e}").expect("write");
        }
        println!("wrote {} entries -> {path}", part.len());
    }
}
