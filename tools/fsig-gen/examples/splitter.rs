//! Split a .fsig file into halves by line count: splitter <in> <out_a> <out_b>.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[1]).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let h = lines.len() / 2;
    std::fs::write(&args[2], lines[..h].join("\n")).unwrap();
    std::fs::write(&args[3], lines[h..].join("\n")).unwrap();
    println!("{} lines -> {} + {}", lines.len(), h, lines.len() - h);
}
