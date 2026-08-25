use std::process::Command;

fn main() {
    let exe = r"target\debug\examples\decompile_demo.exe";
    let sample = r"C:\Users\DD7D~1\AppData\Local\Temp\opencode\sample_frozen.exe";
    let mut total = 0usize;
    let mut clean = 0usize;
    let mut garbage_hits: Vec<(String, usize)> = Vec::new();
    for off in (0x600..0x20000).step_by(0x200) {
        let out = Command::new(exe)
            .args([sample, &format!("0x{off:X}")])
            .output();
        let out = match out {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        let c = String::from_utf8_lossy(&out.stdout);
        if c.trim().is_empty() || !c.contains("void demo") {
            continue;
        }
        total += 1;
        let lines: Vec<&str> = c.lines().collect();
        // A line is garbage if it contains raw stack derefs, flag refs, goto fallbacks or warnings
        let bad: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| {
                l.contains("*(rsp") || l.contains("flag_") || l.contains("goto bb")
                    || l.contains("WARNING") || l.trim().starts_with("Label {") ||
                    l.contains("func_0x") && false
            })
            .collect();
        if bad.is_empty() {
            clean += 1;
        } else {
            garbage_hits.push((format!("0x{off:X}"), bad.len()));
        }
    }
    println!("functions={total} clean={clean} with_garbage={} ({:.1}% clean)",
        garbage_hits.len(),
        if total > 0 { clean as f64 * 100.0 / total as f64 } else { 0.0 },
    );
    for (off, n) in garbage_hits.iter().take(40) {
        println!("  {off}: {n} garbage lines");
    }
}
