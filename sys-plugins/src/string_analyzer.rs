//! # String Analyzer Plugin
//!
//! Advanced string analysis: extracts strings, classifies them (URLs, IPs,
//! file paths, registry keys, crypto hashes, emails), and creates xrefs.

use crate::util;
use plugins::{MenuItem, Plugin, PluginContext, PluginMetadata};

pub struct StringAnalyzerPlugin;
impl Default for StringAnalyzerPlugin {
    fn default() -> Self {
        Self
    }
}

const INTERESTING_PATTERNS: &[(&str, &str)] = &[
    ("http://", "URL"),
    ("https://", "URL"),
    ("ftp://", "URL"),
    ("ws://", "WebSocket URL"),
    ("wss://", "WebSocket URL"),
    ("\\\\", "UNC Path"),
    ("HKEY_", "Registry Key"),
    ("SOFTWARE\\", "Registry Path"),
    ("cmd.exe", "Command Shell"),
    ("powershell", "PowerShell"),
    ("/bin/sh", "Unix Shell"),
    ("/bin/bash", "Bash Shell"),
    ("CreateProcess", "Process Creation API"),
    ("VirtualAlloc", "Memory Allocation API"),
    ("WriteProcessMemory", "Process Injection API"),
    ("LoadLibrary", "DLL Loading API"),
    ("GetProcAddress", "Dynamic API Resolution"),
    ("RegSetValue", "Registry Write API"),
    ("InternetOpen", "WinInet API"),
    ("WSAStartup", "Winsock API"),
    ("connect(", "Socket Connect"),
    ("send(", "Socket Send"),
    ("recv(", "Socket Receive"),
    ("execve", "Unix Exec"),
    ("fork", "Unix Fork"),
    ("socket(", "Socket Create"),
    ("BEGIN RSA", "RSA Private Key"),
    ("BEGIN CERTIFICATE", "X.509 Certificate"),
    ("BEGIN PUBLIC KEY", "Public Key"),
    ("ssh-rsa", "SSH RSA Key"),
    ("Authorization: Bearer", "OAuth Token"),
    ("api_key=", "API Key Parameter"),
    ("password=", "Password Parameter"),
    ("token=", "Token Parameter"),
];

impl Plugin for StringAnalyzerPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "String Analyzer".into(),
            version: "1.0.0".into(),
            author: Some("FreakRE Team".into()),
            description:
                "Extracts and classifies strings (URLs, IPs, paths, APIs, crypto material).".into(),
            license: Some("MIT".into()),
            homepage: None,
        }
    }
    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/Strings", "Analyze Strings").with_shortcut("Ctrl+Shift+S")]
    }
    fn on_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        if path == "Analyze/Strings" {
            self.analyze(ctx);
        }
    }
    fn analyze(&mut self, ctx: &mut PluginContext) {
        ctx.println("[StringAnalyzer] Analyzing extracted strings...");

        let functions = match ctx.db.list_functions() {
            Ok(f) => f,
            Err(e) => {
                ctx.println(&format!("Error: {}", e));
                return;
            }
        };

        let mut url_count = 0usize;
        let mut api_count = 0usize;
        let mut crypto_count = 0usize;
        let mut path_count = 0usize;
        let mut other_interesting = 0usize;

        for func in &functions {
            let code = match &func.code_bytes {
                Some(b) => b.as_slice(),
                None => continue,
            };

            // Extract ASCII strings (min length 4)
            let strings = extract_ascii_strings(code, 4);

            for s in &strings {
                let lower = s.to_lowercase();
                let mut classified = false;

                for (pattern, category) in INTERESTING_PATTERNS {
                    if lower.contains(&pattern.to_lowercase()) {
                        // Append-style: refresh only our own "[<category>]" line,
                        // keep user comments and other plugins' annotations.
                        util::upsert_tagged_comment(
                            &mut ctx.db,
                            func.address,
                            &format!("[{}]", category),
                            &format!("[{}] String: \"{}\"", category, truncate_str(s, 80)),
                        );
                        match *category {
                            "URL" | "WebSocket URL" => url_count += 1,
                            c if c.ends_with("API") => api_count += 1,
                            "RSA Private Key" | "X.509 Certificate" | "Public Key"
                            | "SSH RSA Key" => crypto_count += 1,
                            "UNC Path" | "Registry Path" | "Registry Key" => path_count += 1,
                            _ => other_interesting += 1,
                        }
                        classified = true;
                        break;
                    }
                }

                // Check for IP addresses
                if !classified && looks_like_ip(s) {
                    util::upsert_tagged_comment(
                        &mut ctx.db,
                        func.address,
                        "[IP]",
                        &format!("[IP] {}", s),
                    );
                    other_interesting += 1;
                }
            }
        }

        ctx.println(&format!(
            "[StringAnalyzer] Results: {} URLs, {} APIs, {} crypto, {} paths, {} other interesting",
            url_count, api_count, crypto_count, path_count, other_interesting
        ));
    }
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (0x20..=0x7E).contains(&byte) {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push(current);
    }
    strings
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
