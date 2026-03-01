use std::collections::HashMap;
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone)]
pub struct OSFingerprint {
    pub name: String,
    pub class: String,
    pub cpe: Vec<String>,
    pub tests: HashMap<String, String>,
}

pub struct OSDatabase {
    pub fingerprints: Vec<OSFingerprint>,
}

impl OSDatabase {
    pub fn load_from_file(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut fingerprints = Vec::new();
        let mut current_fp: Option<OSFingerprint> = None;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Fingerprint ") {
                if let Some(fp) = current_fp.take() {
                    fingerprints.push(fp);
                }
                current_fp = Some(OSFingerprint {
                    name: line["Fingerprint ".len()..].to_string(),
                    class: String::new(),
                    cpe: Vec::new(),
                    tests: HashMap::new(),
                });
            } else if let Some(ref mut fp) = current_fp {
                if line.starts_with("Class ") {
                    fp.class = line["Class ".len()..].to_string();
                } else if line.starts_with("CPE ") {
                    fp.cpe.push(line["CPE ".len()..].to_string());
                } else if line.contains('(') {
                    if let Some(pos) = line.find('(') {
                        let test_name = &line[..pos];
                        let test_data = &line[pos..];
                        fp.tests.insert(test_name.to_string(), test_data.to_string());
                    }
                }
            }
        }

        if let Some(fp) = current_fp {
            fingerprints.push(fp);
        }

        Ok(OSDatabase { fingerprints })
    }

    /// Simplified heuristic: match TTL and window size against ECN/WIN test fields
    pub fn match_os(&self, ttl: u8, window_size: u16) -> Option<&OSFingerprint> {
        self.fingerprints.iter().find(|f| {
            if let Some(ecn) = f.tests.get("ECN") {
                 if ecn.contains(&format!("T={:X}", ttl)) { return true; }
            }
            if let Some(win) = f.tests.get("WIN") {
                if win.contains(&format!("W1={:X}", window_size)) { return true; }
            }
            false
        })
    }
}
