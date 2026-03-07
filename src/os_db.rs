use std::collections::HashMap;
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone)]
pub struct OSFingerprint {
    pub name: String,
    pub classes: Vec<OSClass>,
    pub cpe: Vec<String>,
    pub tests: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct OSClass {
    pub vendor: String,
    pub family: String,
    pub generation: String,
    pub device_type: String,
}

pub struct OSDatabase {
    pub fingerprints: Vec<OSFingerprint>,
}

#[derive(Debug, Clone)]
pub struct OSMatchResult {
    pub name: String,
    pub score: f64,
    pub cpe: Vec<String>,
    pub device_type: Option<String>,
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
                    classes: Vec::new(),
                    cpe: Vec::new(),
                    tests: HashMap::new(),
                });
            } else if let Some(ref mut fp) = current_fp {
                if line.starts_with("Class ") {
                    if let Some(class) = parse_os_class(&line) {
                        fp.classes.push(class);
                    }
                } else if line.starts_with("CPE ") {
                    fp.cpe.push(line["CPE ".len()..].to_string());
                } else if line.contains('(') {
                    if let Some(pos) = line.find('(') {
                        let test_name = line[..pos].trim().to_string();
                        let test_data = &line[pos + 1..line.len() - 1];
                        let parsed = parse_test_values(test_data);
                        fp.tests.insert(test_name, parsed);
                    }
                }
            }
        }

        if let Some(fp) = current_fp {
            fingerprints.push(fp);
        }

        Ok(OSDatabase { fingerprints })
    }

    pub fn match_fingerprint(&self, observed: &ObservedFingerprint) -> Vec<OSMatchResult> {
        let mut results: Vec<OSMatchResult> = self.fingerprints.iter()
            .filter_map(|fp| {
                let score = self.score_fingerprint(fp, observed);
                if score > 0.3 {
                    Some(OSMatchResult {
                        name: fp.name.clone(),
                        score,
                        cpe: fp.cpe.clone(),
                        device_type: fp.classes.first().map(|c| c.device_type.clone()),
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        results.truncate(5);
        results
    }

    fn score_fingerprint(&self, fp: &OSFingerprint, observed: &ObservedFingerprint) -> f64 {
        let mut total_tests = 0;
        let mut matched_tests = 0;

        if let Some(seq_tests) = fp.tests.get("SEQ") {
            total_tests += 3;
            if let Some(sp_range) = seq_tests.get("SP") {
                if check_range(observed.sp, sp_range) {
                    matched_tests += 1;
                }
            }
            if let Some(gcd_range) = seq_tests.get("GCD") {
                if check_range(observed.gcd, gcd_range) {
                    matched_tests += 1;
                }
            }
            if let Some(isr_range) = seq_tests.get("ISR") {
                if check_range(observed.isr, isr_range) {
                    matched_tests += 1;
                }
            }
        }

        if let Some(win_tests) = fp.tests.get("WIN") {
            for (key, expected) in win_tests {
                if key.starts_with('W') {
                    total_tests += 1;
                    if check_hex_match(observed.window_sizes.first().copied().unwrap_or(0) as u32, expected) {
                        matched_tests += 1;
                    }
                }
            }
        }

        if let Some(ops_tests) = fp.tests.get("OPS") {
            total_tests += 1;
            if let Some(o1) = ops_tests.get("O1") {
                if let Some(ref observed_opts) = observed.tcp_options {
                    if o1.contains(observed_opts) || observed_opts.contains(o1.as_str()) {
                        matched_tests += 1;
                    }
                }
            }
        }

        if let Some(ecn_tests) = fp.tests.get("ECN") {
            total_tests += 1;
            if let Some(t_val) = ecn_tests.get("T") {
                if check_hex_match(observed.ttl as u32, t_val) {
                    matched_tests += 1;
                }
            }
            total_tests += 1;
            if let Some(w_val) = ecn_tests.get("W") {
                if check_hex_match(observed.window_sizes.first().copied().unwrap_or(0) as u32, w_val) {
                    matched_tests += 1;
                }
            }
        }

        for test_name in &["T1", "T2", "T3", "T4", "T5", "T6", "T7"] {
            if let Some(t_tests) = fp.tests.get(*test_name) {
                if let Some(t_val) = t_tests.get("T") {
                    total_tests += 1;
                    let ttl_bucket = classify_ttl(observed.ttl);
                    if t_val.contains(ttl_bucket) {
                        matched_tests += 1;
                    }
                }
                if let Some(w_val) = t_tests.get("W") {
                    total_tests += 1;
                    if check_hex_match(observed.window_sizes.first().copied().unwrap_or(0) as u32, w_val) {
                        matched_tests += 1;
                    }
                }
            }
        }

        if total_tests == 0 {
            return 0.0;
        }

        matched_tests as f64 / total_tests as f64
    }

    pub fn match_os(&self, ttl: u8, window_size: u16) -> Option<&OSFingerprint> {
        let observed = ObservedFingerprint {
            ttl,
            window_sizes: vec![window_size],
            sp: estimate_sp_from_ttl(ttl),
            gcd: 1,
            isr: 0,
            tcp_options: None,
        };

        let results = self.match_fingerprint(&observed);
        if let Some(best) = results.first() {
            if best.score > 0.2 {
                return self.fingerprints.iter().find(|f| f.name == best.name);
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct ObservedFingerprint {
    pub ttl: u8,
    pub window_sizes: Vec<u16>,
    pub sp: u32,
    pub gcd: u32,
    pub isr: u32,
    pub tcp_options: Option<String>,
}

impl ObservedFingerprint {
    pub fn from_responses(ttl: u8, window_sizes: Vec<u16>, isn_diffs: &[u32]) -> Self {
        let gcd = if isn_diffs.len() >= 2 {
            compute_gcd_sequence(isn_diffs)
        } else {
            1
        };

        let sp = if isn_diffs.len() >= 2 {
            compute_sp(isn_diffs)
        } else {
            estimate_sp_from_ttl(ttl)
        };

        let isr = if isn_diffs.len() >= 2 {
            compute_isr(isn_diffs)
        } else {
            0
        };

        Self {
            ttl,
            window_sizes,
            sp,
            gcd,
            isr,
            tcp_options: None,
        }
    }
}

fn parse_os_class(line: &str) -> Option<OSClass> {
    let rest = line.strip_prefix("Class ")?;
    let parts: Vec<&str> = rest.splitn(4, " | ").collect();
    if parts.len() >= 4 {
        Some(OSClass {
            vendor: parts[0].trim().to_string(),
            family: parts[1].trim().to_string(),
            generation: parts[2].trim().to_string(),
            device_type: parts[3].trim().to_string(),
        })
    } else if parts.len() >= 2 {
        Some(OSClass {
            vendor: parts[0].trim().to_string(),
            family: parts.get(1).unwrap_or(&"").trim().to_string(),
            generation: parts.get(2).unwrap_or(&"").trim().to_string(),
            device_type: parts.get(3).unwrap_or(&"general purpose").trim().to_string(),
        })
    } else {
        None
    }
}

fn parse_test_values(data: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for pair in data.split('%') {
        if let Some((key, val)) = pair.split_once('=') {
            values.insert(key.to_string(), val.to_string());
        }
    }
    values
}

fn check_range(value: u32, range_str: &str) -> bool {
    if range_str.contains('-') {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() == 2 {
            let low = u32::from_str_radix(parts[0], 16).unwrap_or(0);
            let high = u32::from_str_radix(parts[1], 16).unwrap_or(u32::MAX);
            return value >= low && value <= high;
        }
    }
    if range_str.contains('|') {
        return range_str.split('|').any(|v| {
            u32::from_str_radix(v, 16).map(|parsed| parsed == value).unwrap_or(false)
        });
    }
    u32::from_str_radix(range_str, 16).map(|parsed| parsed == value).unwrap_or(false)
}

fn check_hex_match(value: u32, expected: &str) -> bool {
    check_range(value, expected)
}

fn classify_ttl(ttl: u8) -> &'static str {
    match ttl {
        0..=32 => "20",
        33..=64 => "40",
        65..=128 => "80",
        _ => "FF",
    }
}

fn estimate_sp_from_ttl(ttl: u8) -> u32 {
    match ttl {
        0..=32 => 0x20,
        33..=64 => 0x6C,
        65..=128 => 0xFA,
        _ => 0x100,
    }
}

fn compute_gcd_sequence(values: &[u32]) -> u32 {
    if values.is_empty() {
        return 1;
    }
    let mut result = values[0];
    for &v in &values[1..] {
        result = gcd(result, v);
    }
    if result == 0 { 1 } else { result }
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn compute_sp(isn_diffs: &[u32]) -> u32 {
    if isn_diffs.is_empty() {
        return 0;
    }
    let mean = isn_diffs.iter().map(|&x| x as f64).sum::<f64>() / isn_diffs.len() as f64;
    let variance = isn_diffs.iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>() / isn_diffs.len() as f64;
    let stddev = variance.sqrt();

    if stddev <= 1.0 {
        return 0;
    }
    (8.0 * (stddev / mean.max(1.0)).log2().abs()) as u32
}

fn compute_isr(isn_diffs: &[u32]) -> u32 {
    if isn_diffs.is_empty() {
        return 0;
    }
    let mean = isn_diffs.iter().map(|&x| x as f64).sum::<f64>() / isn_diffs.len() as f64;
    if mean < 1.0 {
        return 0;
    }
    (8.0 * mean.log2()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_test_values() {
        let data = "SP=100-101%GCD=1-4%ISR=A1-AF";
        let values = parse_test_values(data);
        assert_eq!(values.get("SP"), Some(&"100-101".to_string()));
        assert_eq!(values.get("GCD"), Some(&"1-4".to_string()));
        assert_eq!(values.get("ISR"), Some(&"A1-AF".to_string()));
    }

    #[test]
    fn test_check_range() {
        assert!(check_range(0x100, "100-101"));
        assert!(check_range(0x101, "100-101"));
        assert!(!check_range(0x102, "100-101"));
    }

    #[test]
    fn test_check_range_pipe() {
        assert!(check_range(0x40, "40|80|FF"));
        assert!(check_range(0x80, "40|80|FF"));
        assert!(!check_range(0x41, "40|80|FF"));
    }

    #[test]
    fn test_classify_ttl() {
        assert_eq!(classify_ttl(64), "40");
        assert_eq!(classify_ttl(128), "80");
        assert_eq!(classify_ttl(255), "FF");
        assert_eq!(classify_ttl(32), "20");
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(7, 7), 7);
    }

    #[test]
    fn test_compute_gcd_sequence() {
        assert_eq!(compute_gcd_sequence(&[12, 8, 4]), 4);
        assert_eq!(compute_gcd_sequence(&[6, 3, 9]), 3);
    }

    #[test]
    fn test_observed_fingerprint_from_responses() {
        let fp = ObservedFingerprint::from_responses(64, vec![65535, 65535], &[1000, 2000, 3000]);
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.window_sizes, vec![65535, 65535]);
        assert!(fp.gcd > 0);
    }

    #[test]
    fn test_os_match_result_sorted() {
        let db = OSDatabase { fingerprints: Vec::new() };
        let observed = ObservedFingerprint {
            ttl: 64,
            window_sizes: vec![65535],
            sp: 0x100,
            gcd: 1,
            isr: 0,
            tcp_options: None,
        };
        let results = db.match_fingerprint(&observed);
        assert!(results.is_empty());
    }
}
