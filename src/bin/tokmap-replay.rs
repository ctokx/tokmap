//! Matches recorded replies against signature files, without touching the network.
//!
//! Usage: tokmap-replay [--signatures FILE]... RECORDINGS.jsonl...
//! With no --signatures, the built-in signatures are used. Prints one JSON line per recording.

use anyhow::{Context, Result};
use tokmap::service::Recording;
use tokmap::service_db::ServiceMatcher;

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            let pair = hex.get(i..i + 2).context("odd-length hex")?;
            u8::from_str_radix(pair, 16).context("bad hex")
        })
        .collect()
}

fn main() -> Result<()> {
    let mut signature_files = Vec::new();
    let mut recording_files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--signatures" {
            signature_files.push(args.next().context("--signatures needs a file")?);
        } else {
            recording_files.push(arg);
        }
    }

    let matcher = if signature_files.is_empty() {
        ServiceMatcher::load(&[])?
    } else {
        ServiceMatcher::from_files(&signature_files)?
    };

    for path in &recording_files {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let recording: Recording = serde_json::from_str(line).with_context(|| format!("bad line in {path}"))?;
            let found = matcher
                .database()
                .probe(&recording.probe)
                .and_then(|probe| Some(matcher.match_response(probe, &hex_to_bytes(&recording.response_hex).ok()?)))
                .flatten();

            let output = serde_json::json!({
                "file": path,
                "port": recording.port,
                "protocol": recording.protocol,
                "tunnel": recording.tunnel,
                "probe": recording.probe,
                "match": found,
            });
            println!("{output}");
        }
    }
    Ok(())
}
