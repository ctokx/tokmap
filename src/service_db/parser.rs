use super::types::*;
use anyhow::{Context, Result};
use std::collections::HashSet;

pub fn parse_service_probes(content: &str) -> Result<ServiceDatabase> {
    let mut db = ServiceDatabase::new();
    let mut current_probe: Option<Probe> = None;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("Exclude ") {
            if let Some(ports) = parse_exclude(line) {
                db.excluded_ports.extend(ports);
            }
        } else if line.starts_with("Probe ") {
            if let Some(probe) = current_probe.take() {
                db.probes.push(probe);
            }
            current_probe = parse_probe(line).ok();
        } else if let Some(ref mut probe) = current_probe {
            if line.starts_with("totalwaitms ") {
                if let Some(ms) = line.strip_prefix("totalwaitms ").and_then(|s| s.parse().ok()) {
                    probe.total_wait_ms = ms;
                }
            } else if line.starts_with("tcpwrappedms ") {
                if let Some(ms) = line.strip_prefix("tcpwrappedms ").and_then(|s| s.parse().ok()) {
                    probe.tcp_wrapped_ms = Some(ms);
                }
            } else if line.starts_with("ports ") {
                probe.ports = parse_port_list(line.strip_prefix("ports ").unwrap());
            } else if line.starts_with("sslports ") {
                probe.ssl_ports = parse_port_list(line.strip_prefix("sslports ").unwrap());
            } else if line.starts_with("match ") {
                if let Ok(m) = parse_match(line, false) {
                    probe.matches.push(m);
                }
            } else if line.starts_with("softmatch ") {
                if let Ok(m) = parse_match(line, true) {
                    probe.soft_matches.push(m);
                }
            }
        }
    }

    if let Some(probe) = current_probe {
        db.probes.push(probe);
    }

    Ok(db)
}

fn parse_exclude(line: &str) -> Option<Vec<u16>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let port_spec = parts[1].strip_prefix("T:")?;
    parse_port_list(port_spec)
}

fn parse_probe(line: &str) -> Result<Probe> {
    // Format: Probe TCP NULL q||
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 4 {
        anyhow::bail!("Invalid probe line: {}", line);
    }

    let protocol = match parts[1] {
        "TCP" => Protocol::TCP,
        "UDP" => Protocol::UDP,
        _ => anyhow::bail!("Unknown protocol: {}", parts[1]),
    };

    let name = parts[2].to_string();
    let payload = parse_payload(parts[3])?;

    Ok(Probe {
        protocol,
        name,
        payload,
        total_wait_ms: 5000,
        tcp_wrapped_ms: None,
        ports: None,
        ssl_ports: None,
        matches: Vec::new(),
        soft_matches: Vec::new(),
    })
}

fn parse_payload(s: &str) -> Result<Vec<u8>> {
    if !s.starts_with('q') {
        anyhow::bail!("Payload must start with 'q'");
    }

    let rest = &s[1..];
    if rest.len() < 2 {
        return Ok(Vec::new());
    }

    let delimiter = rest.chars().next().unwrap();
    let end_pos = rest[1..].find(delimiter).context("Missing end delimiter")?;
    let payload_str = &rest[1..=end_pos];

    unescape_payload(payload_str)
}

fn unescape_payload(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('r') => result.push(b'\r'),
                Some('n') => result.push(b'\n'),
                Some('t') => result.push(b'\t'),
                Some('0') => result.push(b'\0'),
                Some('\\') => result.push(b'\\'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    let byte = u8::from_str_radix(&hex, 16)?;
                    result.push(byte);
                }
                Some(c) => result.push(c as u8),
                None => result.push(b'\\'),
            }
        } else {
            result.push(ch as u8);
        }
    }

    Ok(result)
}

fn parse_match(line: &str, is_soft: bool) -> Result<Match> {
    let prefix = if is_soft { "softmatch " } else { "match " };
    let rest = line.strip_prefix(prefix).context("Invalid match line")?;

    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    if parts.len() < 2 {
        anyhow::bail!("Match line missing pattern");
    }

    let service = parts[0].to_string();
    let pattern_and_info = parts[1];

    let (regex_str, flags, remainder) = parse_pattern(pattern_and_info)?;

    let mut regex_builder = regex::RegexBuilder::new(&regex_str);
    if flags.contains('i') {
        regex_builder.case_insensitive(true);
    }
    if flags.contains('s') {
        regex_builder.dot_matches_new_line(true);
    }

    let pattern = regex_builder.build().context("Failed to compile regex")?;

    let version_info = parse_version_info(&remainder);

    Ok(Match {
        service,
        pattern,
        version_info,
        is_soft_match: is_soft,
    })
}

/// Returns (pattern, flags, remainder after flags)
fn parse_pattern(s: &str) -> Result<(String, String, String)> {
    if !s.starts_with('m') {
        anyhow::bail!("Pattern must start with 'm'");
    }

    let rest = &s[1..];
    if rest.is_empty() {
        anyhow::bail!("Empty pattern");
    }

    let delimiter = rest.chars().next().unwrap();
    let pattern_start = 1;

    // Find end delimiter, accounting for escaped delimiters
    let mut i = pattern_start;
    let chars: Vec<char> = rest.chars().collect();
    let mut escaped = false;

    while i < chars.len() {
        if escaped {
            escaped = false;
        } else if chars[i] == '\\' {
            escaped = true;
        } else if chars[i] == delimiter {
            let pattern = chars[pattern_start..i].iter().collect::<String>();
            let after_pattern = chars[i + 1..].iter().collect::<String>();

            let flags: String = after_pattern
                .chars()
                .take_while(|c| c.is_alphabetic())
                .collect();

            let remainder = after_pattern.trim_start_matches(|c: char| c.is_alphabetic()).trim().to_string();

            return Ok((pattern, flags, remainder));
        }
        i += 1;
    }

    anyhow::bail!("Pattern missing end delimiter");
}

fn parse_version_info(s: &str) -> VersionInfo {
    let mut info = VersionInfo::default();

    let fields = extract_fields(s);

    for field in fields {
        if let Some(stripped) = field.strip_prefix("p/") {
            info.product = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("v/") {
            info.version = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("i/") {
            info.info = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("h/") {
            info.hostname = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("o/") {
            info.operating_system = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("d/") {
            info.device_type = Some(stripped.trim_end_matches('/').to_string());
        } else if let Some(stripped) = field.strip_prefix("cpe:/") {
            info.cpe.push(format!("cpe:/{}", stripped.trim_end_matches('/')));
        }
    }

    info
}

/// Split version info string into individual /.../ delimited fields
fn extract_fields(s: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_field = false;

    for ch in s.chars() {
        if ch == '/' && !in_field {
            in_field = true;
            current.push(ch);
        } else if ch == '/' && in_field {
            current.push(ch);
            fields.push(current.clone());
            current.clear();
            in_field = false;
        } else if in_field {
            current.push(ch);
        } else if !current.is_empty() {
            current.push(ch);
        } else if !ch.is_whitespace() {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        fields.push(current);
    }

    fields
}

fn parse_port_list(s: &str) -> Option<Vec<u16>> {
    let mut ports = HashSet::new();

    for part in s.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for port in start..=end {
                        ports.insert(port);
                    }
                }
            }
        } else {
            if let Ok(port) = part.parse::<u16>() {
                ports.insert(port);
            }
        }
    }

    if ports.is_empty() {
        None
    } else {
        Some(ports.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_payload() {
        assert_eq!(
            unescape_payload(r"GET / HTTP/1.0\r\n\r\n").unwrap(),
            b"GET / HTTP/1.0\r\n\r\n"
        );
        assert_eq!(unescape_payload(r"\x00\x01\xFF").unwrap(), &[0, 1, 255]);
    }

    #[test]
    fn test_parse_payload() {
        assert_eq!(parse_payload("q||").unwrap(), b"");
        assert_eq!(
            parse_payload(r"q|GET / HTTP/1.0\r\n\r\n|").unwrap(),
            b"GET / HTTP/1.0\r\n\r\n"
        );
    }

    #[test]
    fn test_parse_port_list() {
        let ports = parse_port_list("80,443,8080-8082").unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
        assert!(ports.contains(&8081));
        assert!(ports.contains(&8082));
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn test_parse_pattern() {
        let (pattern, flags, remainder) =
            parse_pattern(r#"m|^220.*FTP|i p/FTP Server/"#).unwrap();
        assert_eq!(pattern, "^220.*FTP");
        assert_eq!(flags, "i");
        assert!(remainder.contains("p/FTP Server/"));
    }
}
