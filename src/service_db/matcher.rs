use super::parser::parse_service_probes;
use super::types::*;
use anyhow::Context;
use pcre2::bytes::Captures;
use tracing::info;

const BUILT_IN_PROBES: &str = include_str!("../../signatures/tokmap.probes");
const BUILT_IN_MATCHES: &str = include_str!("../../signatures/verified.matches");

fn read_files(paths: &[String]) -> anyhow::Result<String> {
    let mut text = String::new();
    for path in paths {
        let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        text.push_str(&String::from_utf8_lossy(&bytes));
        text.push('\n');
    }
    Ok(text)
}

pub struct ServiceMatcher {
    db: ServiceDatabase,
}

impl ServiceMatcher {
    pub fn new(db: ServiceDatabase) -> Self {
        Self { db }
    }

    /// The signatures built into the binary, followed by any extra files.
    pub fn load(extra_files: &[String]) -> anyhow::Result<Self> {
        let mut text = format!("{BUILT_IN_PROBES}\n{BUILT_IN_MATCHES}\n");
        text.push_str(&read_files(extra_files)?);
        let db = parse_service_probes(&text)?;
        info!("Loaded {} service probes", db.probes.len());
        Ok(Self::new(db))
    }

    /// Only the given files, without the built-in signatures.
    pub fn from_files(paths: &[String]) -> anyhow::Result<Self> {
        Ok(Self::new(parse_service_probes(&read_files(paths)?)?))
    }

    pub fn database(&self) -> &ServiceDatabase {
        &self.db
    }

    pub fn probes_for(&self, port: u16, tunnel: bool, intensity: u8) -> Vec<&Probe> {
        self.db.probes_for(port, tunnel, intensity)
    }

    pub fn udp_probes_for(&self, port: u16, intensity: u8) -> Vec<&Probe> {
        self.db.udp_probes_for(port, intensity)
    }

    /// Matches a response against the probe that drew it, then its fallbacks, then the empty
    /// probe. Other probes' signatures are skipped: they describe different conversations.
    pub fn match_response(&self, probe: &Probe, response: &[u8]) -> Option<ServiceMatch> {
        let fallbacks = probe.fallback.iter().filter_map(|name| self.db.probe(name));
        let empty_probe = self.db.probes.iter().find(|p| p.payload.is_empty());
        let chain = std::iter::once(probe)
            .chain(fallbacks)
            .chain(empty_probe.filter(|p| p.name != probe.name));

        let mut soft = None;
        for candidate in chain {
            if let Some(hard) = candidate.matches.iter().find_map(|m| try_match(m, response, false)) {
                return Some(hard);
            }
            if soft.is_none() {
                soft = candidate.soft_matches.iter().find_map(|m| try_match(m, response, true));
            }
        }
        soft
    }
}

fn try_match(m: &Match, response: &[u8], is_soft: bool) -> Option<ServiceMatch> {
    let captures = m.pattern.captures(response).ok()??;
    let fill = |template: &Option<String>| {
        template
            .as_deref()
            .map(|t| substitute(t, &captures))
            .filter(|text| !text.is_empty())
    };

    let template = &m.version_info;
    let version_info = VersionInfo {
        product: fill(&template.product),
        version: fill(&template.version),
        info: fill(&template.info),
        hostname: fill(&template.hostname),
        operating_system: fill(&template.operating_system),
        device_type: fill(&template.device_type),
        cpe: template.cpe.iter().map(|cpe| substitute(cpe, &captures)).collect(),
    };

    Some(ServiceMatch::from_match(&m.service, &version_info, is_soft))
}

/// Expands `$1`, `$P(1)`, `$SUBST(1,"_",".")` and `$I(1,">")` in a template.
fn substitute(template: &str, captures: &Captures) -> String {
    let mut out = String::new();
    let mut rest = template;

    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        match expand(rest, captures) {
            Some((text, used)) => {
                out.push_str(&text);
                rest = &rest[used..];
            }
            None => {
                out.push('$');
                rest = &rest[1..];
            }
        }
    }

    out.push_str(rest);
    out
}

fn expand(text: &str, captures: &Captures) -> Option<(String, usize)> {
    let group = |n: usize| captures.get(n).map_or(&[][..], |m| m.as_bytes());
    let lossy = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();

    let after_dollar = &text[1..];
    if let Some(n) = after_dollar.chars().next().and_then(|c| c.to_digit(10)) {
        return Some((lossy(group(n as usize)), 2));
    }

    let (name, args_start) = after_dollar.split_at(after_dollar.find('(')?);
    let end = args_start.find(')')?;
    let args = &args_start[1..end];
    let used = 1 + name.len() + end + 1;
    let (n, quoted) = args.split_once(',').unwrap_or((args, ""));
    let n: usize = n.trim().parse().ok()?;
    let strings: Vec<&str> = quoted.split('"').skip(1).step_by(2).collect();

    let value = match (name, strings.as_slice()) {
        ("P", _) => group(n)
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|&b| b as char)
            .collect(),
        ("SUBST", [from, to]) => lossy(group(n)).replace(from, to),
        ("I", [order]) => {
            let bytes = group(n);
            let fold = |sum: u64, b: &u8| sum << 8 | *b as u64;
            let number = match *order {
                ">" => bytes.iter().fold(0, fold),
                _ => bytes.iter().rev().fold(0, fold),
            };
            number.to_string()
        }
        _ => return None,
    };

    Some((value, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = r#"
Exclude T:9100-9107
Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-OpenSSH_([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/a
match mysql m|^.\0\0\0\x0a([\w._-]+)\0| p/MySQL/ v/$1/
match ftp m|^220(?!.*FileZilla).*FTP| p/Some FTP/
match demo-int m|^INT(..)| v/$I(1,">")/
match demo-subst m|^VER ([\d_]+)| v/$SUBST(1,"_",".")/
match demo-print m|^RAW (.+)$|s v/$P(1)/
softmatch http m|^HTTP/1\.[01] \d\d\d|
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
sslports 443
match http m|^HTTP/1\.[01] \d\d\d.*\r\nServer: nginx/([\d.]+)|s p/nginx/ v/$1/
Probe TCP RareThing q|x|
rarity 9
ports 7000
match rare m|^rare|
Probe TCP OnlyFallback q|y|
rarity 3
fallback GetRequest
Probe UDP Udp q|z|
rarity 1
match udp-only m|^udp|
"#;

    fn matcher() -> ServiceMatcher {
        ServiceMatcher::new(parse_service_probes(DB).unwrap())
    }

    fn null_match(response: &[u8]) -> Option<ServiceMatch> {
        let m = matcher();
        let probe = m.database().probe("NULL").unwrap();
        m.match_response(probe, response)
    }

    #[test]
    fn matches_raw_bytes_with_nul_and_high_bytes() {
        let found = null_match(b"\xff\0\0\0\x0a8.0.36\0rest").unwrap();
        assert_eq!(found.service_name, "mysql");
        assert_eq!(found.version.as_deref(), Some("8.0.36"));
    }

    #[test]
    fn lookahead_patterns_work() {
        assert!(null_match(b"220 Acme FTP").is_some());
        assert!(null_match(b"220 FileZilla FTP").is_none());
    }

    #[test]
    fn capture_fills_version_and_cpe() {
        let found = null_match(b"SSH-2.0-OpenSSH_9.6p1\r\n").unwrap();
        assert_eq!(found.product.as_deref(), Some("OpenSSH"));
        assert_eq!(found.info.as_deref(), Some("protocol 2.0"));
        assert_eq!(found.cpe, vec!["cpe:/a:openbsd:openssh:9.6p1"]);
    }

    #[test]
    fn template_helpers_expand() {
        assert_eq!(null_match(b"INT\x01\x02").unwrap().version.as_deref(), Some("258"));
        assert_eq!(null_match(b"VER 1_2_3").unwrap().version.as_deref(), Some("1.2.3"));
        assert_eq!(null_match(b"RAW a\x01b\x7f").unwrap().version.as_deref(), Some("ab"));
    }

    #[test]
    fn soft_match_is_low_confidence_and_loses_to_hard() {
        assert_eq!(null_match(b"HTTP/1.1 200 OK\r\n").unwrap().confidence, Confidence::Low);

        let m = matcher();
        let get = m.database().probe("GetRequest").unwrap();
        let hard = m.match_response(get, b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n").unwrap();
        assert_eq!(hard.confidence, Confidence::High);
    }

    #[test]
    fn response_is_not_matched_against_unrelated_probes() {
        let m = matcher();
        let null = m.database().probe("NULL").unwrap();
        assert!(m.match_response(null, b"rare").is_none());
    }

    #[test]
    fn fallback_chain_is_followed() {
        let m = matcher();
        let probe = m.database().probe("OnlyFallback").unwrap();
        let found = m.match_response(probe, b"HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\n").unwrap();
        assert_eq!(found.product.as_deref(), Some("nginx"));
    }

    #[test]
    fn built_in_signatures_load() {
        let m = ServiceMatcher::load(&[]).unwrap();
        assert!(m.database().probe("Empty").is_some_and(|p| p.payload.is_empty()));
        let hello = m.database().probe("TlsClientHello").unwrap();
        assert!(m.match_response(hello, b"\x16\x03\x03\x00\x40rest").is_some());
        assert!(m.match_response(hello, b"HTTP/1.1 400 Bad Request").is_none());
    }

    #[test]
    fn probes_are_ordered_filtered_and_tcp_only() {
        let m = matcher();
        let names = |port, tunnel, intensity| -> Vec<String> {
            m.probes_for(port, tunnel, intensity).iter().map(|p| p.name.clone()).collect()
        };

        assert_eq!(names(5173, false, 7), ["NULL", "GetRequest", "OnlyFallback"]);
        assert_eq!(names(7000, false, 7), ["NULL", "RareThing", "GetRequest", "OnlyFallback"]);
        assert_eq!(names(5173, false, 2), ["NULL", "GetRequest"]);
        assert_eq!(names(443, true, 2), ["NULL", "GetRequest"]);
        assert!(names(9100, false, 9).is_empty());
    }

    #[test]
    fn udp_probes_are_kept_apart_from_tcp() {
        let m = matcher();
        let names: Vec<&str> = m.udp_probes_for(53, 7).iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Udp"]);
    }
}
