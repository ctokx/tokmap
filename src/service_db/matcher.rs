use super::types::*;
use super::parser::parse_service_probes;
use tracing::{info, warn};

pub struct ServiceMatcher {
    db: ServiceDatabase,
}

impl ServiceMatcher {
    pub fn new(db: ServiceDatabase) -> Self {
        Self { db }
    }

    pub fn load_default() -> anyhow::Result<Self> {
        let paths = [
            "nmap-service-probes",
            "./nmap-service-probes",
            "../nmap-service-probes",
        ];

        for path in &paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                match parse_service_probes(&content) {
                    Ok(db) => {
                        info!("Loaded {} service probes from {}", db.probes.len(), path);
                        return Ok(Self::new(db));
                    }
                    Err(e) => {
                        warn!("Failed to parse service database from {}: {}", path, e);
                    }
                }
            }
        }

        anyhow::bail!("Could not find nmap-service-probes file")
    }

    pub fn database(&self) -> &ServiceDatabase {
        &self.db
    }

    pub fn match_banner(&self, banner: &str, port: u16) -> Option<ServiceMatch> {
        let probes = self.db.get_probes_for_port(port);

        // Hard matches first (higher confidence)
        for probe in &probes {
            for m in &probe.matches {
                if let Some(service_match) = self.try_match(m, banner, false) {
                    return Some(service_match);
                }
            }
        }

        // Fall back to soft matches
        for probe in &probes {
            for m in &probe.soft_matches {
                if let Some(service_match) = self.try_match(m, banner, true) {
                    return Some(service_match);
                }
            }
        }

        None
    }

    fn try_match(&self, m: &Match, banner: &str, is_soft: bool) -> Option<ServiceMatch> {
        let captures = m.pattern.captures(banner)?;

        let mut version_info = m.version_info.clone();

        // Substitute capture groups ($1, $2, etc.) in version info templates
        version_info.product = substitute_captures(&version_info.product, &captures);
        version_info.version = substitute_captures(&version_info.version, &captures);
        version_info.info = substitute_captures(&version_info.info, &captures);
        version_info.hostname = substitute_captures(&version_info.hostname, &captures);
        version_info.operating_system = substitute_captures(&version_info.operating_system, &captures);
        version_info.device_type = substitute_captures(&version_info.device_type, &captures);

        version_info.cpe = version_info
            .cpe
            .iter()
            .filter_map(|cpe| substitute_captures(&Some(cpe.clone()), &captures))
            .collect();

        Some(ServiceMatch::from_match(&m.service, &version_info, is_soft))
    }
}

fn substitute_captures(template: &Option<String>, captures: &regex::Captures) -> Option<String> {
    let template = template.as_ref()?;
    let mut result = template.clone();

    for i in 1..captures.len() {
        if let Some(capture) = captures.get(i) {
            let placeholder = format!("${}", i);
            result = result.replace(&placeholder, capture.as_str());
        }
    }

    if result.contains('$') && result == *template {
        Some(result)
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn test_substitute_captures() {
        let re = Regex::new(r"Server: nginx/(\d+\.\d+\.\d+)").unwrap();
        let banner = "Server: nginx/1.18.0";
        let captures = re.captures(banner).unwrap();

        let template = Some("nginx version $1".to_string());
        let result = substitute_captures(&template, &captures);

        assert_eq!(result, Some("nginx version 1.18.0".to_string()));
    }

    #[test]
    fn test_substitute_multiple_captures() {
        let re = Regex::new(r"^220 ([\w.-]+) FTP server \(Version ([\d.]+)\)").unwrap();
        let banner = "220 example.com FTP server (Version 2.3.4)";
        let captures = re.captures(banner).unwrap();

        let template = Some("$2 on $1".to_string());
        let result = substitute_captures(&template, &captures);

        assert_eq!(result, Some("2.3.4 on example.com".to_string()));
    }
}
