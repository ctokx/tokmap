use pcre2::bytes::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ServiceDatabase {
    pub probes: Vec<Probe>,
    pub excluded_ports: Vec<u16>,
}

impl ServiceDatabase {
    pub fn new() -> Self {
        Self {
            probes: Vec::new(),
            excluded_ports: Vec::new(),
        }
    }

    /// TCP probes for a port, best first: the empty probe, probes registered for the port,
    /// then the rest up to `intensity`. `tunnel` means the probes will run inside TLS.
    pub fn probes_for(&self, port: u16, tunnel: bool, intensity: u8) -> Vec<&Probe> {
        if self.excluded_ports.contains(&port) {
            return Vec::new();
        }

        let registered = |probe: &Probe| {
            let ports = if tunnel { &probe.ssl_ports } else { &probe.ports };
            ports.as_ref().is_some_and(|ports| ports.contains(&port))
        };
        let tcp = || self.probes.iter().filter(|p| p.protocol == Protocol::TCP);

        tcp()
            .filter(|p| p.payload.is_empty())
            .chain(tcp().filter(|p| !p.payload.is_empty() && registered(p)))
            .chain(tcp().filter(|p| !p.payload.is_empty() && !registered(p) && p.rarity <= intensity))
            .collect()
    }

    /// UDP probes for a port: registered ones first, then the rest up to `intensity`.
    pub fn udp_probes_for(&self, port: u16, intensity: u8) -> Vec<&Probe> {
        let udp = || self.probes.iter().filter(|p| p.protocol == Protocol::UDP);
        let registered = |probe: &Probe| probe.ports.as_ref().is_some_and(|ports| ports.contains(&port));

        udp()
            .filter(|p| registered(p))
            .chain(udp().filter(|p| !registered(p) && p.rarity <= intensity))
            .collect()
    }

    pub fn probe(&self, name: &str) -> Option<&Probe> {
        self.probes.iter().find(|p| p.name == name)
    }
}

impl Default for ServiceDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub protocol: Protocol,
    pub name: String,
    pub payload: Vec<u8>,
    pub total_wait_ms: u64,
    pub tcp_wrapped_ms: Option<u64>,
    pub ports: Option<Vec<u16>>,
    pub ssl_ports: Option<Vec<u16>>,
    pub rarity: u8,
    pub fallback: Vec<String>,
    pub matches: Vec<Match>,
    pub soft_matches: Vec<Match>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub service: String,
    pub pattern: Regex,
    pub version_info: VersionInfo,
    pub is_soft_match: bool,
}

#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub product: Option<String>,          // p/Product/
    pub version: Option<String>,          // v/Version/
    pub info: Option<String>,             // i/Info/
    pub hostname: Option<String>,         // h/Hostname/
    pub operating_system: Option<String>, // o/OS/
    pub device_type: Option<String>,      // d/Device/
    pub cpe: Vec<String>,                 // cpe:/a:vendor:product:version/
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMatch {
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Confidence {
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
}

impl ServiceMatch {
    pub fn from_match(service: &str, version_info: &VersionInfo, is_soft: bool) -> Self {
        Self {
            service_name: service.to_string(),
            product: version_info.product.clone(),
            version: version_info.version.clone(),
            info: version_info.info.clone(),
            hostname: version_info.hostname.clone(),
            os: version_info.operating_system.clone(),
            device_type: version_info.device_type.clone(),
            cpe: version_info.cpe.clone(),
            confidence: if is_soft {
                Confidence::Low
            } else {
                Confidence::High
            },
        }
    }
}
