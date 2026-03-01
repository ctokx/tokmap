use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<crate::service::ServiceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_analysis: Option<crate::llm::LLMAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    #[serde(rename = "closed|filtered")]
    ClosedFiltered,
    Unfiltered,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanType {
    Syn,        // -sS (default)
    Connect,    // -sT
    Ack,        // -sA
    Window,     // -sW
    Fin,        // -sF
    Null,       // -sN
    Xmas,       // -sX
    Udp,        // -sU
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Vec<PortResult>,
    pub scan_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_guess: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResults {
    pub targets: Vec<HostResult>,
    pub total_duration_ms: u64,
    pub scan_type: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub rate_limit: Option<u32>,
    pub service_detection: bool,
    pub llm_enabled: bool,
    pub scan_type: ScanType,
    pub udp_scan: bool,
    pub host_discovery: bool,
    pub ping_scan_only: bool,
    pub version_intensity: u8,
    pub os_detection: bool,
    pub resolve_dns: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_state_serialization() {
        assert_eq!(serde_json::to_string(&PortState::Open).unwrap(), "\"open\"");
        assert_eq!(serde_json::to_string(&PortState::Closed).unwrap(), "\"closed\"");
        assert_eq!(serde_json::to_string(&PortState::Filtered).unwrap(), "\"filtered\"");
    }

    #[test]
    fn test_port_result_serialization() {
        let result = PortResult {
            port: 80,
            state: PortState::Open,
            latency_ms: Some(5),
            service: None,
            llm_analysis: None,
            protocol: Some(Protocol::TCP),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"port\":80"));
        assert!(json.contains("\"state\":\"open\""));
    }

    #[test]
    fn test_json_roundtrip() {
        let original = ScanResults {
            targets: vec![HostResult {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: Some("test.local".to_string()),
                ports: vec![
                    PortResult {
                        port: 80,
                        state: PortState::Open,
                        latency_ms: Some(10),
                        service: None,
                        llm_analysis: None,
                        protocol: Some(Protocol::TCP),
                    },
                ],
                scan_duration_ms: 500,
                os_guess: None,
                os_fingerprint: None,
            }],
            total_duration_ms: 600,
            scan_type: "SYN".to_string(),
            timestamp: "2026-02-04T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ScanResults = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.targets.len(), 1);
        assert_eq!(deserialized.total_duration_ms, 600);
        assert_eq!(deserialized.targets[0].ports[0].port, 80);
    }
}
