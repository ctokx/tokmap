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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<Hop>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: Option<u64>,
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
    pub udp_ports: Vec<u16>,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub max_retries: u32,
    pub rate_limit: Option<u32>,
    pub service_detection: bool,
    pub llm_enabled: bool,
    pub scan_type: ScanType,
    pub tcp_scan: bool,
    pub udp_scan: bool,
    pub traceroute: bool,
    pub host_discovery: bool,
    pub ping_scan_only: bool,
    pub version_intensity: u8,
    pub os_detection: bool,
    pub resolve_dns: bool,
    pub signature_files: Vec<String>,
    pub record_dir: Option<String>,
}

/// Seconds since the Unix epoch as an RFC 3339 UTC timestamp.
pub fn format_utc(secs: u64) -> String {
    let mut days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let (hours, minutes, seconds) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);

    let is_leap = |year: i64| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut year = 1970i64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    for (i, &length) in month_days.iter().enumerate() {
        if days < length {
            month = i + 1;
            break;
        }
        days -= length;
    }

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, days + 1, hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates_handle_epoch_and_leap_days() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_798_761_599), "2026-12-31T23:59:59Z");
    }

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
                mac: None,
                vendor: None,
                trace: None,
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
