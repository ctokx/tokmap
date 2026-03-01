use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiscoveryMethod {
    None,         // -Pn: skip discovery, treat all as up
    Default,      // ICMP echo + TCP SYN 443 + TCP ACK 80 + ICMP timestamp
    PingScanOnly, // -sn: ping scan only, no port scan
    TcpSyn,       // -PS
    TcpAck,       // -PA
    Arp,          // local network only
}

#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub ip: IpAddr,
    pub is_up: bool,
    pub latency_ms: Option<u64>,
    pub method: String,
}

pub async fn discover_hosts(
    targets: &[IpAddr],
    method: DiscoveryMethod,
    timeout: Duration,
) -> Vec<DiscoveryResult> {
    match method {
        DiscoveryMethod::None => {
            targets
                .iter()
                .map(|ip| DiscoveryResult {
                    ip: *ip,
                    is_up: true,
                    latency_ms: None,
                    method: "no-ping".to_string(),
                })
                .collect()
        }
        DiscoveryMethod::PingScanOnly | DiscoveryMethod::Default => {
            let mut results = Vec::new();
            for &ip in targets {
                let result = tcp_ping(ip, &[80, 443, 22], timeout).await;
                results.push(result);
            }
            results
        }
        DiscoveryMethod::TcpSyn => {
            let mut results = Vec::new();
            for &ip in targets {
                let result = tcp_ping(ip, &[80, 443], timeout).await;
                results.push(result);
            }
            results
        }
        DiscoveryMethod::TcpAck => {
            let mut results = Vec::new();
            for &ip in targets {
                let result = tcp_ping(ip, &[80], timeout).await;
                results.push(result);
            }
            results
        }
        DiscoveryMethod::Arp => {
            // ARP is handled at the scanner level
            targets
                .iter()
                .map(|ip| DiscoveryResult {
                    ip: *ip,
                    is_up: true,
                    latency_ms: None,
                    method: "arp".to_string(),
                })
                .collect()
        }
    }
}

async fn tcp_ping(ip: IpAddr, ports: &[u16], timeout: Duration) -> DiscoveryResult {
    let start = std::time::Instant::now();

    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                let latency = start.elapsed().as_millis() as u64;
                debug!("Host {} is up (TCP connect to port {})", ip, port);
                return DiscoveryResult {
                    ip,
                    is_up: true,
                    latency_ms: Some(latency),
                    method: format!("tcp-syn-{}", port),
                };
            }
            Ok(Err(e)) => {
                // Connection refused = host is up (port closed but host responds)
                let err_str = format!("{}", e);
                if err_str.contains("refused") || err_str.contains("reset") {
                    let latency = start.elapsed().as_millis() as u64;
                    debug!("Host {} is up (connection refused on port {})", ip, port);
                    return DiscoveryResult {
                        ip,
                        is_up: true,
                        latency_ms: Some(latency),
                        method: format!("tcp-rst-{}", port),
                    };
                }
            }
            Err(_) => {
                continue;
            }
        }
    }

    debug!("Host {} appears down (no response)", ip);
    DiscoveryResult {
        ip,
        is_up: false,
        latency_ms: None,
        method: "no-response".to_string(),
    }
}
