use crate::connect::{Answer, Limits, Transport};
use futures::stream::{self, FuturesUnordered, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::debug;

/// Answering on any of these, even with a refusal, proves the host is up.
const PING_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 135];
/// Also ping a few requested ports: they may be all a filtered host answers on.
const SCAN_PORTS_PINGED: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiscoveryMethod {
    None,         // -Pn: skip discovery, treat all as up
    Default,      // TCP connect to common ports
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
    scan_ports: &[u16],
    limits: &Limits,
) -> Vec<DiscoveryResult> {
    let ports: Vec<u16> = match method {
        DiscoveryMethod::None | DiscoveryMethod::Arp => {
            let label = if method == DiscoveryMethod::Arp { "arp" } else { "no-ping" };
            return targets
                .iter()
                .map(|ip| DiscoveryResult {
                    ip: *ip,
                    is_up: true,
                    latency_ms: None,
                    method: label.to_string(),
                })
                .collect();
        }
        DiscoveryMethod::PingScanOnly | DiscoveryMethod::Default => PING_PORTS
            .iter()
            .chain(scan_ports.iter().take(SCAN_PORTS_PINGED))
            .copied()
            .collect(),
        DiscoveryMethod::TcpSyn => vec![80, 443],
        DiscoveryMethod::TcpAck => vec![80],
    };

    stream::iter(targets)
        .map(|&ip| tcp_ping(ip, &ports, timeout, limits))
        .buffer_unordered(limits.max_sockets)
        .collect()
        .await
}

async fn tcp_ping(ip: IpAddr, ports: &[u16], timeout: Duration, limits: &Limits) -> DiscoveryResult {
    let start = Instant::now();

    let mut attempts: FuturesUnordered<_> = ports
        .iter()
        .map(|&port| async move { (port, limits.probe(SocketAddr::new(ip, port), timeout, Transport::Tcp).await) })
        .collect();

    while let Some((port, answer)) = attempts.next().await {
        if answer != Answer::Silent {
            debug!("Host {} is up ({:?} on port {})", ip, answer, port);
            return DiscoveryResult {
                ip,
                is_up: true,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                method: format!("tcp-{}", port),
            };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refused_ports_prove_a_host_is_up() {
        let targets: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let limits = Limits::new(16, None);
        let found = discover_hosts(&targets, DiscoveryMethod::Default, Duration::from_secs(1), &[], &limits).await;
        assert!(found[0].is_up);
    }

    #[tokio::test]
    async fn no_ping_marks_every_target_up_without_probing() {
        let targets: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap()];
        let limits = Limits::new(1, None);
        let found = discover_hosts(&targets, DiscoveryMethod::None, Duration::from_secs(1), &[], &limits).await;
        assert!(found[0].is_up);
    }
}
