use crate::llm::LLMAnalyzer;
use crate::os_db::OSDatabase;
use crate::packet::{build_ether_syn_packet, parse_tcp_response, random_source_port, TcpResponseType, TcpFingerprint};
use crate::service;
use crate::service_db::ServiceMatcher;
use crate::types::{HostResult, PortResult, PortState, ScanConfig, ScanResults};
use anyhow::Result;
use pnet::datalink::{self, NetworkInterface, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

pub struct Scanner {
    config: ScanConfig,
    service_matcher: Option<ServiceMatcher>,
    os_db: Option<OSDatabase>,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        let matcher = match ServiceMatcher::load_default() {
            Ok(m) => {
                info!("Loaded Nmap service signature database");
                Some(m)
            },
            Err(e) => {
                warn!("Failed to load service matcher: {}", e);
                info!("Service database not available, using basic detection");
                None
            }
        };

        let os_db = match OSDatabase::load_from_file("nmap-os-db") {
            Ok(db) => {
                info!("Loaded Nmap OS database");
                Some(db)
            },
            Err(e) => {
                warn!("Failed to load OS database: {}", e);
                None
            }
        };

        Scanner {
            config,
            service_matcher: matcher,
            os_db,
        }
    }

    fn find_interface_by_ip(ip: Ipv4Addr) -> Option<NetworkInterface> {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.ips.iter().any(|nw| nw.ip() == IpAddr::V4(ip)))
    }

    async fn arp_resolve(interface: &NetworkInterface, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Result<MacAddr> {
        let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Failed to create datalink channel for ARP")),
        };

        let src_mac = interface.mac.ok_or_else(|| anyhow::anyhow!("Interface has no MAC address"))?;

        let mut buffer = [0u8; 42];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
            eth_packet.set_destination(MacAddr::broadcast());
            eth_packet.set_source(src_mac);
            eth_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_packet = MutableArpPacket::new(&mut buffer[14..]).unwrap();
            arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(src_mac);
            arp_packet.set_sender_proto_addr(src_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(target_ip);
        }

        tx.send_to(&buffer, None).ok_or_else(|| anyhow::anyhow!("Failed to send ARP request"))??;

        let timeout = Duration::from_secs(2);
        let start = Instant::now();

        while start.elapsed() < timeout {
            if let Ok(packet) = rx.next() {
                let eth = EthernetPacket::new(packet).unwrap();
                if eth.get_ethertype() == EtherTypes::Arp {
                    let arp = ArpPacket::new(eth.payload()).unwrap();
                    if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == target_ip {
                        return Ok(arp.get_sender_hw_addr());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        Err(anyhow::anyhow!("ARP timeout for {}", target_ip))
    }

    pub async fn scan(&self) -> Result<ScanResults> {
        let start_time = Instant::now();
        info!(
            "Starting SYN scan of {} targets, {} ports per target",
            self.config.targets.len(),
            self.config.ports.len()
        );
        let mut results = Vec::new();

        for target in &self.config.targets {
            match self.scan_host(*target).await {
                Ok(host_result) => results.push(host_result),
                Err(e) => warn!("Failed to scan {}: {}", target, e),
            }
        }

        let total_duration = start_time.elapsed();

        Ok(ScanResults {
            targets: results,
            total_duration_ms: total_duration.as_millis() as u64,
            scan_type: "SYN".to_string(),
            timestamp: get_timestamp(),
        })
    }

    async fn scan_host(&self, target: IpAddr) -> Result<HostResult> {
        let start_time = Instant::now();
        info!("Scanning host: {}", target);

        let target_v4 = match target {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 not yet supported"));
            }
        };

        let src_ip = get_source_ip(target_v4)?;
        let interface = Self::find_interface_by_ip(src_ip)
            .ok_or_else(|| anyhow::anyhow!("Could not find interface for IP {}", src_ip))?;

        let src_mac = interface.mac.ok_or_else(|| anyhow::anyhow!("Source interface has no MAC"))?;

        let dst_mac = match Self::arp_resolve(&interface, src_ip, target_v4).await {
            Ok(mac) => mac,
            Err(_) => {
                return self.scan_host_connect(target, target_v4).await;
            }
        };

        let (mut tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow::anyhow!("Failed to create datalink channel")),
        };

        let (result_tx, mut result_rx) = mpsc::channel(1000);
        let timeout_duration = self.config.timeout;

        tokio::task::spawn_blocking(move || {
            receive_responses_datalink(rx, result_tx, timeout_duration, src_ip);
        });

        let results_map: Arc<Mutex<HashMap<u16, PortResult>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut fingerprints = Vec::new();

        for &port in &self.config.ports {
            let src_port = random_source_port();
            let packet = build_ether_syn_packet(src_mac, dst_mac, src_ip, target_v4, src_port, port);

            if let Some(res) = tx.send_to(&packet, None) {
                let _ = res;
            }

            {
                let mut map = results_map.lock().await;
                map.insert(
                    port,
                    PortResult {
                        port,
                        state: PortState::Filtered,
                        latency_ms: None,
                        service: None,
                        llm_analysis: None,
                        protocol: Some(crate::types::Protocol::TCP),
                    },
                );
            }

            if let Some(rate) = self.config.rate_limit {
                let delay = Duration::from_micros(1_000_000 / rate as u64);
                tokio::time::sleep(delay).await;
            }
        }

        let response_deadline = Instant::now() + self.config.timeout + Duration::from_millis(500);

        while Instant::now() < response_deadline {
            match tokio::time::timeout(Duration::from_millis(100), result_rx.recv()).await {
                Ok(Some((port, response_type, latency, fingerprint))) => {
                    let state = match response_type {
                        TcpResponseType::SynAck => PortState::Open,
                        TcpResponseType::Rst => PortState::Closed,
                        TcpResponseType::Other => PortState::Filtered,
                    };

                    if state == PortState::Open {
                        fingerprints.push(fingerprint);
                    }

                    let mut map = results_map.lock().await;
                    if let Some(result) = map.get_mut(&port) {
                        result.state = state;
                        result.latency_ms = if state == PortState::Open {
                            Some(latency)
                        } else {
                            None
                        };
                    }
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        let map = results_map.lock().await;
        let mut port_results: Vec<_> = map.values().cloned().collect();
        drop(map);

        port_results.sort_by_key(|r| r.port);

        if self.config.service_detection {
            info!("Starting service detection for {} open ports",
                  port_results.iter().filter(|p| p.state == PortState::Open).count());

            for port_result in &mut port_results {
                if port_result.state == PortState::Open {
                    match service::grab_banner_with_db(
                        target,
                        port_result.port,
                        self.config.timeout,
                        self.service_matcher.as_ref()
                    ).await {
                        Ok(service_info) => {
                            debug!("Detected service on {}:{}: {}", target, port_result.port, service_info.service_name);
                            port_result.service = Some(service_info);
                        }
                        Err(e) => {
                            debug!("Failed to detect service on {}:{}: {}", target, port_result.port, e);
                        }
                    }
                }
            }
        }

        if self.config.llm_enabled {
            info!("Starting LLM analysis for open ports");
            let llm = LLMAnalyzer::from_env();

            if llm.is_enabled() {
                for port_result in &mut port_results {
                    if port_result.state == PortState::Open {
                        if let Some(ref service_info) = port_result.service {
                            match llm.analyze_banner(&service_info.banner, port_result.port).await {
                                Ok(Some(analysis)) => {
                                    info!("LLM analyzed {}:{} - Confidence: {:.2}",
                                          target, port_result.port, analysis.confidence);
                                    port_result.llm_analysis = Some(analysis);
                                }
                                Ok(None) => {
                                    debug!("LLM disabled for {}:{}", target, port_result.port);
                                }
                                Err(e) => {
                                    warn!("LLM analysis failed for {}:{}: {}", target, port_result.port, e);
                                }
                            }
                        }
                    }
                }
            } else {
                warn!("LLM enabled but GEMINI_API_KEY not set");
            }
        }

        let duration = start_time.elapsed();

        let mut os_guess = None;
        let mut os_fingerprint_str = None;

        if let Some(fp) = fingerprints.first() {
            os_fingerprint_str = Some(format!("TTL={}, WIN={}", fp.ttl, fp.window_size));
            if let Some(db) = &self.os_db {
                if let Some(matched) = db.match_os(fp.ttl, fp.window_size) {
                    os_guess = Some(matched.name.clone());
                }
            }
        }

        Ok(HostResult {
            ip: target,
            hostname: None,
            ports: port_results,
            scan_duration_ms: duration.as_millis() as u64,
            os_guess,
            os_fingerprint: os_fingerprint_str,
        })
    }

    /// Fallback when ARP resolution fails (e.g. scanning non-local targets)
    async fn scan_host_connect(&self, target: IpAddr, _target_v4: Ipv4Addr) -> Result<HostResult> {
        let start_time = Instant::now();
        let results_map: Arc<Mutex<HashMap<u16, PortResult>>> = Arc::new(Mutex::new(HashMap::new()));

        let mut futures = Vec::new();
        for &port in &self.config.ports {
            let timeout = self.config.timeout;
            let results_map_clone = results_map.clone();

            futures.push(tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(target, port);
                let state = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => PortState::Open,
                    Ok(Err(_)) => PortState::Closed,
                    Err(_) => PortState::Filtered,
                };

                let mut map = results_map_clone.lock().await;
                map.insert(port, PortResult {
                    port,
                    state,
                    latency_ms: None,
                    service: None,
                    llm_analysis: None,
                    protocol: Some(crate::types::Protocol::TCP),
                });
            }));
        }

        for f in futures {
            let _ = f.await;
        }

        let map = results_map.lock().await;
        let mut port_results: Vec<_> = map.values().cloned().collect();
        port_results.sort_by_key(|r| r.port);

        Ok(HostResult {
            ip: target,
            hostname: None,
            ports: port_results,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
            os_guess: None,
            os_fingerprint: None,
        })
    }
}

fn receive_responses_datalink(
    mut rx: Box<dyn DataLinkReceiver>,
    result_tx: mpsc::Sender<(u16, TcpResponseType, u64, TcpFingerprint)>,
    timeout: Duration,
    local_ip: Ipv4Addr,
) {
    let start_time = Instant::now();
    let deadline = start_time + timeout + Duration::from_secs(2);

    loop {
        if Instant::now() > deadline {
            break;
        }

        match rx.next() {
            Ok(packet) => {
                let eth = EthernetPacket::new(packet).unwrap();
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();

                    if ipv4.get_destination() != local_ip {
                        continue;
                    }

                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some((port, response_type, fingerprint)) = parse_tcp_response(eth.payload()) {
                            let latency = Instant::now().duration_since(start_time).as_millis() as u64;
                            if result_tx.blocking_send((port, response_type, latency, fingerprint)).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Find the first non-loopback IPv4 address on the system
fn get_source_ip(_target: Ipv4Addr) -> Result<Ipv4Addr> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        if interface.is_loopback() { continue; }
        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                if ipv4.is_unspecified() || ipv4.is_loopback() { continue; }
                return Ok(ipv4);
            }
        }
    }
    Err(anyhow::anyhow!("No network interface found"))
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970i64;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md as i64 { month = i + 1; break; }
        days -= md as i64;
    }
    let day = days + 1;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
}
