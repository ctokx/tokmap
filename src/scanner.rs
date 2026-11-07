use crate::connect::{self, Answer, Limits, Transport};
use crate::discovery::{discover_hosts, DiscoveryMethod};
use crate::llm::LLMAnalyzer;
use crate::os_db::{OSDatabase, ObservedFingerprint};
use crate::os_probe::{build_observed_fingerprint, find_closed_port, find_open_port, send_os_probes};
use crate::packet::{
    build_probe_frame, interpret_response, parse_reply, random_source_port, silent_port_state,
    Reply, TcpFingerprint,
};
use crate::route::{self, open_capture};
use crate::service;
use crate::service_db::ServiceMatcher;
use crate::target::reverse_dns;
use crate::trace::{self, TraceRoute};
use crate::types::{
    format_utc, Hop, HostResult, PortResult, PortState, Protocol, ScanConfig, ScanResults, ScanType,
};
use crate::vendors::Vendors;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

const HOST_PARALLELISM: usize = 64;
/// Each raw host opens its own capture handle, and every handle sees all traffic.
const RAW_HOST_PARALLELISM: usize = 8;
const PORT_PARALLELISM: usize = 32;
/// One sender tops out near 16k packets/s on Windows, so large sweeps get several. Elsewhere one
/// is plenty, and every extra capture socket makes the kernel copy each packet again.
const PORTS_PER_SENDER: usize = 8192;
const MAX_SENDERS: usize = if cfg!(windows) { 4 } else { 1 };
/// Unanswered probes allowed at once. A Linux capture socket buffers only a few hundred packets,
/// so sending faster than replies are read loses them, and a lost reply is a wrong answer.
const PROBE_WINDOW: isize = 256;
const MIN_PROBE_WINDOW: isize = 8;
/// How long a full window may block before its probes are written off as silent ports.
const WINDOW_STALL: Duration = Duration::from_millis(5);
/// Once a host is answering, this much silence means the remaining ports are not going to.
const MIN_QUIET_WAIT: Duration = Duration::from_millis(100);
const NORMAL_TTL: u8 = 64;
const TRACE_WAIT: Duration = Duration::from_secs(2);
const TRACE_DEFAULT_PORT: u16 = 80;
const VENDOR_FILE: &str = "oui.csv";

pub struct Scanner {
    config: ScanConfig,
    service_matcher: Option<ServiceMatcher>,
    os_db: Option<OSDatabase>,
    llm_provider_name: Option<String>,
    limits: Limits,
    raw_slots: Arc<Semaphore>,
    interfaces: OnceLock<Vec<NetworkInterface>>,
    vendors: OnceLock<Option<Vendors>>,
    known_macs: Mutex<HashMap<IpAddr, MacAddr>>,
    gateways: tokio::sync::Mutex<HashMap<(String, bool), Option<MacAddr>>>,
    used_raw: AtomicBool,
    used_connect: AtomicBool,
}

/// How this machine reaches a target at the Ethernet level.
#[derive(Clone)]
struct Link {
    interface: NetworkInterface,
    src_ip: IpAddr,
    src_mac: MacAddr,
    on_link: bool,
}

/// What a raw scan needs. Only targets with a known next hop get one.
struct RawRoute {
    link: Link,
    target: IpAddr,
    dst_mac: MacAddr,
    _slot: OwnedSemaphorePermit,
}

#[derive(Default)]
struct ScannedPorts {
    ports: Vec<PortResult>,
    os_guess: Option<String>,
    os_fingerprint: Option<String>,
    mac: Option<MacAddr>,
    trace: Option<Vec<Hop>>,
}

fn port_result(port: u16, state: PortState, latency_ms: Option<u64>, protocol: Protocol) -> PortResult {
    PortResult {
        port,
        state,
        latency_ms,
        service: None,
        llm_analysis: None,
        protocol: Some(protocol),
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Self::with_llm_provider(config, None)
    }

    pub fn with_llm_provider(config: ScanConfig, llm_provider: Option<String>) -> Self {
        // Loaded on demand: a plain port scan must not pay for signatures it will not use.
        let wants_signatures = config.service_detection || config.record_dir.is_some();
        let matcher = wants_signatures
            .then(|| ServiceMatcher::load(&config.signature_files))
            .and_then(|loaded| match loaded {
                Ok(m) => Some(m),
                Err(e) => {
                    warn!("Failed to load signatures: {}", e);
                    None
                }
            });

        let os_db = config.os_detection.then(|| OSDatabase::load_from_file("nmap-os-db")).and_then(|loaded| {
            match loaded {
                Ok(db) => {
                    info!("Loaded OS database");
                    Some(db)
                }
                Err(e) => {
                    warn!("Failed to load OS database: {}", e);
                    None
                }
            }
        });

        let limits = Limits::new(config.max_concurrent, config.rate_limit);

        Scanner {
            config,
            service_matcher: matcher,
            os_db,
            llm_provider_name: llm_provider,
            limits,
            raw_slots: Arc::new(Semaphore::new(RAW_HOST_PARALLELISM)),
            interfaces: OnceLock::new(),
            vendors: OnceLock::new(),
            known_macs: Mutex::new(HashMap::new()),
            gateways: tokio::sync::Mutex::new(HashMap::new()),
            used_raw: AtomicBool::new(false),
            used_connect: AtomicBool::new(false),
        }
    }

    pub async fn scan(&self) -> Result<ScanResults> {
        let start_time = Instant::now();
        let targets = self.live_targets().await;
        info!(
            "Scanning {} targets, {} TCP and {} UDP ports per target",
            targets.len(),
            if self.config.tcp_scan { self.config.ports.len() } else { 0 },
            if self.config.udp_scan { self.config.udp_ports.len() } else { 0 },
        );

        let mut results: Vec<HostResult> = stream::iter(targets)
            .map(|target| async move { (target, self.scan_host(target).await) })
            .buffer_unordered(HOST_PARALLELISM)
            .filter_map(|(target, result)| async move {
                result.map_err(|e| warn!("Failed to scan {}: {}", target, e)).ok()
            })
            .collect()
            .await;
        results.sort_by_key(|host| host.ip);

        Ok(ScanResults {
            targets: results,
            total_duration_ms: start_time.elapsed().as_millis() as u64,
            scan_type: self.scan_label(),
            timestamp: get_timestamp(),
        })
    }

    /// Names what actually ran: a SYN scan falls back to connect when no raw route exists.
    fn scan_label(&self) -> String {
        if self.config.ping_scan_only {
            return "PING".to_string();
        }
        let tcp = self.config.tcp_scan.then(|| match self.config.scan_type {
            ScanType::Connect => "CONNECT",
            ScanType::Ack => "ACK",
            ScanType::Window => "WINDOW",
            ScanType::Fin => "FIN",
            ScanType::Null => "NULL",
            ScanType::Xmas => "XMAS",
            ScanType::Syn | ScanType::Udp => {
                match (self.used_raw.load(Ordering::Relaxed), self.used_connect.load(Ordering::Relaxed)) {
                    (true, true) => "SYN+CONNECT",
                    (false, true) => "CONNECT",
                    _ => "SYN",
                }
            }
        });
        let udp = self.config.udp_scan.then_some("UDP");
        [tcp, udp].into_iter().flatten().collect::<Vec<_>>().join("+")
    }

    async fn live_targets(&self) -> Vec<IpAddr> {
        let targets = &self.config.targets;
        if !self.config.host_discovery {
            return targets.clone();
        }
        // Scanning one host answers the same question as pinging it first.
        if targets.len() < 2 && !self.config.ping_scan_only {
            return targets.clone();
        }

        let mut up: HashSet<IpAddr> = HashSet::new();
        let mut needs_tcp_ping: Vec<IpAddr> = Vec::new();
        let mut neighbours: HashMap<String, (Link, Vec<Ipv4Addr>)> = HashMap::new();
        let mut remote: HashMap<String, (Link, Vec<Ipv4Addr>)> = HashMap::new();

        for &target in targets {
            let raw_allowed = self.config.scan_type != ScanType::Connect;
            match (target, raw_allowed.then(|| self.link_to(target)).flatten()) {
                (IpAddr::V4(ip), Some(link)) if link.src_ip.is_ipv4() => {
                    let group = if link.on_link { &mut neighbours } else { &mut remote };
                    if !link.on_link {
                        needs_tcp_ping.push(target);
                    }
                    group.entry(link.interface.name.clone()).or_insert((link, Vec::new())).1.push(ip);
                }
                _ => needs_tcp_ping.push(target),
            }
        }

        // ARP is decisive for neighbours: anything that does not answer it is not there.
        for (link, ips) in neighbours.into_values() {
            let IpAddr::V4(src_ip) = link.src_ip else { continue };
            match route::arp_sweep(link.interface.clone(), link.src_mac, src_ip, ips.clone()).await {
                Some(found) => {
                    let mut known = self.known_macs.lock().unwrap();
                    for (ip, mac) in found {
                        up.insert(IpAddr::V4(ip));
                        known.insert(IpAddr::V4(ip), mac);
                    }
                }
                None => needs_tcp_ping.extend(ips.into_iter().map(IpAddr::V4)),
            }
        }

        let pings = async {
            let mut answered = Vec::new();
            for (link, ips) in remote.into_values() {
                let IpAddr::V4(src_ip) = link.src_ip else { continue };
                let Some(&first) = ips.first() else { continue };
                let Some(gateway) = self.next_hop(&link, IpAddr::V4(first)).await else { continue };
                let found = route::icmp_sweep(
                    link.interface.clone(), link.src_mac, gateway, src_ip, ips, self.config.timeout,
                )
                .await;
                answered.extend(found.into_iter().flatten().map(IpAddr::V4));
            }
            answered
        };
        let tcp_pings = discover_hosts(
            &needs_tcp_ping,
            DiscoveryMethod::Default,
            self.config.timeout,
            &self.config.ports,
            &self.limits,
        );
        let (answered, tcp_results) = tokio::join!(pings, tcp_pings);

        up.extend(answered);
        up.extend(tcp_results.iter().filter(|r| r.is_up).map(|r| r.ip));

        let mut live: Vec<IpAddr> = up.into_iter().collect();
        live.sort();
        info!("Host discovery: {} of {} hosts up", live.len(), targets.len());
        live
    }

    async fn scan_host(&self, target: IpAddr) -> Result<HostResult> {
        let start_time = Instant::now();
        info!("Scanning host: {}", target);

        let name_lookup = async {
            if self.config.resolve_dns { reverse_dns(target).await } else { None }
        };
        let (hostname, scanned) = tokio::join!(name_lookup, self.scan_target(target));
        let scanned = scanned?;

        let mac = scanned.mac.or_else(|| self.known_macs.lock().unwrap().get(&target).copied());

        Ok(HostResult {
            ip: target,
            hostname,
            ports: scanned.ports,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
            os_guess: scanned.os_guess,
            os_fingerprint: scanned.os_fingerprint,
            mac: mac.map(|m| m.to_string()),
            vendor: mac.and_then(|m| self.vendor_of(m)),
            trace: scanned.trace,
        })
    }

    fn vendor_of(&self, mac: MacAddr) -> Option<String> {
        self.vendors
            .get_or_init(|| Vendors::load(VENDOR_FILE))
            .as_ref()?
            .lookup(&mac.to_string())
            .map(str::to_string)
    }

    async fn scan_target(&self, target: IpAddr) -> Result<ScannedPorts> {
        if self.config.ping_scan_only {
            return Ok(ScannedPorts::default());
        }

        let scan_type = self.config.scan_type;
        let raw_tcp = self.config.tcp_scan && scan_type != ScanType::Connect;
        let wants_route = raw_tcp || self.config.traceroute || self.config.os_detection;
        let route = if wants_route { self.raw_route(target).await } else { None };

        let (mut ports, fingerprints) = match (&route, self.config.tcp_scan) {
            (_, false) => (Vec::new(), Vec::new()),
            (Some(route), true) if raw_tcp => {
                self.used_raw.store(true, Ordering::Relaxed);
                self.raw_sweep(route).await?
            }
            _ if raw_tcp && scan_type != ScanType::Syn => {
                anyhow::bail!("{:?} scan needs raw packets, and there is no raw route to this target", scan_type);
            }
            _ => {
                self.used_connect.store(true, Ordering::Relaxed);
                (self.tcp_connect_sweep(target).await, Vec::new())
            }
        };

        if self.config.udp_scan {
            ports.extend(self.udp_sweep(target).await);
        }

        self.detect_services(target, &mut ports).await;
        self.record_responses(target, &ports).await?;
        self.analyze_with_llm(target, &mut ports).await;

        let (os_guess, os_fingerprint) = self
            .fingerprint_os(target, route.as_ref(), &ports, &fingerprints)
            .await?;

        let trace = if self.config.traceroute {
            self.trace_route(target, route.as_ref(), &ports).await
        } else {
            None
        };

        Ok(ScannedPorts {
            ports,
            os_guess,
            os_fingerprint,
            mac: route.as_ref().filter(|r| r.link.on_link).map(|r| r.dst_mac),
            trace,
        })
    }

    fn link_to(&self, target: IpAddr) -> Option<Link> {
        if target.is_loopback() || is_link_local(target) {
            return None;
        }
        let src_ip = route::source_ip_for(target)?;
        if src_ip == target {
            return None;
        }

        let interfaces = self.interfaces.get_or_init(datalink::interfaces);
        let interface = interfaces.iter().find(|iface| iface.ips.iter().any(|nw| nw.ip() == src_ip))?;
        Some(Link {
            interface: interface.clone(),
            src_ip,
            src_mac: interface.mac?,
            on_link: interface.ips.iter().any(|nw| nw.contains(target)),
        })
    }

    /// The MAC to address frames for `target` to: the host itself on-link, otherwise the gateway.
    async fn next_hop(&self, link: &Link, target: IpAddr) -> Option<MacAddr> {
        if let Some(&mac) = self.known_macs.lock().unwrap().get(&target) {
            return Some(mac);
        }

        if link.on_link {
            let mac = route::learn_next_hop(link.interface.clone(), link.src_ip, target).await?;
            self.known_macs.lock().unwrap().insert(target, mac);
            return Some(mac);
        }

        // Every off-link target behind an interface shares a gateway, so ask once.
        let mut gateways = self.gateways.lock().await;
        let key = (link.interface.name.clone(), target.is_ipv4());
        if let Some(&known) = gateways.get(&key) {
            return known;
        }
        let gateway = route::learn_next_hop(link.interface.clone(), link.src_ip, target).await;
        gateways.insert(key, gateway);
        gateway
    }

    async fn raw_route(&self, target: IpAddr) -> Option<RawRoute> {
        let link = self.link_to(target)?;
        let slot = self.raw_slots.clone().acquire_owned().await.ok()?;
        let dst_mac = self.next_hop(&link, target).await?;
        Some(RawRoute { link, target, dst_mac, _slot: slot })
    }

    async fn tcp_connect_sweep(&self, target: IpAddr) -> Vec<PortResult> {
        let answers = connect::sweep(
            target,
            &self.config.ports,
            self.config.timeout,
            self.config.max_retries,
            &self.limits,
            Transport::Tcp,
        )
        .await;

        let mut results: Vec<PortResult> = answers
            .into_iter()
            .map(|(port, answer)| match answer {
                Answer::Open(ms) => port_result(port, PortState::Open, Some(ms), Protocol::TCP),
                Answer::Closed => port_result(port, PortState::Closed, None, Protocol::TCP),
                Answer::Silent => port_result(port, PortState::Filtered, None, Protocol::TCP),
            })
            .collect();
        results.sort_by_key(|r| r.port);
        results
    }

    async fn udp_sweep(&self, target: IpAddr) -> Vec<PortResult> {
        let answers = connect::sweep(
            target,
            &self.config.udp_ports,
            self.config.timeout,
            self.config.max_retries,
            &self.limits,
            Transport::Udp,
        )
        .await;

        let mut results: Vec<PortResult> = answers
            .into_iter()
            .map(|(port, answer)| match answer {
                Answer::Open(ms) => port_result(port, PortState::Open, Some(ms), Protocol::UDP),
                Answer::Closed => port_result(port, PortState::Closed, None, Protocol::UDP),
                Answer::Silent => port_result(port, PortState::OpenFiltered, None, Protocol::UDP),
            })
            .collect();
        results.sort_by_key(|r| r.port);
        results
    }

    async fn raw_sweep(&self, route: &RawRoute) -> Result<(Vec<PortResult>, Vec<TcpFingerprint>)> {
        let scan_type = self.config.scan_type;
        let (tx, rx) = open_capture(&route.link.interface)?;
        let mut senders = vec![tx];
        for _ in 1..(self.config.ports.len() / PORTS_PER_SENDER).clamp(1, MAX_SENDERS) {
            senders.push(open_capture(&route.link.interface)?.0);
        }
        let src_port = random_source_port();

        // Unbounded: sending and draining alternate, and the capture thread must never stall.
        let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
        let in_flight = Arc::new(AtomicIsize::new(0));
        let replies_seen = in_flight.clone();
        let (local, target) = (route.link.src_ip, route.target);
        // A plain thread: a capture read may outlive the scan and must not hold up process exit.
        std::thread::spawn(move || {
            receive_replies(rx, reply_tx, local, target, src_port, &replies_seen)
        });

        let silent = silent_port_state(scan_type);
        let mut results: HashMap<u16, PortResult> = self
            .config
            .ports
            .iter()
            .map(|&port| (port, port_result(port, silent, None, Protocol::TCP)))
            .collect();
        let mut unanswered: HashSet<u16> = results.keys().copied().collect();
        let mut fingerprints = Vec::new();

        for attempt in 0..=self.config.max_retries {
            let before = unanswered.len();
            senders = self.send_wave(route, senders, &unanswered, src_port, &in_flight).await?;

            let deadline = tokio::time::Instant::now() + self.config.timeout;
            let quiet_wait = (self.config.timeout / 4).max(MIN_QUIET_WAIT);
            let mut wait_until = deadline;
            while !unanswered.is_empty() {
                let Ok(Some((reply, latency))) =
                    tokio::time::timeout_at(wait_until, reply_rx.recv()).await
                else {
                    break;
                };
                wait_until = deadline.min(tokio::time::Instant::now() + quiet_wait);

                let (port, state) = match reply {
                    Reply::Tcp { port, kind, fingerprint } => {
                        let state = interpret_response(kind, fingerprint.window_size, scan_type);
                        if state == PortState::Open && unanswered.contains(&port) {
                            fingerprints.push(fingerprint);
                        }
                        (port, state)
                    }
                    Reply::Unreachable { port } => (port, PortState::Filtered),
                };

                if !unanswered.remove(&port) {
                    continue;
                }
                if let Some(result) = results.get_mut(&port) {
                    result.state = state;
                    result.latency_ms = (state == PortState::Open).then_some(latency);
                }
            }

            let recovered = before - unanswered.len();
            if attempt > 0 && recovered > 0 {
                // A retry got answers the first try did not, so packets are being lost.
                self.limits.note_loss();
            }
            // Same rule as the connect sweep: retry only while retries still turn up answers.
            if unanswered.is_empty() || (attempt > 0 && recovered == 0) {
                break;
            }
        }

        let mut port_results: Vec<PortResult> = results.into_values().collect();
        port_results.sort_by_key(|r| r.port);
        Ok((port_results, fingerprints))
    }

    /// Sends one probe per port on blocking threads, since a packet send can stall an async worker.
    async fn send_wave(
        &self,
        route: &RawRoute,
        mut senders: Vec<Box<dyn DataLinkSender>>,
        ports: &HashSet<u16>,
        src_port: u16,
        in_flight: &Arc<AtomicIsize>,
    ) -> Result<Vec<Box<dyn DataLinkSender>>> {
        let wave: Vec<u16> = ports.iter().copied().collect();
        let (src_mac, dst_mac) = (route.link.src_mac, route.dst_mac);
        let (src_ip, target) = (route.link.src_ip, route.target);
        let scan_type = self.config.scan_type;
        let pacer = self.limits.pacer.clone();
        let window = (PROBE_WINDOW >> self.limits.backoff()).max(MIN_PROBE_WINDOW);
        let in_flight = in_flight.clone();
        in_flight.store(0, Ordering::Relaxed);

        let senders = tokio::task::spawn_blocking(move || {
            let share = wave.len().div_ceil(senders.len()).max(1);
            std::thread::scope(|scope| {
                for (tx, ports) in senders.iter_mut().zip(wave.chunks(share)) {
                    let (pacer, in_flight) = (&pacer, &in_flight);
                    scope.spawn(move || {
                        for &port in ports {
                            pacer.wait_blocking();
                            wait_for_window(in_flight, window);
                            in_flight.fetch_add(1, Ordering::Relaxed);
                            let frame = build_probe_frame(
                                src_mac, dst_mac, src_ip, target, src_port, port, scan_type, NORMAL_TTL,
                            );
                            if let Some(Some(Err(e))) = frame.map(|f| tx.send_to(&f, None)) {
                                debug!("Failed to send probe to {}:{}: {}", target, port, e);
                            }
                        }
                    });
                }
            });
            senders
        })
        .await?;
        Ok(senders)
    }

    async fn detect_services(&self, target: IpAddr, ports: &mut [PortResult]) {
        if !self.config.service_detection {
            return;
        }

        let wanted: Vec<(u16, bool)> = ports
            .iter()
            .filter_map(|p| {
                let udp = p.protocol == Some(Protocol::UDP);
                let candidate = p.state == PortState::Open || (udp && p.state == PortState::OpenFiltered);
                candidate.then_some((p.port, udp))
            })
            .collect();
        info!("Starting service detection for {} ports", wanted.len());

        let wait = self.config.timeout;
        let matcher = self.service_matcher.as_ref();
        let intensity = self.config.version_intensity;
        let sockets = &self.limits.sockets;

        let mut found: HashMap<(u16, bool), service::ServiceInfo> = stream::iter(wanted)
            .map(|(port, udp)| async move {
                let detected = if udp {
                    service::detect_udp(target, port, wait, matcher, intensity, sockets).await
                } else {
                    service::grab_banner_with_db(target, port, wait, matcher, intensity, sockets).await.ok()
                };
                ((port, udp), detected)
            })
            .buffer_unordered(PORT_PARALLELISM)
            .filter_map(|(key, detected)| async move { detected.map(|info| (key, info)) })
            .collect()
            .await;

        for result in ports {
            let udp = result.protocol == Some(Protocol::UDP);
            if let Some(info) = found.remove(&(result.port, udp)) {
                // An answer to a version probe proves a silent UDP port is really open.
                if udp && !info.banner.is_empty() {
                    result.state = PortState::Open;
                }
                result.service = Some(info);
            }
        }
    }

    /// Saves every probe's raw reply as evidence for building signatures.
    async fn record_responses(&self, target: IpAddr, ports: &[PortResult]) -> Result<()> {
        let (Some(dir), Some(matcher)) = (&self.config.record_dir, &self.service_matcher) else {
            return Ok(());
        };
        std::fs::create_dir_all(dir)?;

        let mut lines = String::new();
        for result in ports.iter().filter(|p| p.state == PortState::Open || p.state == PortState::OpenFiltered) {
            let udp = result.protocol == Some(Protocol::UDP);
            let recordings = service::record_port(
                target, result.port, udp, self.config.timeout, matcher, &self.limits.sockets,
            )
            .await;
            for recording in recordings {
                lines.push_str(&serde_json::to_string(&recording)?);
                lines.push('\n');
            }
        }

        let file = format!("{}/{}.jsonl", dir, target.to_string().replace(':', "_"));
        std::fs::write(file, lines)?;
        Ok(())
    }

    async fn analyze_with_llm(&self, target: IpAddr, port_results: &mut [PortResult]) {
        if !self.config.llm_enabled {
            return;
        }

        info!("Starting LLM analysis for open ports");
        let llm = if let Some(ref provider_name) = self.llm_provider_name {
            LLMAnalyzer::from_provider_name(provider_name)
        } else {
            LLMAnalyzer::from_env()
        };

        if !llm.is_enabled() {
            warn!("LLM enabled but no API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or OLLAMA_HOST");
            return;
        }

        info!("Using {} LLM provider", llm.provider_name());
        for port_result in port_results.iter_mut().filter(|p| p.state == PortState::Open) {
            let Some(ref service_info) = port_result.service else { continue };
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

    async fn trace_route(
        &self,
        target: IpAddr,
        route: Option<&RawRoute>,
        ports: &[PortResult],
    ) -> Option<Vec<Hop>> {
        let Some(route) = route else {
            warn!("Traceroute needs a raw route, skipping {}", target);
            return None;
        };

        let open = ports
            .iter()
            .find(|p| p.state == PortState::Open && p.protocol == Some(Protocol::TCP))
            .map_or(TRACE_DEFAULT_PORT, |p| p.port);
        let request = TraceRoute {
            interface: route.link.interface.clone(),
            src_mac: route.link.src_mac,
            dst_mac: route.dst_mac,
            src_ip: route.link.src_ip,
            target,
            port: open,
        };
        tokio::task::spawn_blocking(move || trace::trace(&request, TRACE_WAIT)).await.ok()
    }

    async fn fingerprint_os(
        &self,
        target: IpAddr,
        route: Option<&RawRoute>,
        port_results: &[PortResult],
        fingerprints: &[TcpFingerprint],
    ) -> Result<(Option<String>, Option<String>)> {
        let passive_summary = || {
            fingerprints.first().map(|f| format!("TTL={} WIN={}", f.ttl, f.window_size))
        };

        if !self.config.os_detection {
            return Ok((None, passive_summary()));
        }
        let (Some(route), IpAddr::V4(dst_ip)) = (route, target) else {
            warn!("OS detection needs a raw IPv4 route, skipping {}", target);
            return Ok((None, None));
        };
        let IpAddr::V4(src_ip) = route.link.src_ip else {
            return Ok((None, None));
        };

        let open_ports: Vec<u16> = port_results.iter()
            .filter(|r| r.state == PortState::Open && r.protocol == Some(Protocol::TCP))
            .map(|r| r.port)
            .collect();

        let observed = if let Some(open_port) = find_open_port(&open_ports) {
            let closed_port = find_closed_port(&open_ports);
            info!("Sending OS fingerprint probes to {}:{} (open) / {} (closed)", target, open_port, closed_port);

            let interface = route.link.interface.clone();
            let (src_mac, dst_mac) = (route.link.src_mac, route.dst_mac);
            let probe_result = tokio::task::spawn_blocking(move || {
                let (mut tx, mut rx) = open_capture(&interface).ok()?;
                Some(send_os_probes(
                    &mut tx, &mut rx,
                    src_mac, dst_mac,
                    src_ip, dst_ip,
                    open_port, closed_port,
                ))
            }).await.ok().flatten();

            probe_result.and_then(|r| build_observed_fingerprint(&r))
        } else if !fingerprints.is_empty() {
            let window_sizes: Vec<u16> = fingerprints.iter().map(|f| f.window_size).collect();
            Some(ObservedFingerprint::from_responses(fingerprints[0].ttl, window_sizes, &[]))
        } else {
            None
        };

        if let Some(observed) = observed {
            let summary = format!("TTL={} WIN={} SP={} GCD={} ISR={}",
                observed.ttl,
                observed.window_sizes.iter().map(|w| format!("{:X}", w)).collect::<Vec<_>>().join(","),
                observed.sp, observed.gcd, observed.isr);

            let guess = self.os_db.as_ref().and_then(|db| {
                let matches = db.match_fingerprint(&observed);
                matches.first().map(|best| {
                    debug!("OS detection: {} candidates, best: {} ({:.0}%)", matches.len(), best.name, best.score * 100.0);
                    format!("{} (score: {:.0}%)", best.name, best.score * 100.0)
                })
            });
            return Ok((guess, Some(summary)));
        }

        let guess = fingerprints.first().and_then(|f| {
            self.os_db.as_ref()?.match_os(f.ttl, f.window_size).map(|m| m.name.clone())
        });
        Ok((guess, passive_summary()))
    }
}

/// Holds a sender back while the window is full. Silent ports never free their slots, so after
/// WINDOW_STALL the outstanding probes are written off rather than stalling the sweep.
fn wait_for_window(in_flight: &AtomicIsize, window: isize) {
    let start = Instant::now();
    while in_flight.load(Ordering::Relaxed) >= window {
        if start.elapsed() >= WINDOW_STALL {
            in_flight.store(0, Ordering::Relaxed);
            return;
        }
        std::thread::yield_now();
    }
}

fn receive_replies(
    mut rx: Box<dyn DataLinkReceiver>,
    result_tx: mpsc::UnboundedSender<(Reply, u64)>,
    local_ip: IpAddr,
    target: IpAddr,
    src_port: u16,
    in_flight: &AtomicIsize,
) {
    let start_time = Instant::now();

    while !result_tx.is_closed() {
        let Ok(frame) = rx.next() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        if let Some(reply) = parse_reply(frame, local_ip, target, src_port) {
            in_flight.fetch_sub(1, Ordering::Relaxed);
            let latency = start_time.elapsed().as_millis() as u64;
            if result_tx.send((reply, latency)).is_err() {
                break;
            }
        }
    }
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format_utc(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_window_does_not_block() {
        let in_flight = AtomicIsize::new(PROBE_WINDOW - 1);
        let start = Instant::now();
        wait_for_window(&in_flight, PROBE_WINDOW);
        assert!(start.elapsed() < WINDOW_STALL);
        assert_eq!(in_flight.load(Ordering::Relaxed), PROBE_WINDOW - 1);
    }

    #[test]
    fn full_window_with_silent_ports_is_written_off() {
        let in_flight = AtomicIsize::new(PROBE_WINDOW);
        wait_for_window(&in_flight, PROBE_WINDOW);
        assert_eq!(in_flight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn replies_release_a_full_window() {
        let in_flight = Arc::new(AtomicIsize::new(PROBE_WINDOW));
        let reader = in_flight.clone();
        let thread = std::thread::spawn(move || reader.fetch_sub(1, Ordering::Relaxed));
        wait_for_window(&in_flight, PROBE_WINDOW);
        thread.join().unwrap();
        assert!(in_flight.load(Ordering::Relaxed) < PROBE_WINDOW);
    }

    #[test]
    fn link_local_is_recognised() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(!is_link_local("fd00::1".parse().unwrap()));
        assert!(!is_link_local("10.0.0.1".parse().unwrap()));
    }
}
