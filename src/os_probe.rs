use crate::os_db::ObservedFingerprint;
use crate::packet::{
    build_ether_os_probe, nmap_os_probe_options, parse_tcp_response_with_isn, OsProbeKind,
    TcpResponseType,
};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::debug;

const OS_PROBE_INTER_PACKET_MS: u64 = 100;
const OS_PROBE_RESPONSE_WAIT_MS: u64 = 2500;

#[derive(Debug, Default)]
pub struct OsProbeResult {
    pub window_sizes: Vec<u16>,
    pub isn_values: Vec<u32>,
    pub ttl: Option<u8>,
    pub tcp_options_seen: Vec<String>,
}

pub fn send_os_probes(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    open_port: u16,
    closed_port: u16,
) -> OsProbeResult {
    let mut result = OsProbeResult::default();
    let probe_src_port = crate::packet::random_source_port();

    let syn_probes = [
        OsProbeKind::Syn1,
        OsProbeKind::Syn2,
        OsProbeKind::Syn3,
        OsProbeKind::Syn4,
        OsProbeKind::Syn5,
        OsProbeKind::Syn6,
    ];

    for kind in &syn_probes {
        let opts = nmap_os_probe_options(*kind);
        let pkt = build_ether_os_probe(src_mac, dst_mac, src_ip, dst_ip, probe_src_port, open_port, &opts);
        let _ = tx.send_to(&pkt, None);
        std::thread::sleep(Duration::from_millis(OS_PROBE_INTER_PACKET_MS));
    }

    let ecn_opts = nmap_os_probe_options(OsProbeKind::Ecn);
    let ecn_pkt = build_ether_os_probe(src_mac, dst_mac, src_ip, dst_ip, probe_src_port, open_port, &ecn_opts);
    let _ = tx.send_to(&ecn_pkt, None);

    let closed_probes = [
        OsProbeKind::T5,
        OsProbeKind::T6,
        OsProbeKind::T7,
    ];

    for kind in &closed_probes {
        let opts = nmap_os_probe_options(*kind);
        let pkt = build_ether_os_probe(src_mac, dst_mac, src_ip, dst_ip, probe_src_port, closed_port, &opts);
        let _ = tx.send_to(&pkt, None);
        std::thread::sleep(Duration::from_millis(OS_PROBE_INTER_PACKET_MS));
    }

    let deadline = Instant::now() + Duration::from_millis(OS_PROBE_RESPONSE_WAIT_MS);

    loop {
        if Instant::now() > deadline {
            break;
        }

        match rx.next() {
            Ok(packet) => {
                let eth = match EthernetPacket::new(packet) {
                    Some(e) => e,
                    None => continue,
                };

                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }

                let ip_payload = eth.payload();
                let ipv4 = match Ipv4Packet::new(ip_payload) {
                    Some(p) => p,
                    None => continue,
                };

                if ipv4.get_destination() != src_ip {
                    continue;
                }

                if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }

                if let Some((_port, resp_type, fingerprint, isn)) = parse_tcp_response_with_isn(ip_payload) {
                    match resp_type {
                        TcpResponseType::SynAck => {
                            result.window_sizes.push(fingerprint.window_size);
                            result.isn_values.push(isn);
                            if result.ttl.is_none() {
                                result.ttl = Some(fingerprint.ttl);
                            }
                            debug!("OS probe SYN-ACK: ISN={} WIN={} TTL={}", isn, fingerprint.window_size, fingerprint.ttl);
                        }
                        TcpResponseType::Rst => {
                            if result.ttl.is_none() {
                                result.ttl = Some(fingerprint.ttl);
                            }
                        }
                        TcpResponseType::Other => {}
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    result
}

pub fn build_observed_fingerprint(probe_result: &OsProbeResult) -> Option<ObservedFingerprint> {
    let ttl = probe_result.ttl?;

    let isn_diffs: Vec<u32> = probe_result
        .isn_values
        .windows(2)
        .map(|w| w[1].wrapping_sub(w[0]))
        .collect();

    Some(ObservedFingerprint::from_responses(
        ttl,
        probe_result.window_sizes.clone(),
        &isn_diffs,
    ))
}

pub fn find_closed_port(open_ports: &[u16]) -> u16 {
    let candidates = [1, 3, 9, 65535, 65534, 55000, 54321];
    for &p in &candidates {
        if !open_ports.contains(&p) {
            return p;
        }
    }
    let mut rng_port: u16 = 60000;
    loop {
        if !open_ports.contains(&rng_port) {
            return rng_port;
        }
        rng_port += 1;
    }
}

pub fn find_open_port(open_ports: &[u16]) -> Option<u16> {
    open_ports.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_closed_port() {
        let open = vec![80, 443, 22];
        let closed = find_closed_port(&open);
        assert!(!open.contains(&closed));
    }

    #[test]
    fn test_find_open_port() {
        let open = vec![80, 443];
        assert_eq!(find_open_port(&open), Some(80));
        let empty: Vec<u16> = vec![];
        assert_eq!(find_open_port(&empty), None);
    }

    #[test]
    fn test_build_observed_fingerprint_no_ttl() {
        let result = OsProbeResult::default();
        assert!(build_observed_fingerprint(&result).is_none());
    }

    #[test]
    fn test_build_observed_fingerprint_with_data() {
        let result = OsProbeResult {
            window_sizes: vec![65535, 65535, 65535],
            isn_values: vec![1000, 2000, 3000],
            ttl: Some(64),
            tcp_options_seen: vec![],
        };
        let fp = build_observed_fingerprint(&result);
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.window_sizes.len(), 3);
    }
}
