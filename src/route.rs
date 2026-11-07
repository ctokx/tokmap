//! Finding the way to a target at the Ethernet level, and discovering hosts with raw frames.

use crate::packet::{build_echo_frame, parse_echo_reply};
use anyhow::Result;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::debug;

pub const CAPTURE_POLL: Duration = Duration::from_millis(50);
/// Also sizes the Npcap kernel buffer. pnet's 4 KiB default drops replies during a burst.
const CAPTURE_BUFFER: usize = 8 * 1024 * 1024;
const ARP_WAIT: Duration = Duration::from_millis(500);
const NEXT_HOP_WAIT: Duration = Duration::from_millis(1000);
/// Discard port: a harmless place to send the datagram that reveals the next hop.
const REVEAL_PORT: u16 = 9;

pub type CaptureChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

pub fn open_capture(interface: &NetworkInterface) -> Result<CaptureChannel> {
    let config = datalink::Config {
        read_timeout: Some(CAPTURE_POLL),
        read_buffer_size: CAPTURE_BUFFER,
        ..Default::default()
    };
    match datalink::channel(interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(anyhow::anyhow!("Unsupported datalink channel")),
        Err(e) => Err(anyhow::anyhow!("Failed to create datalink channel: {}", e)),
    }
}

/// The source address the OS would route to `target`. Connecting a UDP socket sends nothing.
pub fn source_ip_for(target: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match target {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect((target, REVEAL_PORT)).ok()?;
    Some(socket.local_addr().ok()?.ip()).filter(|ip| !ip.is_unspecified())
}

/// Runs blocking capture work on a plain thread with a hard limit, so a capture read that ignores
/// its timeout can neither stall the scan nor hold up process exit.
pub(crate) async fn on_capture_thread<T: Send + 'static>(
    limit: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (done_tx, done_rx) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(work());
    });
    tokio::time::timeout(limit, done_rx).await.ok()?.ok()
}

fn arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
    let mut buffer = [0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    let mut arp = MutableArpPacket::new(&mut buffer[14..]).unwrap();
    arp.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target);
    buffer
}

fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    (arp.get_operation() == ArpOperations::Reply)
        .then(|| (arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

/// Asks every target at once on one capture. Returns who answered, or None if capture failed.
pub async fn arp_sweep(
    interface: NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
) -> Option<HashMap<Ipv4Addr, MacAddr>> {
    on_capture_thread(ARP_WAIT * 2 + CAPTURE_POLL * 4, move || {
        let (mut tx, mut rx) = open_capture(&interface).ok()?;
        let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
        let mut found = HashMap::new();

        // Two rounds: one lost request must not make a live host look down.
        for _ in 0..2 {
            for &target in wanted.iter().filter(|t| !found.contains_key(*t)) {
                let _ = tx.send_to(&arp_request(src_mac, src_ip, target), None);
            }
            let start = Instant::now();
            while start.elapsed() < ARP_WAIT && found.len() < wanted.len() {
                match rx.next() {
                    Ok(frame) => {
                        if let Some((ip, mac)) = parse_arp_reply(frame).filter(|(ip, _)| wanted.contains(ip)) {
                            found.insert(ip, mac);
                        }
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(1)),
                }
            }
            if found.len() == wanted.len() {
                break;
            }
        }
        Some(found)
    })
    .await
    .flatten()
}

/// Pings every target through `gateway`. Returns who answered, or None if capture failed.
pub async fn icmp_sweep(
    interface: NetworkInterface,
    src_mac: MacAddr,
    gateway: MacAddr,
    src_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
    wait: Duration,
) -> Option<HashSet<Ipv4Addr>> {
    on_capture_thread(wait + CAPTURE_POLL * 4, move || {
        let (mut tx, mut rx) = open_capture(&interface).ok()?;
        let identifier = rand::random::<u16>();
        let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();

        for &target in &wanted {
            let _ = tx.send_to(&build_echo_frame(src_mac, gateway, src_ip, target, identifier), None);
        }

        let mut found = HashSet::new();
        let start = Instant::now();
        while start.elapsed() < wait && found.len() < wanted.len() {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ip) = parse_echo_reply(frame, identifier).filter(|ip| wanted.contains(ip)) {
                        found.insert(ip);
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        Some(found)
    })
    .await
    .flatten()
}

/// The destination MAC of a frame carrying a UDP datagram from `src_ip` to `target`.
fn revealed_next_hop(frame: &[u8], src_ip: IpAddr, target: IpAddr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(frame)?;
    let port = |payload: &[u8]| UdpPacket::new(payload).map(|udp| udp.get_destination());

    let matches = if eth.get_ethertype() == EtherTypes::Ipv4 {
        let ip = Ipv4Packet::new(eth.payload())?;
        ip.get_next_level_protocol() == IpNextHeaderProtocols::Udp
            && IpAddr::V4(ip.get_source()) == src_ip
            && IpAddr::V4(ip.get_destination()) == target
            && port(ip.payload()) == Some(REVEAL_PORT)
    } else if eth.get_ethertype() == EtherTypes::Ipv6 {
        let ip = Ipv6Packet::new(eth.payload())?;
        ip.get_next_header() == IpNextHeaderProtocols::Udp
            && IpAddr::V6(ip.get_source()) == src_ip
            && IpAddr::V6(ip.get_destination()) == target
            && port(ip.payload()) == Some(REVEAL_PORT)
    } else {
        false
    };

    matches.then(|| eth.get_destination())
}

/// Learns the MAC a packet to `target` is sent to, by sending one UDP datagram through the OS and
/// watching the frame leave. This works for gateways and IPv6 neighbours on every platform
/// without reading routing tables, because the OS does the routing and neighbour lookup itself.
pub async fn learn_next_hop(
    interface: NetworkInterface,
    src_ip: IpAddr,
    target: IpAddr,
) -> Option<MacAddr> {
    on_capture_thread(NEXT_HOP_WAIT + CAPTURE_POLL * 4, move || {
        let (_tx, mut rx) = open_capture(&interface).ok()?;
        let socket = UdpSocket::bind(SocketAddr::new(src_ip, 0)).ok()?;
        socket.connect((target, REVEAL_PORT)).ok()?;
        socket.send(b"tokmap route check").ok()?;

        let start = Instant::now();
        while start.elapsed() < NEXT_HOP_WAIT {
            match rx.next() {
                Ok(frame) => {
                    if let Some(mac) = revealed_next_hop(frame, src_ip, target) {
                        return Some(mac);
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        debug!("No outgoing frame seen for {}", target);
        None
    })
    .await
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build_probe_frame;
    use crate::types::ScanType;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;

    const ME: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
    const HOP: MacAddr = MacAddr(2, 0, 0, 0, 0, 2);

    fn udp_frame(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 8];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_source(ME);
            eth.set_destination(HOP);
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut frame[14..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(28);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(src);
            ip.set_destination(dst);
        }
        MutableUdpPacket::new(&mut frame[34..]).unwrap().set_destination(port);
        frame
    }

    #[test]
    fn next_hop_comes_from_the_matching_frame_only() {
        let (me, target) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 0, 2, 1));
        let frame = udp_frame(me, target, REVEAL_PORT);
        assert_eq!(revealed_next_hop(&frame, me.into(), target.into()), Some(HOP));

        let wrong_port = udp_frame(me, target, 53);
        assert_eq!(revealed_next_hop(&wrong_port, me.into(), target.into()), None);

        let wrong_target = udp_frame(me, Ipv4Addr::new(192, 0, 2, 2), REVEAL_PORT);
        assert_eq!(revealed_next_hop(&wrong_target, me.into(), target.into()), None);

        let tcp = build_probe_frame(ME, HOP, me.into(), target.into(), 1, 2, ScanType::Syn, 64).unwrap();
        assert_eq!(revealed_next_hop(&tcp, me.into(), target.into()), None);
    }

    #[test]
    fn arp_reply_is_decoded_and_requests_are_ignored() {
        let (me, peer) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let mut frame = arp_request(HOP, peer, me);
        assert_eq!(parse_arp_reply(&frame), None);

        MutableArpPacket::new(&mut frame[14..]).unwrap().set_operation(ArpOperations::Reply);
        assert_eq!(parse_arp_reply(&frame), Some((peer, HOP)));
    }

    #[test]
    fn source_address_comes_from_routing() {
        assert_eq!(source_ip_for("127.0.0.1".parse().unwrap()), Some("127.0.0.1".parse().unwrap()));
    }
}
