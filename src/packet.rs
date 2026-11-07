use crate::types::ScanType;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn tcp_checksum_raw(buf: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let tcp_pkt = TcpPacket::new(buf).unwrap();
    pnet::packet::tcp::ipv4_checksum(&tcp_pkt, &src_ip, &dst_ip)
}

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;

pub fn build_ether_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    scan_type: ScanType,
) -> Vec<u8> {
    let total_len = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buffer = vec![0u8; total_len];

    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_LEN]).unwrap();
        eth_packet.set_source(src_mac);
        eth_packet.set_destination(dst_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);
    }

    let ip_tcp_buffer = build_tcp_packet(src_ip, dst_ip, src_port, dst_port, scan_type);
    buffer[ETHERNET_HEADER_LEN..].copy_from_slice(&ip_tcp_buffer);

    buffer
}

pub fn build_ether_syn_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_ether_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, ScanType::Syn)
}

pub fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    scan_type: ScanType,
) -> Vec<u8> {
    if scan_type == ScanType::Udp {
        return Vec::new();
    }
    build_tcp_packet_with_ttl(src_ip, dst_ip, src_port, dst_port, scan_type, 64)
}

fn build_tcp_packet_with_ttl(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    scan_type: ScanType,
    ttl: u8,
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buffer = vec![0u8; total_len];

    fill_tcp_header(&mut buffer[IPV4_HEADER_LEN..], src_port, dst_port, scan_type);
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..]).unwrap();
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
        tcp_packet.set_checksum(checksum);
    }

    let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(total_len as u16);
    ip_packet.set_identification(rand::random::<u16>());
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);
    let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);
    drop(ip_packet);

    buffer
}

pub fn build_syn_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, ScanType::Syn)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpResponseType {
    SynAck,
    Rst,
    Other,
}

#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub ttl: u8,
    pub window_size: u16,
    pub tcp_flags: u8,
}

pub fn parse_tcp_response(ip_packet_bytes: &[u8]) -> Option<(u16, TcpResponseType, TcpFingerprint)> {
    let ip = Ipv4Packet::new(ip_packet_bytes)?;

    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let ttl = ip.get_ttl();
    let tcp = TcpPacket::new(ip.payload())?;

    let src_port = tcp.get_source();
    let flags = tcp.get_flags();
    let window_size = tcp.get_window();

    let response_type = if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
        TcpResponseType::SynAck
    } else if (flags & TcpFlags::RST) != 0 {
        TcpResponseType::Rst
    } else {
        TcpResponseType::Other
    };

    let fingerprint = TcpFingerprint {
        ttl,
        window_size,
        tcp_flags: flags,
    };

    Some((src_port, response_type, fingerprint))
}

pub fn interpret_response(
    response_type: TcpResponseType,
    window_size: u16,
    scan_type: ScanType,
) -> crate::types::PortState {
    use crate::types::PortState;

    match scan_type {
        ScanType::Syn => match response_type {
            TcpResponseType::SynAck => PortState::Open,
            TcpResponseType::Rst => PortState::Closed,
            TcpResponseType::Other => PortState::Filtered,
        },
        ScanType::Ack | ScanType::Window => match response_type {
            TcpResponseType::Rst if scan_type == ScanType::Window && window_size > 0 => {
                PortState::Open
            }
            TcpResponseType::Rst if scan_type == ScanType::Window => PortState::Closed,
            TcpResponseType::Rst => PortState::Unfiltered,
            _ => PortState::Filtered,
        },
        ScanType::Fin | ScanType::Null | ScanType::Xmas => match response_type {
            TcpResponseType::Rst => PortState::Closed,
            _ => PortState::OpenFiltered,
        },
        ScanType::Connect => match response_type {
            TcpResponseType::SynAck => PortState::Open,
            TcpResponseType::Rst => PortState::Closed,
            _ => PortState::Filtered,
        },
        ScanType::Udp => PortState::OpenFiltered,
    }
}

pub fn random_source_port() -> u16 {
    rand::random::<u16>() % 16384 + 49152
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OsProbeKind {
    Syn1, Syn2, Syn3, Syn4, Syn5, Syn6,
    Ecn,
    T2, T3, T4, T5, T6, T7,
    UdpClosed,
}

#[derive(Debug, Clone)]
pub struct OsProbeOptions {
    pub mss: Option<u16>,
    pub window_size: u16,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp: bool,
    pub nop: bool,
    pub ecn: bool,
    pub df: bool,
    pub ttl: u8,
    pub flags: u8,
}

impl Default for OsProbeOptions {
    fn default() -> Self {
        Self {
            mss: Some(1460),
            window_size: 1,
            window_scale: None,
            sack_permitted: false,
            timestamp: false,
            nop: false,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        }
    }
}

fn build_tcp_options(opts: &OsProbeOptions) -> Vec<u8> {
    let mut options = Vec::new();

    if let Some(mss) = opts.mss {
        options.push(2u8);
        options.push(4u8);
        options.extend_from_slice(&mss.to_be_bytes());
    }

    if opts.sack_permitted {
        options.push(4u8);
        options.push(2u8);
    }

    if opts.timestamp {
        options.push(8u8);
        options.push(10u8);
        let ts_val = rand::random::<u32>();
        options.extend_from_slice(&ts_val.to_be_bytes());
        options.extend_from_slice(&0u32.to_be_bytes());
    }

    if let Some(ws) = opts.window_scale {
        options.push(3u8);
        options.push(3u8);
        options.push(ws);
    }

    if opts.nop {
        options.push(1u8);
    }

    while options.len() % 4 != 0 {
        options.push(0u8);
    }

    while options.len() < 20 {
        options.push(0u8);
    }
    options.truncate(20);

    options
}

pub fn build_os_probe_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    opts: &OsProbeOptions,
) -> Vec<u8> {
    let tcp_opts_bytes = build_tcp_options(opts);
    let tcp_total = TCP_HEADER_LEN + tcp_opts_bytes.len();
    let total_len = IPV4_HEADER_LEN + tcp_total;
    let mut buffer = vec![0u8; total_len];

    let seq: u32 = rand::random();

    let tcp_start = IPV4_HEADER_LEN;
    let data_offset_words = (tcp_total / 4) as u8;

    buffer[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    buffer[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    buffer[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    buffer[tcp_start + 8..tcp_start + 12].copy_from_slice(&0u32.to_be_bytes());
    buffer[tcp_start + 12] = data_offset_words << 4;
    buffer[tcp_start + 13] = opts.flags;
    buffer[tcp_start + 14..tcp_start + 16].copy_from_slice(&opts.window_size.to_be_bytes());
    buffer[tcp_start + 16..tcp_start + 18].copy_from_slice(&0u16.to_be_bytes());
    buffer[tcp_start + 18..tcp_start + 20].copy_from_slice(&0u16.to_be_bytes());

    let opts_start = tcp_start + TCP_HEADER_LEN;
    buffer[opts_start..opts_start + tcp_opts_bytes.len()].copy_from_slice(&tcp_opts_bytes);

    let tcp_cksum = tcp_checksum_raw(&buffer[tcp_start..], src_ip, dst_ip);
    buffer[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    {
        let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(if opts.ecn { 1 } else { 0 });
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_identification(rand::random::<u16>());
        ip_packet.set_flags(if opts.df { 2 } else { 0 });
        ip_packet.set_fragment_offset(0);
        ip_packet.set_ttl(opts.ttl);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        ip_packet.set_checksum(0);

        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);
    }

    buffer
}

pub fn build_ether_os_probe(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    opts: &OsProbeOptions,
) -> Vec<u8> {
    let ip_tcp = build_os_probe_packet(src_ip, dst_ip, src_port, dst_port, opts);
    let total_len = ETHERNET_HEADER_LEN + ip_tcp.len();
    let mut buffer = vec![0u8; total_len];

    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..ETHERNET_HEADER_LEN]).unwrap();
        eth_packet.set_source(src_mac);
        eth_packet.set_destination(dst_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);
    }

    buffer[ETHERNET_HEADER_LEN..].copy_from_slice(&ip_tcp);
    buffer
}

pub fn nmap_os_probe_options(kind: OsProbeKind) -> OsProbeOptions {
    match kind {
        OsProbeKind::Syn1 => OsProbeOptions {
            mss: Some(265),
            window_size: 1,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Syn2 => OsProbeOptions {
            mss: Some(265),
            window_size: 63,
            window_scale: Some(0),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Syn3 => OsProbeOptions {
            mss: Some(265),
            window_size: 4,
            window_scale: Some(5),
            sack_permitted: true,
            timestamp: true,
            nop: false,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Syn4 => OsProbeOptions {
            mss: Some(265),
            window_size: 4,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Syn5 => OsProbeOptions {
            mss: Some(265),
            window_size: 16,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: false,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Syn6 => OsProbeOptions {
            mss: Some(265),
            window_size: 512,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::Ecn => OsProbeOptions {
            mss: Some(265),
            window_size: 3,
            window_scale: Some(10),
            sack_permitted: false,
            timestamp: false,
            nop: true,
            ecn: true,
            df: true,
            ttl: 64,
            flags: TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR,
        },
        OsProbeKind::T2 => OsProbeOptions {
            mss: None,
            window_size: 128,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: 0,
        },
        OsProbeKind::T3 => OsProbeOptions {
            mss: None,
            window_size: 256,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: false,
            ttl: 64,
            flags: TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH,
        },
        OsProbeKind::T4 => OsProbeOptions {
            mss: None,
            window_size: 1024,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::ACK,
        },
        OsProbeKind::T5 => OsProbeOptions {
            mss: None,
            window_size: 31337,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: false,
            ttl: 64,
            flags: TcpFlags::SYN,
        },
        OsProbeKind::T6 => OsProbeOptions {
            mss: None,
            window_size: 32768,
            window_scale: Some(10),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: true,
            ttl: 64,
            flags: TcpFlags::ACK,
        },
        OsProbeKind::T7 => OsProbeOptions {
            mss: None,
            window_size: 65535,
            window_scale: Some(15),
            sack_permitted: true,
            timestamp: true,
            nop: true,
            ecn: false,
            df: false,
            ttl: 64,
            flags: TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        },
        OsProbeKind::UdpClosed => OsProbeOptions {
            mss: None,
            window_size: 0,
            window_scale: None,
            sack_permitted: false,
            timestamp: false,
            nop: false,
            ecn: false,
            df: false,
            ttl: 64,
            flags: 0,
        },
    }
}

pub fn parse_tcp_response_with_isn(ip_packet_bytes: &[u8]) -> Option<(u16, TcpResponseType, TcpFingerprint, u32)> {
    let ip = Ipv4Packet::new(ip_packet_bytes)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let ttl = ip.get_ttl();
    let tcp = TcpPacket::new(ip.payload())?;
    let src_port = tcp.get_source();
    let flags = tcp.get_flags();
    let window_size = tcp.get_window();
    let isn = tcp.get_sequence();

    let response_type = if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
        TcpResponseType::SynAck
    } else if (flags & TcpFlags::RST) != 0 {
        TcpResponseType::Rst
    } else {
        TcpResponseType::Other
    };

    let fingerprint = TcpFingerprint { ttl, window_size, tcp_flags: flags };
    Some((src_port, response_type, fingerprint, isn))
}

/// What a captured frame means for a raw scan.
#[derive(Debug, Clone)]
pub enum Reply {
    Tcp { port: u16, kind: TcpResponseType, fingerprint: TcpFingerprint },
    /// An ICMP "administratively blocked" style error quoting one of our probes.
    Unreachable { port: u16 },
}

fn scan_flags(scan_type: ScanType) -> u8 {
    match scan_type {
        ScanType::Ack | ScanType::Window => TcpFlags::ACK,
        ScanType::Fin => TcpFlags::FIN,
        ScanType::Null => 0,
        ScanType::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        ScanType::Syn | ScanType::Connect | ScanType::Udp => TcpFlags::SYN,
    }
}

fn fill_tcp_header(buffer: &mut [u8], src_port: u16, dst_port: u16, scan_type: ScanType) {
    let mut tcp = MutableTcpPacket::new(buffer).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(rand::random::<u32>());
    if matches!(scan_type, ScanType::Ack | ScanType::Window) {
        tcp.set_acknowledgement(rand::random::<u32>());
    }
    tcp.set_data_offset(5);
    tcp.set_flags(scan_flags(scan_type));
    tcp.set_window(64240);
}

fn ipv6_tcp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    scan_type: ScanType,
    hop_limit: u8,
) -> Vec<u8> {
    let mut buffer = vec![0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN];
    fill_tcp_header(&mut buffer[IPV6_HEADER_LEN..], src_port, dst_port, scan_type);
    {
        let mut tcp = MutableTcpPacket::new(&mut buffer[IPV6_HEADER_LEN..]).unwrap();
        let checksum = pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
        tcp.set_checksum(checksum);
    }
    let mut ip = MutableIpv6Packet::new(&mut buffer).unwrap();
    ip.set_version(6);
    ip.set_payload_length(TCP_HEADER_LEN as u16);
    ip.set_next_header(IpNextHeaderProtocols::Tcp);
    ip.set_hop_limit(hop_limit);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    buffer
}

fn with_ethernet(src_mac: MacAddr, dst_mac: MacAddr, ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
    {
        let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(ethertype);
    }
    frame[ETHERNET_HEADER_LEN..].copy_from_slice(payload);
    frame
}

/// A TCP probe of any scan type, for IPv4 or IPv6, ready to put on the wire.
/// Returns None when the addresses are of different families.
#[allow(clippy::too_many_arguments)]
pub fn build_probe_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    scan_type: ScanType,
    ttl: u8,
) -> Option<Vec<u8>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let packet = build_tcp_packet_with_ttl(src, dst, src_port, dst_port, scan_type, ttl);
            Some(with_ethernet(src_mac, dst_mac, EtherTypes::Ipv4, &packet))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let packet = ipv6_tcp_packet(src, dst, src_port, dst_port, scan_type, ttl);
            Some(with_ethernet(src_mac, dst_mac, EtherTypes::Ipv6, &packet))
        }
        _ => None,
    }
}

/// An ICMP echo request, used for host discovery.
pub fn build_echo_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identifier: u16,
) -> Vec<u8> {
    const ECHO_LEN: usize = 8;
    let mut buffer = vec![0u8; IPV4_HEADER_LEN + ECHO_LEN];
    {
        let mut echo = MutableEchoRequestPacket::new(&mut buffer[IPV4_HEADER_LEN..]).unwrap();
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_identifier(identifier);
        echo.set_sequence_number(1);
    }
    let checksum = pnet::packet::util::checksum(&buffer[IPV4_HEADER_LEN..], 1);
    MutableEchoRequestPacket::new(&mut buffer[IPV4_HEADER_LEN..]).unwrap().set_checksum(checksum);
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((IPV4_HEADER_LEN + ECHO_LEN) as u16);
        ip.set_identification(rand::random::<u16>());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }
    with_ethernet(src_mac, dst_mac, EtherTypes::Ipv4, &buffer)
}

/// The source of an ICMP echo reply carrying our identifier.
pub fn parse_echo_reply(frame: &[u8], identifier: u16) -> Option<Ipv4Addr> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }
    let reply = EchoReplyPacket::new(ip.payload())?;
    (reply.get_icmp_type() == IcmpTypes::EchoReply && reply.get_identifier() == identifier)
        .then(|| ip.get_source())
}

/// A TCP header's source and destination ports, from the start of the header.
fn tcp_ports(bytes: &[u8]) -> Option<(u16, u16)> {
    let ports = bytes.get(..4)?;
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

/// An ICMP or ICMPv6 error about one of our TCP probes.
#[derive(Debug, Clone, PartialEq)]
pub struct IcmpError {
    pub from: IpAddr,
    pub quoted_src_port: u16,
    pub quoted_dst_port: u16,
    pub time_exceeded: bool,
    /// The error means a filter or router refused the probe.
    pub blocked: bool,
}

pub fn parse_icmp_error(frame: &[u8], target: IpAddr) -> Option<IcmpError> {
    const ICMP_PREFIX: usize = 8;
    let eth = EthernetPacket::new(frame)?;

    if eth.get_ethertype() == EtherTypes::Ipv4 {
        let ip = Ipv4Packet::new(eth.payload())?;
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return None;
        }
        let icmp = ip.payload();
        let (kind, code) = (*icmp.first()?, *icmp.get(1)?);
        if kind != 3 && kind != 11 {
            return None;
        }
        let quoted = Ipv4Packet::new(icmp.get(ICMP_PREFIX..)?)?;
        if IpAddr::V4(quoted.get_destination()) != target
            || quoted.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return None;
        }
        let header_len = quoted.get_header_length() as usize * 4;
        let (src, dst) = tcp_ports(icmp.get(ICMP_PREFIX + header_len..)?)?;
        return Some(IcmpError {
            from: IpAddr::V4(ip.get_source()),
            quoted_src_port: src,
            quoted_dst_port: dst,
            time_exceeded: kind == 11,
            blocked: kind == 3 && matches!(code, 1 | 2 | 3 | 9 | 10 | 13),
        });
    }

    if eth.get_ethertype() == EtherTypes::Ipv6 {
        let ip = Ipv6Packet::new(eth.payload())?;
        if ip.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return None;
        }
        let icmp = ip.payload();
        let (kind, code) = (*icmp.first()?, *icmp.get(1)?);
        if kind != 1 && kind != 3 {
            return None;
        }
        let quoted = Ipv6Packet::new(icmp.get(ICMP_PREFIX..)?)?;
        if IpAddr::V6(quoted.get_destination()) != target
            || quoted.get_next_header() != IpNextHeaderProtocols::Tcp
        {
            return None;
        }
        let (src, dst) = tcp_ports(icmp.get(ICMP_PREFIX + IPV6_HEADER_LEN..)?)?;
        return Some(IcmpError {
            from: IpAddr::V6(ip.get_source()),
            quoted_src_port: src,
            quoted_dst_port: dst,
            time_exceeded: kind == 3,
            blocked: kind == 1 && matches!(code, 0 | 1 | 3 | 4),
        });
    }

    None
}

fn classify_tcp(tcp: &TcpPacket, ttl: u8) -> Reply {
    let flags = tcp.get_flags();
    let kind = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        TcpResponseType::SynAck
    } else if flags & TcpFlags::RST != 0 {
        TcpResponseType::Rst
    } else {
        TcpResponseType::Other
    };
    Reply::Tcp {
        port: tcp.get_source(),
        kind,
        fingerprint: TcpFingerprint { ttl, window_size: tcp.get_window(), tcp_flags: flags },
    }
}

/// Decodes a captured frame if it answers one of our probes. The capture sees all traffic, so
/// anything not from `target` to our `src_ip` and `src_port` is ignored.
pub fn parse_reply(frame: &[u8], src_ip: IpAddr, target: IpAddr, src_port: u16) -> Option<Reply> {
    if let Some(error) = parse_icmp_error(frame, target) {
        return (error.blocked && error.quoted_src_port == src_port)
            .then_some(Reply::Unreachable { port: error.quoted_dst_port });
    }

    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() == EtherTypes::Ipv4 {
        let ip = Ipv4Packet::new(eth.payload())?;
        if IpAddr::V4(ip.get_source()) != target
            || IpAddr::V4(ip.get_destination()) != src_ip
            || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return None;
        }
        let tcp = TcpPacket::new(ip.payload())?;
        return (tcp.get_destination() == src_port).then(|| classify_tcp(&tcp, ip.get_ttl()));
    }
    if eth.get_ethertype() == EtherTypes::Ipv6 {
        let ip = Ipv6Packet::new(eth.payload())?;
        if IpAddr::V6(ip.get_source()) != target
            || IpAddr::V6(ip.get_destination()) != src_ip
            || ip.get_next_header() != IpNextHeaderProtocols::Tcp
        {
            return None;
        }
        let tcp = TcpPacket::new(ip.payload())?;
        return (tcp.get_destination() == src_port).then(|| classify_tcp(&tcp, ip.get_hop_limit()));
    }
    None
}

/// The state of a port that never answered, which depends on the scan type.
pub fn silent_port_state(scan_type: ScanType) -> crate::types::PortState {
    use crate::types::PortState;
    match scan_type {
        ScanType::Fin | ScanType::Null | ScanType::Xmas | ScanType::Udp => PortState::OpenFiltered,
        _ => PortState::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
    use pnet::packet::Packet;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_syn_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let src_port = 50000;
        let dst_port = 80;

        let packet = build_syn_packet(src_ip, dst_ip, src_port, dst_port);

        assert!(!packet.is_empty());
        assert_eq!(packet.len(), 40);

        let ip_packet = Ipv4Packet::new(&packet).expect("Failed to parse IP packet");
        assert_eq!(ip_packet.get_version(), 4);
        assert_eq!(ip_packet.get_source(), src_ip);
        assert_eq!(ip_packet.get_destination(), dst_ip);

        let tcp_packet = TcpPacket::new(ip_packet.payload()).expect("Failed to parse TCP packet");
        assert_eq!(tcp_packet.get_source(), src_port);
        assert_eq!(tcp_packet.get_destination(), dst_port);
        assert_eq!(tcp_packet.get_flags(), TcpFlags::SYN);
        assert_ne!(tcp_packet.get_checksum(), 0);
    }

    #[test]
    fn test_random_source_port() {
        let port1 = random_source_port();
        assert!(port1 >= 49152);

        let mut ports = std::collections::HashSet::new();
        for _ in 0..100 {
            ports.insert(random_source_port());
        }
        assert!(ports.len() > 50);
    }

    #[test]
    fn test_parse_tcp_syn_ack_response() {
        let mut buffer = vec![0u8; 40];

        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::new(192, 168, 1, 1));
            ip.set_destination(Ipv4Addr::new(192, 168, 1, 100));
        }

        {
            let mut tcp = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
            tcp.set_source(80);
            tcp.set_destination(50000);
            tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            tcp.set_data_offset(5);
        }

        let result = parse_tcp_response(&buffer);
        assert!(result.is_some());
        let (port, response_type, _fingerprint) = result.unwrap();
        assert_eq!(port, 80);
        assert_eq!(response_type, TcpResponseType::SynAck);
    }

    #[test]
    fn test_parse_tcp_rst_response() {
        let mut buffer = vec![0u8; 40];

        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::new(192, 168, 1, 1));
            ip.set_destination(Ipv4Addr::new(192, 168, 1, 100));
        }

        {
            let mut tcp = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
            tcp.set_source(80);
            tcp.set_destination(50000);
            tcp.set_flags(TcpFlags::RST);
            tcp.set_data_offset(5);
        }

        let result = parse_tcp_response(&buffer);
        assert!(result.is_some());
        let (port, response_type, _fingerprint) = result.unwrap();
        assert_eq!(port, 80);
        assert_eq!(response_type, TcpResponseType::Rst);
    }

    #[test]
    fn test_parse_invalid_packet() {
        let buffer = vec![0u8; 10];
        let result = parse_tcp_response(&buffer);
        assert!(result.is_none());
    }

    mod frames {
        use super::super::*;
        use crate::types::PortState;

        const MAC_A: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
        const MAC_B: MacAddr = MacAddr(2, 0, 0, 0, 0, 2);

        fn v4(last: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
        }

        fn v6(last: u16) -> IpAddr {
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last))
        }

        /// The frame a target would send back for `flags`.
        fn answer(from: IpAddr, to: IpAddr, from_port: u16, to_port: u16, flags: u8) -> Vec<u8> {
            let mut frame = build_probe_frame(MAC_B, MAC_A, from, to, from_port, to_port, ScanType::Syn, 64).unwrap();
            let tcp_at = ETHERNET_HEADER_LEN + if from.is_ipv4() { IPV4_HEADER_LEN } else { IPV6_HEADER_LEN };
            MutableTcpPacket::new(&mut frame[tcp_at..]).unwrap().set_flags(flags);
            frame
        }

        fn sent_flags(scan_type: ScanType, ip: IpAddr, peer: IpAddr) -> u8 {
            let frame = build_probe_frame(MAC_A, MAC_B, ip, peer, 50000, 80, scan_type, 64).unwrap();
            let tcp_at = ETHERNET_HEADER_LEN + if ip.is_ipv4() { IPV4_HEADER_LEN } else { IPV6_HEADER_LEN };
            TcpPacket::new(&frame[tcp_at..]).unwrap().get_flags()
        }

        #[test]
        fn every_scan_type_sets_its_flags_on_both_ip_versions() {
            for (a, b) in [(v4(1), v4(2)), (v6(1), v6(2))] {
                assert_eq!(sent_flags(ScanType::Syn, a, b), TcpFlags::SYN);
                assert_eq!(sent_flags(ScanType::Ack, a, b), TcpFlags::ACK);
                assert_eq!(sent_flags(ScanType::Window, a, b), TcpFlags::ACK);
                assert_eq!(sent_flags(ScanType::Fin, a, b), TcpFlags::FIN);
                assert_eq!(sent_flags(ScanType::Null, a, b), 0);
                assert_eq!(sent_flags(ScanType::Xmas, a, b), TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
            }
        }

        #[test]
        fn mixed_address_families_are_refused() {
            assert!(build_probe_frame(MAC_A, MAC_B, v4(1), v6(2), 1, 2, ScanType::Syn, 64).is_none());
        }

        #[test]
        fn ipv6_probe_has_a_valid_checksum() {
            let (src, dst) = (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
            let packet = ipv6_tcp_packet(src, dst, 50000, 80, ScanType::Syn, 7);
            let ip = Ipv6Packet::new(&packet).unwrap();
            assert_eq!(ip.get_hop_limit(), 7);
            let tcp = TcpPacket::new(ip.payload()).unwrap();
            assert_eq!(pnet::packet::tcp::ipv6_checksum(&tcp, &src, &dst), tcp.get_checksum());
        }

        #[test]
        fn ttl_is_set_and_the_ip_checksum_stays_valid() {
            let frame = build_probe_frame(MAC_A, MAC_B, v4(1), v4(2), 1, 2, ScanType::Syn, 9).unwrap();
            let ip = Ipv4Packet::new(&frame[ETHERNET_HEADER_LEN..]).unwrap();
            assert_eq!(ip.get_ttl(), 9);
            assert_eq!(pnet::packet::ipv4::checksum(&ip), ip.get_checksum());
        }

        #[test]
        fn replies_are_decoded_on_both_ip_versions() {
            for (me, target) in [(v4(1), v4(2)), (v6(1), v6(2))] {
                let frame = answer(target, me, 443, 50000, TcpFlags::SYN | TcpFlags::ACK);
                let Some(Reply::Tcp { port, kind, .. }) = parse_reply(&frame, me, target, 50000) else {
                    panic!("no reply decoded");
                };
                assert_eq!((port, kind), (443, TcpResponseType::SynAck));
            }
        }

        #[test]
        fn traffic_from_other_hosts_or_ports_is_ignored() {
            let stranger = answer(v4(9), v4(1), 443, 50000, TcpFlags::SYN | TcpFlags::ACK);
            assert!(parse_reply(&stranger, v4(1), v4(2), 50000).is_none());

            let other_flow = answer(v4(2), v4(1), 443, 50001, TcpFlags::SYN | TcpFlags::ACK);
            assert!(parse_reply(&other_flow, v4(1), v4(2), 50000).is_none());
        }

        fn icmp_v4(kind: u8, code: u8, from: Ipv4Addr, probe: &[u8]) -> Vec<u8> {
            let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&probe[..IPV4_HEADER_LEN + 8]);
            let mut buffer = vec![0u8; IPV4_HEADER_LEN + icmp.len()];
            buffer[IPV4_HEADER_LEN..].copy_from_slice(&icmp);
            let mut ip = MutableIpv4Packet::new(&mut buffer).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((IPV4_HEADER_LEN + icmp.len()) as u16);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip.set_source(from);
            with_ethernet(MAC_B, MAC_A, EtherTypes::Ipv4, &buffer)
        }

        #[test]
        fn icmp_errors_quote_the_probe_ports() {
            let probe = build_probe_frame(MAC_A, MAC_B, v4(1), v4(2), 50000, 8080, ScanType::Syn, 3).unwrap();
            let router = Ipv4Addr::new(10, 0, 0, 254);

            let expired = icmp_v4(11, 0, router, &probe[ETHERNET_HEADER_LEN..]);
            let error = parse_icmp_error(&expired, v4(2)).unwrap();
            assert_eq!(error.from, IpAddr::V4(router));
            assert_eq!((error.quoted_src_port, error.quoted_dst_port), (50000, 8080));
            assert!(error.time_exceeded && !error.blocked);

            let blocked = icmp_v4(3, 13, router, &probe[ETHERNET_HEADER_LEN..]);
            assert!(matches!(
                parse_reply(&blocked, v4(1), v4(2), 50000),
                Some(Reply::Unreachable { port: 8080 })
            ));
            assert!(parse_reply(&blocked, v4(1), v4(2), 50001).is_none());
        }

        #[test]
        fn echo_replies_need_our_identifier() {
            let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
            let mut frame = build_echo_frame(MAC_B, MAC_A, b, a, 77);
            frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN] = 0; // echo request becomes echo reply
            assert_eq!(parse_echo_reply(&frame, 77), Some(b));
            assert_eq!(parse_echo_reply(&frame, 78), None);
        }

        #[test]
        fn silent_ports_depend_on_the_scan_type() {
            assert_eq!(silent_port_state(ScanType::Syn), PortState::Filtered);
            assert_eq!(silent_port_state(ScanType::Ack), PortState::Filtered);
            assert_eq!(silent_port_state(ScanType::Fin), PortState::OpenFiltered);
            assert_eq!(silent_port_state(ScanType::Xmas), PortState::OpenFiltered);
        }

        #[test]
        fn responses_map_to_nmap_style_states() {
            let state = |kind, window, scan| interpret_response(kind, window, scan);
            assert_eq!(state(TcpResponseType::Rst, 0, ScanType::Ack), PortState::Unfiltered);
            assert_eq!(state(TcpResponseType::Rst, 0, ScanType::Fin), PortState::Closed);
            assert_eq!(state(TcpResponseType::Rst, 512, ScanType::Window), PortState::Open);
            assert_eq!(state(TcpResponseType::Rst, 0, ScanType::Window), PortState::Closed);
        }
    }
}
