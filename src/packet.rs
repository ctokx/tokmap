use crate::types::ScanType;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
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
    let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buffer = vec![0u8; total_len];

    let tcp_flags = match scan_type {
        ScanType::Syn => TcpFlags::SYN,
        ScanType::Ack => TcpFlags::ACK,
        ScanType::Window => TcpFlags::ACK, // Same as ACK scan; we check window size in response
        ScanType::Fin => TcpFlags::FIN,
        ScanType::Null => 0,
        ScanType::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        ScanType::Connect => TcpFlags::SYN, // Connect scan uses the OS stack, not raw packets
        ScanType::Udp => return Vec::new(),
    };

    {
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..]).unwrap();

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(rand::random::<u32>());

        if matches!(scan_type, ScanType::Ack | ScanType::Window) {
            tcp_packet.set_acknowledgement(rand::random::<u32>());
        } else {
            tcp_packet.set_acknowledgement(0);
        }

        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(tcp_flags);
        tcp_packet.set_window(64240);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &src_ip,
            &dst_ip,
        );
        tcp_packet.set_checksum(checksum);
    }

    {
        let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_identification(rand::random::<u16>());
        ip_packet.set_flags(0);
        ip_packet.set_fragment_offset(0);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        ip_packet.set_checksum(0);

        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);
    }

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

/// Dynamic/private port range (49152-65535)
pub fn random_source_port() -> u16 {
    rand::random::<u16>() % 16384 + 49152
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
}
