//! UDP probing. Payloads are built from the protocol specifications named beside each one, so a
//! service answers instead of ignoring an empty datagram.

use crate::connect::Answer;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const QUERY_ID: [u8; 2] = *b"tk";
const QUIC_MIN_DATAGRAM: usize = 1200;

/// A standard query for one name (RFC 1035 section 4).
fn dns_query(labels: &[&str], qtype: u16) -> Vec<u8> {
    let mut query = QUERY_ID.to_vec();
    query.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // recursion desired, one question
    for label in labels {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    query.extend(qtype.to_be_bytes());
    query.extend([0, 1]); // class IN
    query
}

/// One BER tag-length-value (X.690). Short-form length is enough for these small messages.
fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, content.len() as u8];
    out.extend(content);
    out
}

/// SNMPv2c GetRequest for sysDescr.0 with the default community (RFC 3416).
fn snmp_get_sysdescr() -> Vec<u8> {
    const SYS_DESCR: [u8; 8] = [0x2b, 6, 1, 2, 1, 1, 1, 0]; // 1.3.6.1.2.1.1.1.0

    let binding = ber(0x30, &[ber(0x06, &SYS_DESCR), ber(0x05, &[])].concat());
    let pdu = [
        ber(0x02, &[0x54, 0x4b]), // request id
        ber(0x02, &[0]),          // error status
        ber(0x02, &[0]),          // error index
        ber(0x30, &binding),
    ]
    .concat();
    let message = [ber(0x02, &[1]), ber(0x04, b"public"), ber(0xa0, &pdu)].concat();
    ber(0x30, &message)
}

/// NetBIOS NODE STATUS REQUEST for the wildcard name (RFC 1002 section 4.2.17).
fn netbios_node_status() -> Vec<u8> {
    let mut query = QUERY_ID.to_vec();
    query.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.push(32);
    // First-level encoding: each nibble plus 'A'. The name is "*" padded with NULs.
    for byte in std::iter::once(b'*').chain(std::iter::repeat_n(0, 15)) {
        query.push(b'A' + (byte >> 4));
        query.push(b'A' + (byte & 0x0f));
    }
    query.push(0);
    query.extend([0, 0x21, 0, 1]); // NBSTAT, IN
    query
}

/// ONC RPC call to procedure 0, which every program implements as a no-op (RFC 5531).
fn rpc_null_call(program: u32, version: u32) -> Vec<u8> {
    let mut call = b"tkmp".to_vec();
    call.extend(0u32.to_be_bytes()); // CALL
    call.extend(2u32.to_be_bytes()); // RPC version
    call.extend(program.to_be_bytes());
    call.extend(version.to_be_bytes());
    call.extend(0u32.to_be_bytes()); // procedure 0
    call.extend([0u8; 16]); // AUTH_NONE credentials and verifier
    call
}

/// A long header with a reserved version, which servers must answer with Version Negotiation
/// (RFC 9000 section 6). Clients must pad initial datagrams, so servers ignore short ones.
fn quic_version_probe() -> Vec<u8> {
    let mut packet = vec![0xc0, 0x1a, 0x1a, 0x1a, 0x1a, 8];
    packet.extend(b"tokmapdc");
    packet.push(0);
    packet.resize(QUIC_MIN_DATAGRAM, 0);
    packet
}

/// IKEv2 header for IKE_SA_INIT with no payloads (RFC 7296 section 3.1).
fn ike_header() -> Vec<u8> {
    let mut packet = b"tokmapsa".to_vec(); // initiator SPI
    packet.extend([0u8; 8]); // responder SPI
    packet.extend([0, 0x20, 34, 0x08]); // no payload, version 2.0, IKE_SA_INIT, initiator
    packet.extend(0u32.to_be_bytes()); // message id
    packet.extend(28u32.to_be_bytes()); // total length
    packet
}

/// The datagram most likely to get an answer on `port`.
pub fn payload_for(port: u16) -> Vec<u8> {
    match port {
        53 => dns_query(&[], 2),
        69 => b"\x00\x01tokmap-probe\x00octet\x00".to_vec(), // RFC 1350 read request
        111 => rpc_null_call(100_000, 2),
        123 => {
            // RFC 5905: version 4, client mode.
            let mut packet = vec![0u8; 48];
            packet[0] = 0x23;
            packet
        }
        137 => netbios_node_status(),
        161 => snmp_get_sysdescr(),
        443 => quic_version_probe(),
        500 | 4500 => ike_header(),
        1434 => vec![0x03], // MC-SQLR CLNT_UCAST_EX
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec(),
        2049 => rpc_null_call(100_003, 3),
        3478 => {
            // RFC 8489: Binding Request with the fixed magic cookie.
            let mut packet = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
            packet.extend(b"tokmapprobe!");
            packet
        }
        5060 => b"OPTIONS sip:probe@tokmap.invalid SIP/2.0\r\n\
Via: SIP/2.0/UDP tokmap.invalid;branch=z9hG4bK-tokmap\r\n\
Max-Forwards: 70\r\n\
From: <sip:tokmap@tokmap.invalid>;tag=tokmap\r\n\
To: <sip:probe@tokmap.invalid>\r\n\
Call-ID: tokmap-probe\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec(),
        5353 => dns_query(&["_services", "_dns-sd", "_udp", "local"], 12), // RFC 6763 section 9
        11211 => {
            // memcached UDP frame header, then the text protocol's version command.
            let mut packet = vec![0x74, 0x6b, 0, 0, 0, 1, 0, 0];
            packet.extend(b"version\r\n");
            packet
        }
        _ => Vec::new(),
    }
}

/// One UDP probe. A connected socket surfaces ICMP port-unreachable as a socket error, so closed
/// ports are detected without raw sockets or privileges.
pub async fn probe_once(addr: SocketAddr, wait: Duration) -> Answer {
    let bind: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let Ok(socket) = UdpSocket::bind(bind).await else { return Answer::Silent };
    if socket.connect(addr).await.is_err() {
        return Answer::Silent;
    }

    let start = Instant::now();
    if let Err(e) = socket.send(&payload_for(addr.port())).await {
        return if refused(&e) { Answer::Closed } else { Answer::Silent };
    }

    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(wait, socket.recv(&mut buffer)).await {
        Ok(Ok(_)) => Answer::Open(start.elapsed().as_millis() as u64),
        Ok(Err(e)) if refused(&e) => Answer::Closed,
        _ => Answer::Silent,
    }
}

/// Linux reports ICMP port-unreachable as refused, Windows as reset.
fn refused(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;

    #[tokio::test]
    async fn answering_port_is_open() {
        let server = UdpSocket::bind((LOCAL, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (_, peer) = server.recv_from(&mut buffer).await.unwrap();
            server.send_to(b"hello", peer).await.unwrap();
        });
        assert!(matches!(probe_once(addr, Duration::from_secs(1)).await, Answer::Open(_)));
    }

    #[tokio::test]
    async fn closed_port_is_reported_from_icmp() {
        let unused = UdpSocket::bind((LOCAL, 0)).await.unwrap();
        let addr = unused.local_addr().unwrap();
        drop(unused);
        assert_eq!(probe_once(addr, Duration::from_secs(1)).await, Answer::Closed);
    }

    #[tokio::test]
    async fn quiet_listener_is_silent() {
        let server = UdpSocket::bind((LOCAL, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        assert_eq!(probe_once(addr, Duration::from_millis(100)).await, Answer::Silent);
        drop(server);
    }

    #[test]
    fn dns_payload_is_a_well_formed_query() {
        let query = payload_for(5353);
        assert_eq!(&query[4..6], &[0, 1], "one question");
        assert_eq!(query[12] as usize, "_services".len());
        assert_eq!(&query[query.len() - 4..], &[0, 12, 0, 1], "PTR in class IN");
    }

    #[test]
    fn snmp_lengths_are_consistent() {
        let message = snmp_get_sysdescr();
        assert_eq!(message[0], 0x30);
        assert_eq!(message[1] as usize, message.len() - 2);
    }

    #[test]
    fn netbios_wildcard_name_is_encoded() {
        let query = netbios_node_status();
        assert_eq!(&query[13..15], b"CK", "'*' is 0x2A, so nibbles 2 and A");
        assert_eq!(query[12], 32);
    }

    #[test]
    fn fixed_size_payloads_match_their_specs() {
        assert_eq!(payload_for(123).len(), 48);
        assert_eq!(payload_for(443).len(), QUIC_MIN_DATAGRAM);
        assert_eq!(payload_for(500).len(), 28);
        assert_eq!(payload_for(3478).len(), 20);
        assert_eq!(payload_for(111).len(), 40);
        assert!(payload_for(40000).is_empty());
    }
}
