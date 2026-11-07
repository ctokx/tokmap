//! TCP traceroute: one SYN per TTL, sent together, so a trace takes one wait instead of thirty.

use crate::packet::{build_probe_frame, parse_icmp_error, parse_reply, Reply};
use crate::route::open_capture;
use crate::types::{Hop, ScanType};
use pnet::datalink::NetworkInterface;
use pnet::util::MacAddr;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const MAX_HOPS: u8 = 30;
/// Source port of the TTL-1 probe. Each probe gets its own, so replies identify their TTL.
const BASE_PORT: u16 = 40000;

pub struct TraceRoute {
    pub interface: NetworkInterface,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub target: IpAddr,
    pub port: u16,
}

fn ttl_of(port: u16) -> Option<u8> {
    let ttl = port.checked_sub(BASE_PORT)?;
    (1..=MAX_HOPS as u16).contains(&ttl).then_some(ttl as u8)
}

/// Turns raw sightings into a route: everything past the target is an echo of it.
fn assemble(mut seen: BTreeMap<u8, (IpAddr, u64)>, reached_at: Option<u8>) -> Vec<Hop> {
    let last = reached_at.or(seen.keys().next_back().copied()).unwrap_or(0);
    (1..=last)
        .map(|ttl| {
            let hit = seen.remove(&ttl);
            Hop { ttl, ip: hit.map(|h| h.0), rtt_ms: hit.map(|h| h.1) }
        })
        .collect()
}

/// Blocking: run on a thread that may take up to `wait`.
pub fn trace(route: &TraceRoute, wait: Duration) -> Vec<Hop> {
    let Ok((mut tx, mut rx)) = open_capture(&route.interface) else { return Vec::new() };

    let start = Instant::now();
    for ttl in 1..=MAX_HOPS {
        let source_port = BASE_PORT + ttl as u16;
        if let Some(frame) = build_probe_frame(
            route.src_mac, route.dst_mac, route.src_ip, route.target,
            source_port, route.port, ScanType::Syn, ttl,
        ) {
            let _ = tx.send_to(&frame, None);
        }
    }

    let mut seen: BTreeMap<u8, (IpAddr, u64)> = BTreeMap::new();
    let mut reached_at: Option<u8> = None;

    while start.elapsed() < wait {
        let Ok(frame) = rx.next() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        let rtt = start.elapsed().as_millis() as u64;

        if let Some(error) = parse_icmp_error(frame, route.target) {
            if error.quoted_dst_port == route.port {
                if let Some(ttl) = ttl_of(error.quoted_src_port) {
                    seen.entry(ttl).or_insert((error.from, rtt));
                }
            }
            continue;
        }

        // A TCP answer means that probe got all the way there.
        for ttl in 1..=MAX_HOPS {
            let port = BASE_PORT + ttl as u16;
            if matches!(parse_reply(frame, route.src_ip, route.target, port), Some(Reply::Tcp { .. })) {
                reached_at = Some(reached_at.map_or(ttl, |at| at.min(ttl)));
                seen.entry(ttl).or_insert((route.target, rtt));
            }
        }

        if let Some(at) = reached_at {
            if (1..=at).all(|ttl| seen.contains_key(&ttl)) {
                break;
            }
        }
    }

    assemble(seen, reached_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn ports_map_back_to_ttls() {
        assert_eq!(ttl_of(BASE_PORT + 1), Some(1));
        assert_eq!(ttl_of(BASE_PORT + MAX_HOPS as u16), Some(MAX_HOPS));
        assert_eq!(ttl_of(BASE_PORT), None);
        assert_eq!(ttl_of(BASE_PORT + MAX_HOPS as u16 + 1), None);
        assert_eq!(ttl_of(80), None);
    }

    #[test]
    fn route_stops_at_the_target_and_keeps_silent_hops() {
        let seen = BTreeMap::from([(1, (ip(1), 2)), (3, (ip(3), 6)), (4, (ip(3), 6)), (9, (ip(3), 6))]);
        let route = assemble(seen, Some(3));
        assert_eq!(route.len(), 3);
        assert_eq!(route[0].ip, Some(ip(1)));
        assert_eq!(route[1], Hop { ttl: 2, ip: None, rtt_ms: None });
        assert_eq!(route[2].ip, Some(ip(3)));
    }

    #[test]
    fn unreached_target_still_reports_how_far_it_got() {
        let route = assemble(BTreeMap::from([(1, (ip(1), 2)), (2, (ip(2), 4))]), None);
        assert_eq!(route.len(), 2);
    }

    #[test]
    fn nothing_seen_means_an_empty_route() {
        assert!(assemble(BTreeMap::new(), None).is_empty());
    }
}
