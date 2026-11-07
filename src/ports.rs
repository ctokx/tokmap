/// tokmap's own TCP port ranking, most likely open first. factory/gen_ports.py writes it.
const TCP_RANKING: &str = include_str!("../signatures/tcp-ports.txt");

/// The UDP ports tokmap has a payload for (src/udp.rs). Others rarely answer an empty datagram.
pub const TOP_UDP_PORTS: &[u16] = &[
    53, 69, 111, 123, 137, 161, 443, 500, 1434, 1900, 2049, 3478, 4500, 5060, 5353, 11211,
];

/// The `count` highest-ranked TCP ports, or all of them when there are fewer.
pub fn top_tcp_ports(count: usize) -> Vec<u16> {
    TCP_RANKING
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.trim().parse().ok())
        .take(count)
        .collect()
}

/// Parse port specs like "80,443", "1-1000", "T:80,U:53"
pub fn parse_port_spec(specs: &[String]) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();

    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            // Strip protocol prefix if present
            let port_str = if part.starts_with("T:") || part.starts_with("U:") {
                &part[2..]
            } else {
                part
            };

            if port_str.contains('-') {
                let range: Vec<&str> = port_str.split('-').collect();
                if range.len() == 2 {
                    // nmap forms: "-" is every port, "-100" and "1000-" leave one end open.
                    let start: u16 = if range[0].is_empty() { 1 } else { range[0].parse()? };
                    let end: u16 = if range[1].is_empty() { 65535 } else { range[1].parse()? };
                    for port in start..=end {
                        ports.push(port);
                    }
                }
            } else if !port_str.is_empty() {
                ports.push(port_str.parse()?);
            }
        }
    }

    ports.sort();
    ports.dedup();
    Ok(ports)
}

/// Splits a port spec into TCP and UDP lists. `T:` and `U:` apply until the next prefix, and
/// unprefixed ports apply to both.
pub fn split_port_spec(specs: &[String]) -> anyhow::Result<(Vec<u16>, Vec<u16>)> {
    let (mut tcp, mut udp) = (Vec::new(), Vec::new());
    let (mut to_tcp, mut to_udp) = (true, true);

    for part in specs.iter().flat_map(|spec| spec.split(',')).map(str::trim) {
        if part.starts_with("T:") {
            (to_tcp, to_udp) = (true, false);
        } else if part.starts_with("U:") {
            (to_tcp, to_udp) = (false, true);
        }
        let ports = parse_port_spec(&[part.to_string()])?;
        if to_tcp {
            tcp.extend(&ports);
        }
        if to_udp {
            udp.extend(&ports);
        }
    }

    for list in [&mut tcp, &mut udp] {
        list.sort_unstable();
        list.dedup();
    }
    Ok((tcp, udp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(spec: &str) -> Vec<u16> {
        parse_port_spec(&[spec.to_string()]).unwrap()
    }

    #[test]
    fn ranking_has_a_thousand_distinct_ports_classic_ones_first() {
        let all = top_tcp_ports(usize::MAX);
        assert_eq!(all.len(), 1000);
        assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
        assert_eq!(top_tcp_ports(3), vec![80, 443, 22]);
    }

    #[test]
    fn open_ended_ranges() {
        assert_eq!(parse("-").len(), 65535);
        assert_eq!(parse("-3"), vec![1, 2, 3]);
        assert_eq!(parse("65534-"), vec![65534, 65535]);
    }

    #[test]
    fn prefixes_split_tcp_and_udp() {
        let split = |spec: &str| split_port_spec(&[spec.to_string()]).unwrap();
        assert_eq!(split("80,443"), (vec![80, 443], vec![80, 443]));
        assert_eq!(split("U:53,111,T:21-22"), (vec![21, 22], vec![53, 111]));
    }

    #[test]
    fn lists_and_ranges_merge() {
        assert_eq!(parse("80,79-81,T:443"), vec![79, 80, 81, 443]);
    }
}
