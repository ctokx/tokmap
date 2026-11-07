use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;
use tracing::info;

const MAX_RANGE_HOSTS: u128 = 65536;
const REVERSE_DNS_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub targets: Vec<IpAddr>,
}

/// Supports: single IP, CIDR, IP range (192.168.1.1-254), hostname, comma-separated
pub fn parse_targets(specs: &[String]) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();

    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut parsed = parse_single_target(part)?;
            targets.append(&mut parsed);
        }
    }

    targets.sort();
    targets.dedup();

    Ok(targets)
}

fn parse_single_target(spec: &str) -> Result<Vec<IpAddr>> {
    if spec.contains('/') {
        return parse_cidr(spec);
    }

    // Hostnames contain hyphens and dots too, so only dotted numbers count as a range.
    let dotted = spec.split('.').collect::<Vec<_>>();
    if spec.contains('-') && dotted.len() == 4 && dotted[..3].iter().all(|o| o.parse::<u8>().is_ok()) {
        return parse_ip_range(spec);
    }

    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    resolve_hostname(spec)
}

fn parse_cidr(spec: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR notation: {}", spec);
    }

    if parts[0].contains(':') {
        return parse_cidr_v6(parts[0], parts[1]);
    }

    let base_ip: Ipv4Addr = parts[0].parse()
        .context(format!("Invalid IP in CIDR: {}", parts[0]))?;
    let prefix_len: u32 = parts[1].parse()
        .context(format!("Invalid prefix length: {}", parts[1]))?;

    if prefix_len > 32 {
        anyhow::bail!("Invalid prefix length: {} (must be 0-32)", prefix_len);
    }

    let ip_u32 = u32::from(base_ip);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    let network = ip_u32 & mask;
    let host_count = 1u64 << (32 - prefix_len);

    if host_count > 65536 {
        anyhow::bail!("CIDR /{} would scan {} hosts. Maximum is /16 (65536 hosts). Use a smaller range.", prefix_len, host_count);
    }

    let mut targets = Vec::new();
    for i in 0..host_count as u32 {
        let ip = Ipv4Addr::from(network + i);
        // Skip network and broadcast addresses for /24 and larger
        if prefix_len <= 30 {
            if i == 0 || i == (host_count as u32 - 1) {
                continue;
            }
        }
        targets.push(IpAddr::V4(ip));
    }

    info!("CIDR {} expanded to {} hosts", spec, targets.len());
    Ok(targets)
}

fn parse_cidr_v6(base: &str, prefix: &str) -> Result<Vec<IpAddr>> {
    let base_ip: Ipv6Addr = base.parse().context(format!("Invalid IP in CIDR: {}", base))?;
    let prefix_len: u32 = prefix.parse().context(format!("Invalid prefix length: {}", prefix))?;
    if prefix_len > 128 {
        anyhow::bail!("Invalid prefix length: {} (must be 0-128)", prefix_len);
    }

    let host_bits = 128 - prefix_len;
    if host_bits > 16 {
        anyhow::bail!("IPv6 CIDR /{} is too large to scan. Maximum is /112 ({} hosts).", prefix_len, MAX_RANGE_HOSTS);
    }

    let network = u128::from(base_ip) & (u128::MAX << host_bits);
    Ok((0..1u128 << host_bits).map(|i| IpAddr::V6(Ipv6Addr::from(network + i))).collect())
}

fn parse_ip_range(spec: &str) -> Result<Vec<IpAddr>> {
    let last_dot = spec.rfind('.').context("Invalid IP range")?;
    let base = &spec[..=last_dot];
    let range_part = &spec[last_dot + 1..];

    let range_parts: Vec<&str> = range_part.split('-').collect();
    if range_parts.len() != 2 {
        anyhow::bail!("Invalid IP range: {}", spec);
    }

    let start: u8 = range_parts[0].parse().context("Invalid range start")?;
    let end: u8 = range_parts[1].parse().context("Invalid range end")?;

    if start > end {
        anyhow::bail!("Range start ({}) > end ({})", start, end);
    }

    let mut targets = Vec::new();
    for i in start..=end {
        let ip_str = format!("{}{}", base, i);
        let ip: IpAddr = ip_str.parse().context(format!("Invalid IP: {}", ip_str))?;
        targets.push(ip);
    }

    info!("IP range {} expanded to {} hosts", spec, targets.len());
    Ok(targets)
}

fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    info!("Resolving hostname: {}", hostname);

    let addr = format!("{}:0", hostname);
    let resolved: Vec<_> = addr
        .to_socket_addrs()
        .context(format!("Failed to resolve hostname: {}", hostname))?
        .map(|s| s.ip())
        .collect();

    if resolved.is_empty() {
        anyhow::bail!("Hostname {} did not resolve to any addresses", hostname);
    }

    let ipv4: Vec<_> = resolved.iter().filter(|ip| ip.is_ipv4()).cloned().collect();
    if !ipv4.is_empty() {
        info!("Resolved {} -> {:?}", hostname, ipv4);
        Ok(ipv4)
    } else {
        info!("Resolved {} -> {:?}", hostname, resolved);
        Ok(resolved)
    }
}

/// The PTR name for an address, if the OS resolver has one quickly.
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let lookup = move || dns_lookup::lookup_addr(&ip).ok();
    let name = crate::route::on_capture_thread(REVERSE_DNS_WAIT, lookup).await.flatten()?;
    // Without a PTR record the resolver hands the address back as text.
    (name != ip.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ip() {
        let result = parse_targets(&["192.168.1.1".to_string()]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_cidr_24() {
        let result = parse_targets(&["10.0.0.0/24".to_string()]).unwrap();
        assert_eq!(result.len(), 254);
        assert!(result.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(result.contains(&"10.0.0.254".parse::<IpAddr>().unwrap()));
        assert!(!result.contains(&"10.0.0.0".parse::<IpAddr>().unwrap()));
        assert!(!result.contains(&"10.0.0.255".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_parse_cidr_30() {
        let result = parse_targets(&["10.0.0.0/30".to_string()]).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_ip_range() {
        let result = parse_targets(&["192.168.1.1-5".to_string()]).unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_parse_comma_separated() {
        let result = parse_targets(&["192.168.1.1,192.168.1.2".to_string()]).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn hyphenated_hostnames_are_not_ranges() {
        let error = parse_single_target("my-app.prod.example.invalid").unwrap_err();
        assert!(error.to_string().contains("resolve"));
    }

    #[test]
    fn ipv6_ranges_expand_from_the_network_base() {
        let hosts = parse_targets(&["fd00::5/126".to_string()]).unwrap();
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0], "fd00::4".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[3], "fd00::7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn oversized_ipv6_ranges_are_refused() {
        assert!(parse_targets(&["fd00::/64".to_string()]).is_err());
    }

    #[test]
    fn targets_sort_numerically() {
        let hosts = parse_targets(&["10.0.0.10,10.0.0.9".to_string()]).unwrap();
        assert_eq!(hosts[0], "10.0.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_multiple_specs() {
        let result = parse_targets(&[
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
        ]).unwrap();
        assert_eq!(result.len(), 2);
    }
}
