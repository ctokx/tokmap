use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use tracing::info;

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

    targets.sort_by(|a, b| format!("{}", a).cmp(&format!("{}", b)));
    targets.dedup();

    Ok(targets)
}

fn parse_single_target(spec: &str) -> Result<Vec<IpAddr>> {
    if spec.contains('/') {
        return parse_cidr(spec);
    }

    if spec.contains('-') && spec.chars().filter(|c| *c == '.').count() == 3 {
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

// TODO: implement proper reverse DNS lookup
pub fn reverse_dns(_ip: IpAddr) -> Option<String> {
    None
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
    fn test_parse_multiple_specs() {
        let result = parse_targets(&[
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
        ]).unwrap();
        assert_eq!(result.len(), 2);
    }
}
