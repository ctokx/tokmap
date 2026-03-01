use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub frequency: f64,
    pub comment: Option<String>,
}

pub fn parse_nmap_services(path: &str) -> Result<Vec<PortInfo>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut ports = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: service_name  port/protocol  frequency  # comment
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let service_name = parts[0].to_string();
        let port_proto = parts[1];
        let frequency: f64 = parts[2].parse().unwrap_or(0.0);

        if let Some((port_str, protocol)) = port_proto.split_once('/') {
            if let Ok(port) = port_str.parse::<u16>() {
                let comment = if let Some(pos) = line.find('#') {
                    Some(line[pos + 1..].trim().to_string())
                } else {
                    None
                };

                ports.push(PortInfo {
                    port,
                    protocol: protocol.to_string(),
                    service_name,
                    frequency,
                    comment,
                });
            }
        }
    }

    info!("Parsed {} port entries from nmap-services", ports.len());
    Ok(ports)
}

pub fn get_top_tcp_ports_from_nmap(path: &str, count: usize) -> Result<Vec<u16>> {
    let ports = parse_nmap_services(path)?;

    let mut tcp_ports: Vec<_> = ports
        .into_iter()
        .filter(|p| p.protocol == "tcp")
        .collect();

    tcp_ports.sort_by(|a, b| b.frequency.partial_cmp(&a.frequency).unwrap());

    let top_ports: Vec<u16> = tcp_ports
        .into_iter()
        .take(count)
        .map(|p| p.port)
        .collect();

    debug!("Selected top {} TCP ports from nmap frequency data", top_ports.len());
    Ok(top_ports)
}

#[derive(Debug, Clone)]
pub struct MacVendor {
    pub prefix: String,
    pub vendor: String,
}

pub fn parse_mac_prefixes(path: &str) -> Result<HashMap<String, String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut vendors = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: AABBCC Vendor Name
        if let Some((prefix, vendor)) = line.split_once(char::is_whitespace) {
            vendors.insert(
                prefix.trim().to_uppercase(),
                vendor.trim().to_string()
            );
        }
    }

    info!("Loaded {} MAC vendor prefixes", vendors.len());
    Ok(vendors)
}

pub fn lookup_mac_vendor(mac: &str, vendors: &HashMap<String, String>) -> Option<String> {
    let mac_clean = mac.replace([':', '-'], "").to_uppercase();

    if mac_clean.len() >= 6 {
        if let Some(vendor) = vendors.get(&mac_clean[..6]) {
            return Some(vendor.clone());
        }
    }

    if mac_clean.len() >= 7 {
        if let Some(vendor) = vendors.get(&mac_clean[..7]) {
            return Some(vendor.clone());
        }
    }

    None
}

#[derive(Debug, Clone)]
pub struct RpcService {
    pub name: String,
    pub number: u32,
    pub aliases: Vec<String>,
}

pub fn parse_rpc_services(path: &str) -> Result<HashMap<u32, RpcService>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut services = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: name  number  aliases
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let name = parts[0].to_string();
        if let Ok(number) = parts[1].parse::<u32>() {
            let aliases = parts[2..].iter().map(|s| s.to_string()).collect();

            services.insert(number, RpcService {
                name,
                number,
                aliases,
            });
        }
    }

    info!("Loaded {} RPC services", services.len());
    Ok(services)
}

#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    pub name: String,
    pub number: u8,
    pub aliases: Vec<String>,
}

pub fn parse_protocols(path: &str) -> Result<HashMap<u8, ProtocolInfo>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut protocols = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: name  number  aliases  # comment
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let name = parts[0].to_string();
        if let Ok(number) = parts[1].parse::<u8>() {
            let aliases = parts[2..]
                .iter()
                .filter(|s| !s.starts_with('#'))
                .map(|s| s.to_string())
                .collect();

            protocols.insert(number, ProtocolInfo {
                name,
                number,
                aliases,
            });
        }
    }

    info!("Loaded {} protocols", protocols.len());
    Ok(protocols)
}

pub struct NmapData {
    pub services: Option<Vec<PortInfo>>,
    pub mac_vendors: Option<HashMap<String, String>>,
    pub rpc_services: Option<HashMap<u32, RpcService>>,
    pub protocols: Option<HashMap<u8, ProtocolInfo>>,
}

impl NmapData {
    pub fn new() -> Self {
        Self {
            services: None,
            mac_vendors: None,
            rpc_services: None,
            protocols: None,
        }
    }

    pub fn load_all(&mut self) {
        if let Ok(services) = parse_nmap_services("nmap-services") {
            self.services = Some(services);
        }
        if let Ok(vendors) = parse_mac_prefixes("nmap-mac-prefixes") {
            self.mac_vendors = Some(vendors);
        }
        if let Ok(rpc) = parse_rpc_services("nmap-rpc") {
            self.rpc_services = Some(rpc);
        }
        if let Ok(protos) = parse_protocols("nmap-protocols") {
            self.protocols = Some(protos);
        }
    }

    pub fn get_service_name(&self, port: u16, protocol: &str) -> Option<String> {
        self.services.as_ref()?.iter()
            .find(|s| s.port == port && s.protocol == protocol)
            .map(|s| s.service_name.clone())
    }
}

impl Default for NmapData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_vendor_lookup() {
        let mut vendors = HashMap::new();
        vendors.insert("001122".to_string(), "Test Vendor".to_string());

        assert_eq!(
            lookup_mac_vendor("00:11:22:33:44:55", &vendors),
            Some("Test Vendor".to_string())
        );
        assert_eq!(
            lookup_mac_vendor("00-11-22-33-44-55", &vendors),
            Some("Test Vendor".to_string())
        );
    }
}
