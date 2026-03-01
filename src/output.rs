use crate::types::{ScanResults, PortState, Protocol};
use anyhow::Result;
use serde_json;
use std::io::Write;

pub struct OutputFormatter;

impl OutputFormatter {
    pub fn write_json(results: &ScanResults) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        println!("{}", json);
        Ok(())
    }

    pub fn write_json_file(results: &ScanResults, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print_summary(results: &ScanResults) {
        println!();
        println!("Starting Tokmap {} ( https://github.com/varolius/tokmap )", env!("CARGO_PKG_VERSION"));
        println!("Scan initiated: {}", results.timestamp);
        println!();

        for host in &results.targets {
            println!("Tokmap scan report for {}{}",
                host.ip,
                host.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default()
            );

            let open_count = host.ports.iter().filter(|p| p.state == PortState::Open).count();
            let closed_count = host.ports.iter().filter(|p| p.state == PortState::Closed).count();
            let filtered_count = host.ports.iter().filter(|p| p.state == PortState::Filtered).count();

            if open_count > 0 {
                println!("Host is up ({:.3}s latency).",
                    host.scan_duration_ms as f64 / 1000.0);
            } else {
                println!("Host appears down or all ports filtered.");
            }

            let shown_count = open_count;
            let not_shown = host.ports.len() - shown_count;
            if not_shown > 10 {
                if closed_count > filtered_count {
                    println!("Not shown: {} closed ports", not_shown);
                } else if filtered_count > 0 {
                    println!("Not shown: {} filtered ports", not_shown);
                }
            }

            if !host.ports.is_empty() {
                println!("PORT      STATE         SERVICE       VERSION");

                for port in host.ports.iter().filter(|p| p.state == PortState::Open) {
                    print_port_line(port);
                }

                for port in host.ports.iter().filter(|p| matches!(p.state, PortState::OpenFiltered)) {
                    print_port_line(port);
                }

                if host.ports.len() <= 50 {
                    for port in host.ports.iter().filter(|p| matches!(p.state, PortState::Closed | PortState::Filtered)) {
                        print_port_line(port);
                    }
                }
            }

            if let Some(ref os) = host.os_guess {
                println!("OS guess: {}", os);
            }
            if let Some(ref fp) = host.os_fingerprint {
                println!("OS fingerprint: {}", fp);
            }

            println!();
        }

        let total_hosts = results.targets.len();
        let hosts_up = results.targets.iter().filter(|h|
            h.ports.iter().any(|p| p.state == PortState::Open)
        ).count();
        let total_open: usize = results.targets.iter()
            .map(|h| h.ports.iter().filter(|p| p.state == PortState::Open).count())
            .sum();

        println!();
        println!("Tokmap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds",
            total_hosts,
            if total_hosts == 1 { "" } else { "es" },
            hosts_up,
            if hosts_up == 1 { "" } else { "s" },
            results.total_duration_ms as f64 / 1000.0
        );
        if total_open > 0 {
            println!("{} ports found open across all hosts", total_open);
        }
    }

    pub fn write_xml(results: &ScanResults, path: Option<&str>) -> Result<()> {
        let mut output = String::new();

        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str("<!DOCTYPE nmaprun>\n");
        output.push_str(&format!("<nmaprun scanner=\"tokmap\" version=\"{}\" start=\"{}\">\n",
            env!("CARGO_PKG_VERSION"), results.timestamp));

        output.push_str(&format!("  <scaninfo type=\"{}\" />\n", results.scan_type));

        for host in &results.targets {
            output.push_str(&format!("  <host starttime=\"{}\">\n", results.timestamp));
            output.push_str("    <status state=\"up\"/>\n");
            output.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.ip));

            if let Some(ref hostname) = host.hostname {
                output.push_str(&format!("    <hostnames><hostname name=\"{}\"/></hostnames>\n", hostname));
            }

            output.push_str("    <ports>\n");
            for port in &host.ports {
                let protocol = match port.protocol {
                    Some(Protocol::TCP) => "tcp",
                    Some(Protocol::UDP) => "udp",
                    None => "tcp",
                };

                output.push_str(&format!("      <port protocol=\"{}\" portid=\"{}\">\n", protocol, port.port));
                output.push_str(&format!("        <state state=\"{}\"/>\n", state_to_string(&port.state)));

                if let Some(ref svc) = port.service {
                    output.push_str(&format!("        <service name=\"{}\"", svc.service_name));
                    if let Some(ref ver) = svc.version {
                        output.push_str(&format!(" version=\"{}\"", ver));
                    }
                    output.push_str("/>\n");
                }
                output.push_str("      </port>\n");
            }
            output.push_str("    </ports>\n");

            if let Some(ref os) = host.os_guess {
                output.push_str(&format!("    <os><osmatch name=\"{}\"/></os>\n", os));
            }

            output.push_str("  </host>\n");
        }

        output.push_str(&format!("  <runstats><finished time=\"{}\" elapsed=\"{}\"/></runstats>\n",
            results.timestamp, results.total_duration_ms as f64 / 1000.0));
        output.push_str("</nmaprun>\n");

        if let Some(path) = path {
            let mut file = std::fs::File::create(path)?;
            file.write_all(output.as_bytes())?;
        } else {
            print!("{}", output);
        }

        Ok(())
    }

    pub fn write_grepable(results: &ScanResults, path: Option<&str>) -> Result<()> {
        let mut output = String::new();

        output.push_str(&format!("# Tokmap {} scan initiated {} as: tokmap\n",
            env!("CARGO_PKG_VERSION"), results.timestamp));

        for host in &results.targets {
            let mut line = format!("Host: {} ({})\t",
                host.ip,
                host.hostname.as_ref().unwrap_or(&"".to_string())
            );

            line.push_str("Ports: ");
            let port_entries: Vec<String> = host.ports.iter()
                .map(|p| {
                    let protocol = match p.protocol {
                        Some(Protocol::TCP) => "tcp",
                        Some(Protocol::UDP) => "udp",
                        None => "tcp",
                    };
                    let svc_name = p.service.as_ref()
                        .map(|s| s.service_name.as_str())
                        .unwrap_or("unknown");
                    let svc_ver = p.service.as_ref()
                        .and_then(|s| s.version.as_ref())
                        .map(|v| v.as_str())
                        .unwrap_or("");

                    format!("{}/{}/{}/{}/{}/{}/",
                        p.port, state_to_string(&p.state), protocol,
                        "", svc_name, svc_ver)
                })
                .collect();

            line.push_str(&port_entries.join(", "));

            if let Some(ref os) = host.os_guess {
                line.push_str(&format!("\tOS: {}", os));
            }

            output.push_str(&line);
            output.push('\n');
        }

        output.push_str(&format!("# Tokmap done at {} -- {} IP address{} scanned\n",
            results.timestamp, results.targets.len(),
            if results.targets.len() == 1 { "" } else { "es" }));

        if let Some(path) = path {
            let mut file = std::fs::File::create(path)?;
            file.write_all(output.as_bytes())?;
        } else {
            print!("{}", output);
        }

        Ok(())
    }

    pub fn write_all_formats(results: &ScanResults, prefix: &str) -> Result<()> {
        Self::write_json_file(results, &format!("{}.json", prefix))?;
        Self::write_xml(results, Some(&format!("{}.xml", prefix)))?;
        Self::write_grepable(results, Some(&format!("{}.gnmap", prefix)))?;

        let mut file = std::fs::File::create(format!("{}.nmap", prefix))?;
        writeln!(file, "Tokmap {} scan results", env!("CARGO_PKG_VERSION"))?;
        writeln!(file, "Scan completed: {}", results.timestamp)?;
        writeln!(file)?;

        for host in &results.targets {
            writeln!(file, "Scan report for {}", host.ip)?;
            for port in &host.ports {
                if port.state == PortState::Open {
                    writeln!(file, "  {}/tcp open {}",
                        port.port,
                        port.service.as_ref().map(|s| s.service_name.as_str()).unwrap_or("unknown")
                    )?;
                }
            }
            writeln!(file)?;
        }

        Ok(())
    }
}

fn print_port_line(port: &crate::types::PortResult) {
    let protocol = match port.protocol {
        Some(Protocol::TCP) => "tcp",
        Some(Protocol::UDP) => "udp",
        None => "tcp",
    };

    let state_str = state_to_string(&port.state);
    let service_name = port.service.as_ref()
        .map(|s| s.service_name.as_str())
        .unwrap_or("unknown");
    let version_str = port.service.as_ref()
        .and_then(|s| s.version.as_ref())
        .map(|v| v.as_str())
        .unwrap_or("");

    println!("{:5}/{:<3} {:<13} {:<13} {}",
        port.port, protocol, state_str, service_name, version_str);
}

fn state_to_string(state: &PortState) -> String {
    match state {
        PortState::Open => "open".to_string(),
        PortState::Closed => "closed".to_string(),
        PortState::Filtered => "filtered".to_string(),
        PortState::OpenFiltered => "open|filtered".to_string(),
        PortState::ClosedFiltered => "closed|filtered".to_string(),
        PortState::Unfiltered => "unfiltered".to_string(),
        PortState::Unknown => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostResult, PortResult, PortState, ScanResults, Protocol};

    fn create_test_results() -> ScanResults {
        ScanResults {
            targets: vec![HostResult {
                ip: "127.0.0.1".parse().unwrap(),
                hostname: None,
                ports: vec![
                    PortResult {
                        port: 22,
                        state: PortState::Open,
                        latency_ms: Some(2),
                        service: None,
                        llm_analysis: None,
                        protocol: Some(Protocol::TCP),
                    },
                    PortResult {
                        port: 80,
                        state: PortState::Open,
                        latency_ms: Some(5),
                        service: None,
                        llm_analysis: None,
                        protocol: Some(Protocol::TCP),
                    },
                ],
                scan_duration_ms: 150,
                os_guess: None,
                os_fingerprint: None,
            }],
            total_duration_ms: 200,
            scan_type: "SYN".to_string(),
            timestamp: "2026-02-04T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_write_json_file() {
        let results = create_test_results();
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("tokmap_test_output.json");

        OutputFormatter::write_json_file(&results, test_file.to_str().unwrap()).unwrap();
        assert!(test_file.exists());

        let content = std::fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("scan_type"));
        assert!(content.contains("SYN"));
        assert!(content.contains("127.0.0.1"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_json_valid_format() {
        let results = create_test_results();
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("tokmap_test_valid.json");

        OutputFormatter::write_json_file(&results, test_file.to_str().unwrap()).unwrap();

        let content = std::fs::read_to_string(&test_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(parsed.get("targets").is_some());
        assert!(parsed.get("total_duration_ms").is_some());

        std::fs::remove_file(&test_file).ok();
    }
}
