use anyhow::Result;
use crate::service_db::ServiceMatcher;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub service_name: String,
    pub version: Option<String>,
    pub banner: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

pub async fn grab_banner_with_db(
    ip: IpAddr,
    port: u16,
    probe_timeout: Duration,
    matcher: Option<&ServiceMatcher>,
) -> Result<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(probe_timeout, TcpStream::connect(addr)).await??;

    let mut buffer = vec![0u8; 1024];
    let banner = match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner_text = String::from_utf8_lossy(&buffer[..n]).to_string();
            debug!("Received banner from {}:{}: {}", ip, port, banner_text.trim());
            banner_text
        }
        _ => {
            debug!("No immediate banner from {}:{}, sending HTTP probe", ip, port);
            send_probe(&mut stream, port).await?
        }
    };

    // Try database matching first
    if let Some(matcher) = matcher {
        if let Some(db_match) = matcher.match_banner(&banner, port) {
            debug!("Database matched service: {} on {}:{}", db_match.service_name, ip, port);
            return Ok(ServiceInfo {
                service_name: db_match.product.unwrap_or(db_match.service_name),
                version: db_match.version,
                banner: banner.clone(),
                confidence: match db_match.confidence {
                    crate::service_db::Confidence::High => Confidence::High,
                    crate::service_db::Confidence::Medium => Confidence::Medium,
                    crate::service_db::Confidence::Low => Confidence::Low,
                },
            });
        }
    }

    Ok(identify_service(port, &banner))
}

pub async fn grab_banner(
    ip: IpAddr,
    port: u16,
    probe_timeout: Duration,
) -> Result<ServiceInfo> {
    grab_banner_with_db(ip, port, probe_timeout, None).await
}

async fn send_probe(stream: &mut TcpStream, port: u16) -> Result<String> {
    let probe = match port {
        80 | 8080 | 8000 | 8888 => {
            "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        }
        443 | 8443 => {
            return Ok(String::new());
        }
        21 => {
            return Ok(String::new());
        }
        25 | 587 => {
            return Ok(String::new());
        }
        _ => {
            return Ok(String::new());
        }
    };

    stream.write_all(probe.as_bytes()).await?;

    let mut buffer = vec![0u8; 4096];
    match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]).to_string();
            Ok(response)
        }
        _ => Ok(String::new()),
    }
}

fn identify_service(port: u16, banner: &str) -> ServiceInfo {
    let banner_lower = banner.to_lowercase();
    let banner_trimmed = banner.trim();

    if banner_lower.starts_with("ssh-") {
        return parse_ssh_banner(banner_trimmed);
    }

    if banner_lower.contains("http/") {
        return parse_http_banner(banner);
    }

    if banner_lower.starts_with("220") && banner_lower.contains("ftp") {
        return parse_ftp_banner(banner_trimmed);
    }

    if banner_lower.starts_with("220") && (banner_lower.contains("smtp") || banner_lower.contains("mail")) {
        return parse_smtp_banner(banner_trimmed);
    }

    if port == 3306 || banner.contains("mysql") {
        return parse_mysql_banner(banner);
    }

    if port == 5432 || banner.contains("postgres") {
        return ServiceInfo {
            service_name: "PostgreSQL".to_string(),
            version: None,
            banner: banner.to_string(),
            confidence: Confidence::Medium,
        };
    }

    if port == 6379 || banner.starts_with("-ERR") || banner.starts_with("+PONG") {
        return ServiceInfo {
            service_name: "Redis".to_string(),
            version: None,
            banner: banner.to_string(),
            confidence: Confidence::Medium,
        };
    }

    if port == 27017 {
        return ServiceInfo {
            service_name: "MongoDB".to_string(),
            version: None,
            banner: banner.to_string(),
            confidence: Confidence::Low,
        };
    }

    identify_by_port(port, banner)
}

fn parse_ssh_banner(banner: &str) -> ServiceInfo {
    let parts: Vec<&str> = banner.split('-').collect();

    let (service_name, version) = if parts.len() >= 3 {
        let server_info = parts[2];
        if server_info.contains("OpenSSH") {
            let version = server_info.split('_').nth(1).map(|v| v.split_whitespace().next().unwrap_or(""));
            ("OpenSSH".to_string(), version.map(|v| v.to_string()))
        } else {
            ("SSH".to_string(), Some(server_info.to_string()))
        }
    } else {
        ("SSH".to_string(), None)
    };

    ServiceInfo {
        service_name,
        version,
        banner: banner.to_string(),
        confidence: Confidence::High,
    }
}

fn parse_http_banner(banner: &str) -> ServiceInfo {
    let mut service_name = "HTTP".to_string();
    let mut version = None;

    for line in banner.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            let server_value = line[7..].trim();

            if server_value.contains("nginx") {
                service_name = "nginx".to_string();
                if let Some(v) = server_value.split('/').nth(1) {
                    version = Some(v.split_whitespace().next().unwrap_or("").to_string());
                }
            } else if server_value.contains("Apache") {
                service_name = "Apache".to_string();
                if let Some(v) = server_value.split('/').nth(1) {
                    version = Some(v.split_whitespace().next().unwrap_or("").to_string());
                }
            } else if server_value.contains("Microsoft-IIS") {
                service_name = "IIS".to_string();
                if let Some(v) = server_value.split('/').nth(1) {
                    version = Some(v.to_string());
                }
            } else {
                service_name = format!("HTTP ({})", server_value.split_whitespace().next().unwrap_or("Unknown"));
            }
            break;
        }
    }

    let confidence = if version.is_some() { Confidence::High } else { Confidence::Medium };

    ServiceInfo {
        service_name,
        version,
        banner: banner.lines().take(10).collect::<Vec<_>>().join("\n"),
        confidence,
    }
}

fn parse_ftp_banner(banner: &str) -> ServiceInfo {
    let mut service_name = "FTP".to_string();
    let mut version = None;

    if banner.contains("vsFTPd") {
        service_name = "vsFTPd".to_string();
        if let Some(v) = banner.split("vsFTPd").nth(1) {
            version = Some(v.trim().trim_matches(|c: char| !c.is_ascii_digit() && c != '.').to_string());
        }
    } else if banner.contains("ProFTPD") {
        service_name = "ProFTPD".to_string();
    } else if banner.contains("FileZilla") {
        service_name = "FileZilla Server".to_string();
    }

    let confidence = if version.is_some() { Confidence::High } else { Confidence::Medium };

    ServiceInfo {
        service_name,
        version,
        banner: banner.to_string(),
        confidence,
    }
}

fn parse_smtp_banner(banner: &str) -> ServiceInfo {
    let mut service_name = "SMTP".to_string();
    let version = None;

    if banner.contains("Postfix") {
        service_name = "Postfix".to_string();
    } else if banner.contains("Exim") {
        service_name = "Exim".to_string();
    } else if banner.contains("Sendmail") {
        service_name = "Sendmail".to_string();
    } else if banner.contains("Microsoft ESMTP MAIL") {
        service_name = "Microsoft Exchange".to_string();
    }

    ServiceInfo {
        service_name,
        version,
        banner: banner.to_string(),
        confidence: Confidence::Medium,
    }
}

fn parse_mysql_banner(banner: &str) -> ServiceInfo {
    ServiceInfo {
        service_name: "MySQL".to_string(),
        version: None,
        banner: banner.to_string(),
        confidence: Confidence::Medium,
    }
}

fn identify_by_port(port: u16, banner: &str) -> ServiceInfo {
    let (service_name, confidence) = match port {
        20 | 21 => ("FTP", Confidence::Low),
        22 => ("SSH", Confidence::Low),
        23 => ("Telnet", Confidence::Low),
        25 => ("SMTP", Confidence::Low),
        53 => ("DNS", Confidence::Low),
        80 => ("HTTP", Confidence::Low),
        110 => ("POP3", Confidence::Low),
        143 => ("IMAP", Confidence::Low),
        443 => ("HTTPS", Confidence::Low),
        445 => ("SMB", Confidence::Low),
        3306 => ("MySQL", Confidence::Low),
        3389 => ("RDP", Confidence::Low),
        5432 => ("PostgreSQL", Confidence::Low),
        5900 => ("VNC", Confidence::Low),
        6379 => ("Redis", Confidence::Low),
        8080 => ("HTTP-Proxy", Confidence::Low),
        27017 => ("MongoDB", Confidence::Low),
        _ => ("Unknown", Confidence::Low),
    };

    ServiceInfo {
        service_name: service_name.to_string(),
        version: None,
        banner: banner.to_string(),
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_banner() {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let info = parse_ssh_banner(banner);
        assert_eq!(info.service_name, "OpenSSH");
        assert!(info.version.is_some());
        assert_eq!(info.confidence as u8, Confidence::High as u8);
    }

    #[test]
    fn test_parse_http_nginx() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
        let info = parse_http_banner(banner);
        assert_eq!(info.service_name, "nginx");
        assert_eq!(info.version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_parse_http_apache() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n";
        let info = parse_http_banner(banner);
        assert_eq!(info.service_name, "Apache");
        assert!(info.version.is_some());
    }

    #[test]
    fn test_identify_by_port() {
        let info = identify_by_port(3306, "");
        assert_eq!(info.service_name, "MySQL");

        let info = identify_by_port(6379, "");
        assert_eq!(info.service_name, "Redis");

        let info = identify_by_port(9999, "");
        assert_eq!(info.service_name, "Unknown");
    }

    #[test]
    fn test_parse_ftp_vsftpd() {
        let banner = "220 (vsFTPd 3.0.3)";
        let info = parse_ftp_banner(banner);
        assert_eq!(info.service_name, "vsFTPd");
        assert!(info.version.is_some());
    }

    #[test]
    fn test_smtp_postfix() {
        let banner = "220 mail.example.com ESMTP Postfix";
        let info = parse_smtp_banner(banner);
        assert_eq!(info.service_name, "Postfix");
    }
}
