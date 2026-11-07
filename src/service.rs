use anyhow::Result;
use crate::service_db::{self, Probe, ServiceMatch, ServiceMatcher};
use crate::tls::{self, TlsCertInfo};
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{self, FuturesUnordered, StreamExt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{timeout, timeout_at, Instant};
use tracing::debug;

/// Banner services speak first, so the empty probe gets this long before other probes join it.
const EMPTY_PROBE_HEAD_START: Duration = Duration::from_millis(300);
/// Connections open to one port at once. This overlap is what makes silent ports cheap.
const PROBES_AT_ONCE: usize = 8;
/// Silence after data that ends a read, for servers that hold the connection open.
const QUIET_AFTER_DATA: Duration = Duration::from_millis(300);
const MIN_PROBE_WAIT: Duration = Duration::from_secs(3);
const MAX_RESPONSE: usize = 16 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    pub service_name: String,
    pub version: Option<String>,
    pub banner: String,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsCertInfo>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl From<service_db::Confidence> for Confidence {
    fn from(confidence: service_db::Confidence) -> Self {
        match confidence {
            service_db::Confidence::High => Confidence::High,
            service_db::Confidence::Medium => Confidence::Medium,
            service_db::Confidence::Low => Confidence::Low,
        }
    }
}

pub async fn grab_banner_with_db(
    ip: IpAddr,
    port: u16,
    probe_timeout: Duration,
    matcher: Option<&ServiceMatcher>,
    intensity: u8,
    sockets: &Semaphore,
) -> Result<ServiceInfo> {
    if let Some(matcher) = matcher {
        let session = Session {
            ip,
            port,
            matcher,
            wait: probe_timeout.max(MIN_PROBE_WAIT),
            sockets,
        };
        if let Some(info) = session.detect(intensity).await {
            return Ok(info);
        }
    }
    grab_banner(ip, port, probe_timeout).await
}

/// Names a UDP service by running the signature database's UDP probes against it.
pub async fn detect_udp(
    ip: IpAddr,
    port: u16,
    wait: Duration,
    matcher: Option<&ServiceMatcher>,
    intensity: u8,
    sockets: &Semaphore,
) -> Option<ServiceInfo> {
    let guess = || Some(identify_by_port(port, "")).filter(|info| info.service_name != "Unknown");
    let Some(matcher) = matcher else { return guess() };

    let mut replies = stream::iter(matcher.udp_probes_for(port, intensity))
        .map(|probe| async move {
            let _permit = sockets.acquire().await.expect("semaphore is never closed");
            let response = udp_exchange(ip, port, &probe.payload, wait).await?;
            let found = matcher.match_response(probe, &response);
            Some((response, found))
        })
        .buffer_unordered(PROBES_AT_ONCE);

    let mut findings = Findings::default();
    while let Some(reply) = replies.next().await {
        let Some((response, found)) = reply else { continue };
        if findings.absorb(Reply { response, found, cert: None }) {
            break;
        }
    }

    let answered = findings.hard.is_some() || findings.soft.is_some() || !findings.banner.is_empty();
    if answered { Some(findings.into_service(port)) } else { guess() }
}

async fn udp_exchange(ip: IpAddr, port: u16, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(SocketAddr::new(ip, port)).await.ok()?;
    socket.send(payload).await.ok()?;

    let mut buffer = vec![0u8; 8192];
    let received = timeout(wait, socket.recv(&mut buffer)).await.ok()?.ok()?;
    buffer.truncate(received);
    Some(buffer)
}

/// One probe's raw reply, kept as evidence for building and checking signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Recording {
    pub port: u16,
    pub protocol: String,
    pub tunnel: bool,
    pub probe: String,
    pub response_hex: String,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Sends every probe to a port, keeping all non-empty replies. Unlike detection it does not stop
/// at the first match, and it ignores port registration, because the port may be remapped.
pub async fn record_port(
    ip: IpAddr,
    port: u16,
    udp: bool,
    wait: Duration,
    matcher: &ServiceMatcher,
    sockets: &Semaphore,
) -> Vec<Recording> {
    const EVERY_PROBE: u8 = 9;
    let wait = wait.max(MIN_PROBE_WAIT);
    let record = |probe: &Probe, tunnel: bool, response: &[u8]| Recording {
        port,
        protocol: if udp { "udp" } else { "tcp" }.to_string(),
        tunnel,
        probe: probe.name.clone(),
        response_hex: to_hex(response),
    };

    if udp {
        let probes = matcher.udp_probes_for(port, EVERY_PROBE);
        return stream::iter(probes)
            .map(|probe| async move {
                let _permit = sockets.acquire().await.expect("semaphore is never closed");
                let response = udp_exchange(ip, port, &probe.payload, wait).await?;
                Some(record(probe, false, &response))
            })
            .buffer_unordered(PROBES_AT_ONCE)
            .filter_map(|recording| async move { recording })
            .collect()
            .await;
    }

    let session = Session { ip, port, matcher, wait, sockets };
    let probes = matcher.probes_for(port, false, EVERY_PROBE);

    // Probes go inside TLS only when the port completes a handshake, so plain services are
    // not sent a second round that cannot succeed.
    let speaks_tls = tls::tls_connect(ip, port, wait).await.is_ok();
    let mut recordings = Vec::new();
    for tunnel in [false, true] {
        if tunnel && !speaks_tls {
            break;
        }
        let replies = exchange_all(&session, &probes, tunnel).await;
        recordings.extend(
            replies
                .iter()
                .filter(|(_, reply)| !reply.response.is_empty())
                .map(|(probe, reply)| record(probe, tunnel, &reply.response)),
        );
    }
    recordings
}

async fn exchange_all<'a>(session: &Session<'a>, probes: &[&'a Probe], tunnel: bool) -> Vec<(&'a Probe, Reply)> {
    stream::iter(probes.iter().copied())
        .map(|probe| async move { (probe, session.exchange(probe, tunnel).await) })
        .buffer_unordered(PROBES_AT_ONCE)
        .collect()
        .await
}

struct Session<'a> {
    ip: IpAddr,
    port: u16,
    matcher: &'a ServiceMatcher,
    wait: Duration,
    sockets: &'a Semaphore,
}

#[derive(Default)]
struct Reply {
    response: Vec<u8>,
    found: Option<ServiceMatch>,
    cert: Option<TlsCertInfo>,
}

#[derive(Default)]
struct Findings {
    hard: Option<(ServiceMatch, Vec<u8>)>,
    soft: Option<(ServiceMatch, Vec<u8>)>,
    banner: Vec<u8>,
    cert: Option<TlsCertInfo>,
}

impl Findings {
    /// Returns true once a hard match makes further probing pointless.
    fn absorb(&mut self, reply: Reply) -> bool {
        self.cert = self.cert.take().or(reply.cert);
        match reply.found {
            Some(m) if m.confidence == service_db::Confidence::High => {
                self.hard = Some((m, reply.response));
                return true;
            }
            Some(m) => {
                self.soft.get_or_insert((m, reply.response));
            }
            None if self.banner.is_empty() => self.banner = reply.response,
            None => {}
        }
        false
    }

    fn into_service(self, port: u16) -> ServiceInfo {
        if let Some((m, response)) = self.hard.or(self.soft) {
            return ServiceInfo {
                service_name: m.product.unwrap_or(m.service_name),
                version: m.version,
                banner: String::from_utf8_lossy(&response).into_owned(),
                confidence: m.confidence.into(),
                cpe: (!m.cpe.is_empty()).then_some(m.cpe),
                os_hint: m.os,
                tls_info: self.cert,
            };
        }

        let mut info = if !self.banner.is_empty() {
            identify_service(port, &String::from_utf8_lossy(&self.banner))
        } else if self.cert.is_some() {
            ServiceInfo { service_name: "ssl/unknown".to_string(), ..identify_by_port(port, "") }
        } else {
            identify_by_port(port, "")
        };
        info.tls_info = self.cert;
        info
    }
}

impl Session<'_> {
    async fn detect(&self, intensity: u8) -> Option<ServiceInfo> {
        let plain = self.matcher.probes_for(self.port, false, intensity);
        if plain.is_empty() {
            return None;
        }
        let tunneled = self.matcher.probes_for(self.port, true, intensity);

        let registered_for_tls = plain
            .iter()
            .any(|p| p.ssl_ports.as_ref().is_some_and(|ports| ports.contains(&self.port)));
        if tls::is_likely_ssl_port(self.port) || registered_for_tls {
            let findings = self.run(&tunneled, true).await;
            if findings.cert.is_some() {
                return Some(findings.into_service(self.port));
            }
        }

        let findings = self.run(&plain, false).await;
        if findings.hard.as_ref().is_some_and(|(m, _)| m.service_name == "ssl") {
            let inside = self.run(&tunneled, true).await;
            if inside.cert.is_some() {
                return Some(inside.into_service(self.port));
            }
        }
        Some(findings.into_service(self.port))
    }

    async fn run(&self, probes: &[&Probe], tunnel: bool) -> Findings {
        let mut findings = Findings::default();
        let Some((first, rest)) = probes.split_first() else { return findings };
        let mut running = FuturesUnordered::<BoxFuture<'_, Reply>>::new();

        let mut empty_probe = self.exchange(first, tunnel).boxed();
        match timeout(EMPTY_PROBE_HEAD_START, &mut empty_probe).await {
            Ok(reply) => {
                if findings.absorb(reply) {
                    return findings;
                }
            }
            Err(_) => running.push(empty_probe),
        }

        let mut queue = rest.iter();
        loop {
            while running.len() < PROBES_AT_ONCE {
                let Some(probe) = queue.next() else { break };
                running.push(self.exchange(probe, tunnel).boxed());
            }
            let Some(reply) = running.next().await else { return findings };
            if findings.absorb(reply) {
                return findings;
            }
        }
    }

    async fn exchange(&self, probe: &Probe, tunnel: bool) -> Reply {
        let _permit = self.sockets.acquire().await.expect("semaphore is never closed");

        let declared_wait = Duration::from_millis(probe.total_wait_ms);
        // The empty probe runs alongside the others, so its full wait costs nothing extra.
        let wait = if probe.payload.is_empty() { declared_wait } else { declared_wait.min(self.wait) };
        let deadline = Instant::now() + wait;

        if tunnel {
            let Ok((mut stream, cert)) = tls::tls_connect(self.ip, self.port, wait).await else {
                return Reply::default();
            };
            let (response, found) = self.talk(&mut stream, probe, deadline).await;
            return Reply { response, found, cert };
        }

        let addr = SocketAddr::new(self.ip, self.port);
        let Ok(Ok(mut stream)) = timeout(wait, TcpStream::connect(addr)).await else {
            return Reply::default();
        };
        let (response, found) = self.talk(&mut stream, probe, deadline).await;
        Reply { response, found, cert: None }
    }

    async fn talk<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        probe: &Probe,
        deadline: Instant,
    ) -> (Vec<u8>, Option<ServiceMatch>) {
        if !probe.payload.is_empty()
            && (stream.write_all(&probe.payload).await.is_err() || stream.flush().await.is_err())
        {
            return (Vec::new(), None);
        }

        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut found = None;
        let mut read_until = deadline;

        while response.len() < MAX_RESPONSE {
            match timeout_at(read_until, stream.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => response.extend_from_slice(&chunk[..n]),
                _ => break,
            }
            found = self.matcher.match_response(probe, &response);
            if found.as_ref().is_some_and(|m| m.confidence == service_db::Confidence::High) {
                debug!("Probe '{}' matched on {}:{}", probe.name, self.ip, self.port);
                break;
            }
            read_until = deadline.min(Instant::now() + QUIET_AFTER_DATA);
        }

        (response, found)
    }
}

/// Identification without a signature database.
pub async fn grab_banner(
    ip: IpAddr,
    port: u16,
    probe_timeout: Duration,
) -> Result<ServiceInfo> {
    let addr = SocketAddr::new(ip, port);

    if tls::is_likely_ssl_port(port) {
        if let Ok((banner, cert_info)) = tls::tls_grab_banner(ip, port, probe_timeout).await {
            if !banner.is_empty() {
                let mut info = identify_service(port, &banner);
                info.tls_info = cert_info;
                return Ok(info);
            }
            return Ok(ServiceInfo {
                service_name: "HTTPS".to_string(),
                version: None,
                banner: String::new(),
                confidence: Confidence::Medium,
                cpe: None,
                os_hint: None,
                tls_info: cert_info,
            });
        }
    }

    let mut stream = timeout(probe_timeout, TcpStream::connect(addr)).await??;

    let mut buffer = vec![0u8; 4096];
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

    Ok(identify_service(port, &banner))
}

async fn send_probe(stream: &mut TcpStream, port: u16) -> Result<String> {
    let probe = match port {
        80 | 8080 | 8000 | 8888 => {
            "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        }
        443 | 8443 => return Ok(String::new()),
        21 => return Ok(String::new()),
        25 | 587 => return Ok(String::new()),
        _ => return Ok(String::new()),
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
            cpe: None,
            os_hint: None,
            tls_info: None,
        };
    }

    if port == 6379 || banner.starts_with("-ERR") || banner.starts_with("+PONG") {
        return ServiceInfo {
            service_name: "Redis".to_string(),
            version: None,
            banner: banner.to_string(),
            confidence: Confidence::Medium,
            cpe: None,
            os_hint: None,
            tls_info: None,
        };
    }

    if port == 27017 {
        return ServiceInfo {
            service_name: "MongoDB".to_string(),
            version: None,
            banner: banner.to_string(),
            confidence: Confidence::Low,
            cpe: None,
            os_hint: None,
            tls_info: None,
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
        cpe: None,
        os_hint: None,
        tls_info: None,
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
        cpe: None,
        os_hint: None,
        tls_info: None,
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
        cpe: None,
        os_hint: None,
        tls_info: None,
    }
}

fn parse_smtp_banner(banner: &str) -> ServiceInfo {
    let mut service_name = "SMTP".to_string();

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
        version: None,
        banner: banner.to_string(),
        confidence: Confidence::Medium,
        cpe: None,
        os_hint: None,
        tls_info: None,
    }
}

fn parse_mysql_banner(banner: &str) -> ServiceInfo {
    ServiceInfo {
        service_name: "MySQL".to_string(),
        version: None,
        banner: banner.to_string(),
        confidence: Confidence::Medium,
        cpe: None,
        os_hint: None,
        tls_info: None,
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
        cpe: None,
        os_hint: None,
        tls_info: None,
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

    #[test]
    fn test_service_info_has_cpe_field() {
        let info = ServiceInfo {
            service_name: "nginx".to_string(),
            version: Some("1.18.0".to_string()),
            banner: "test".to_string(),
            confidence: Confidence::High,
            cpe: Some(vec!["cpe:/a:nginx:nginx:1.18.0".to_string()]),
            os_hint: None,
            tls_info: None,
        };
        assert!(info.cpe.is_some());
        assert_eq!(info.cpe.unwrap().len(), 1);
    }

    mod detection {
        use super::*;
        use crate::service_db::parse_service_probes;
        use std::net::Ipv4Addr;
        use tokio::net::TcpListener;

        const DB: &str = r#"
Probe TCP NULL q||
totalwaitms 2000
match ssh m|^SSH-2\.0-OpenSSH_([\w.]+)| p/OpenSSH/ v/$1/
match mysql m|^.\0\0\0\x0a([\w.]+)\0| p/MySQL/ v/$1/
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80
match http m|^HTTP/1\.0 200 OK\r\nServer: nginx/([\d.]+)| p/nginx/ v/$1/
Probe TCP Quiet q|ping\r\n|
rarity 1
match demo m|^pong| p/Demo/
"#;

        /// Serves each connection with `reply(what the client sent)`, after `delay`.
        async fn serve(delay: Duration, greet: &'static [u8], http: bool) -> u16 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        if http {
                            let mut buffer = [0u8; 256];
                            let n = socket.read(&mut buffer).await.unwrap_or(0);
                            if !buffer[..n].starts_with(b"GET") {
                                return;
                            }
                        }
                        tokio::time::sleep(delay).await;
                        let _ = socket.write_all(greet).await;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    });
                }
            });
            port
        }

        async fn detect(port: u16) -> ServiceInfo {
            let matcher = ServiceMatcher::new(parse_service_probes(DB).unwrap());
            let sockets = Semaphore::new(32);
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            grab_banner_with_db(ip, port, Duration::from_secs(1), Some(&matcher), 7, &sockets)
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn binary_banner_is_identified() {
            let port = serve(Duration::ZERO, b"\xff\0\0\0\x0a8.0.36\0\xf7", false).await;
            let info = detect(port).await;
            assert_eq!(info.service_name, "MySQL");
            assert_eq!(info.version.as_deref(), Some("8.0.36"));
        }

        #[tokio::test]
        async fn http_on_an_unregistered_port_is_identified() {
            let port = serve(Duration::ZERO, b"HTTP/1.0 200 OK\r\nServer: nginx/1.25.3\r\n\r\n", true).await;
            let info = detect(port).await;
            assert_eq!(info.service_name, "nginx");
            assert_eq!(info.version.as_deref(), Some("1.25.3"));
        }

        #[tokio::test]
        async fn banner_arriving_after_the_head_start_is_still_caught() {
            let port = serve(Duration::from_millis(900), b"SSH-2.0-OpenSSH_9.6\r\n", false).await;
            assert_eq!(detect(port).await.service_name, "OpenSSH");
        }

        #[tokio::test]
        async fn udp_service_is_named_from_its_reply() {
            const UDP_DB: &str = "Probe UDP Hello q|hi|\nrarity 1\nmatch demo m|^world ([\\d.]+)| p/Demo/ v/$1/\n";
            let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = server.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut buffer = [0u8; 16];
                let (_, peer) = server.recv_from(&mut buffer).await.unwrap();
                server.send_to(b"world 1.2", peer).await.unwrap();
            });

            let matcher = ServiceMatcher::new(parse_service_probes(UDP_DB).unwrap());
            let sockets = Semaphore::new(4);
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let info = detect_udp(ip, port, Duration::from_secs(1), Some(&matcher), 7, &sockets)
                .await
                .unwrap();
            assert_eq!(info.service_name, "Demo");
            assert_eq!(info.version.as_deref(), Some("1.2"));
        }

        #[tokio::test]
        async fn udp_port_with_no_answer_and_no_known_name_stays_unnamed() {
            let matcher = ServiceMatcher::new(parse_service_probes(DB).unwrap());
            let sockets = Semaphore::new(4);
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            assert!(detect_udp(ip, 41999, Duration::from_millis(50), Some(&matcher), 7, &sockets).await.is_none());
        }

        #[tokio::test]
        async fn recording_keeps_replies_from_every_probe_that_answered() {
            let port = serve(Duration::ZERO, b"SSH-2.0-OpenSSH_9.6\r\n", false).await;
            let matcher = ServiceMatcher::new(parse_service_probes(DB).unwrap());
            let sockets = Semaphore::new(32);
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

            let recordings = record_port(ip, port, false, Duration::from_secs(1), &matcher, &sockets).await;
            let empty_probe = recordings.iter().find(|r| r.probe == "NULL").unwrap();
            assert!(empty_probe.response_hex.starts_with(&to_hex(b"SSH-2.0")));
            assert_eq!(empty_probe.protocol, "tcp");
            assert!(!empty_probe.tunnel);
        }

        #[tokio::test]
        async fn hard_match_stops_waiting_for_slower_probes() {
            let port = serve(Duration::ZERO, b"SSH-2.0-OpenSSH_9.6\r\n", false).await;
            let start = Instant::now();
            detect(port).await;
            assert!(start.elapsed() < Duration::from_millis(250), "took {:?}", start.elapsed());
        }
    }
}
