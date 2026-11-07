use anyhow::Result;
use rustls::ClientConfig;
use std::net::{IpAddr, SocketAddr};
use crate::types::format_utc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{ASN1Time, FromDer, GeneralName, X509Certificate};

const SECONDS_PER_DAY: i64 = 86400;

const COMMON_SSL_PORTS: &[u16] = &[
    443, 465, 636, 853, 989, 990, 993, 995, 2083, 2087, 2096, 2484,
    3269, 5061, 5986, 8443, 8883, 9443,
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsCertInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub san: Vec<String>,
    pub version: String,
    pub cipher_suite: Option<String>,
    /// Negative once the certificate has expired.
    pub days_until_expiry: Option<i64>,
}

pub fn is_likely_ssl_port(port: u16) -> bool {
    COMMON_SSL_PORTS.contains(&port)
}

pub fn is_ssl_port_for_probe(port: u16, ssl_ports: Option<&Vec<u16>>) -> bool {
    if let Some(ports) = ssl_ports {
        return ports.contains(&port);
    }
    is_likely_ssl_port(port)
}

/// Built once: a scan does thousands of handshakes and the config never changes.
fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth(),
            )
        })
        .clone()
}

pub async fn tls_connect(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Option<TlsCertInfo>)> {
    let connector = TlsConnector::from(client_config());
    let addr = SocketAddr::new(ip, port);

    let tcp = timeout(connect_timeout, TcpStream::connect(addr)).await??;

    let server_name = rustls_pki_types::ServerName::try_from(ip.to_string())
        .unwrap_or_else(|_| rustls_pki_types::ServerName::IpAddress(
            rustls_pki_types::IpAddr::from(match ip {
                IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
                IpAddr::V6(v6) => std::net::IpAddr::V6(v6),
            })
        ));

    let tls_stream = timeout(connect_timeout, connector.connect(server_name, tcp)).await??;

    let cert_info = extract_cert_info(&tls_stream);

    Ok((tls_stream, cert_info))
}

pub async fn tls_grab_banner(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> Result<(String, Option<TlsCertInfo>)> {
    let (mut tls_stream, cert_info) = tls_connect(ip, port, connect_timeout).await?;

    let mut buffer = vec![0u8; 4096];
    let n = match timeout(Duration::from_millis(500), tls_stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if n == 0 {
        let http_probe = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        let _ = tls_stream.write_all(http_probe).await;
        let n = match timeout(Duration::from_millis(1000), tls_stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
        return Ok((banner, cert_info));
    }

    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
    Ok((banner, cert_info))
}

fn extract_cert_info(tls_stream: &tokio_rustls::client::TlsStream<TcpStream>) -> Option<TlsCertInfo> {
    let (_, conn) = tls_stream.get_ref();

    let certs = conn.peer_certificates()?;
    let cert = certs.first()?;

    let cipher = conn.negotiated_cipher_suite().map(|cs| format!("{:?}", cs.suite()));
    let tls_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "Unknown",
    };

    let mut info = parse_der_cert(cert.as_ref());
    info.version = tls_version.to_string();
    info.cipher_suite = cipher;
    Some(info)
}

fn parse_der_cert(der: &[u8]) -> TlsCertInfo {
    let mut info = TlsCertInfo {
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        san: Vec::new(),
        version: String::new(),
        cipher_suite: None,
        days_until_expiry: None,
    };
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return info };

    let as_date = |time: ASN1Time| u64::try_from(time.timestamp()).ok().map(format_utc);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);

    info.subject = Some(cert.subject().to_string());
    info.issuer = Some(cert.issuer().to_string());
    info.not_before = as_date(cert.validity().not_before);
    info.not_after = as_date(cert.validity().not_after);
    info.days_until_expiry = Some((cert.validity().not_after.timestamp() - now) / SECONDS_PER_DAY);

    if let Ok(Some(names)) = cert.subject_alternative_name() {
        for name in &names.value.general_names {
            match name {
                GeneralName::DNSName(dns) => info.san.push(dns.to_string()),
                GeneralName::IPAddress(bytes) => info.san.extend(ip_from_bytes(bytes)),
                _ => {}
            }
        }
    }
    info
}

fn ip_from_bytes(bytes: &[u8]) -> Option<String> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::from(v4).to_string());
    }
    <[u8; 16]>::try_from(bytes).ok().map(|v6| IpAddr::from(v6).to_string())
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_fields_are_read() {
        let info = parse_der_cert(include_bytes!("../tests/fixtures/test-cert.der"));
        assert!(info.subject.as_deref().unwrap().contains("CN=test.example"));
        assert_eq!(info.subject, info.issuer, "self-signed");
        assert_eq!(info.san, ["test.example", "www.test.example", "192.0.2.7"]);
        assert!(info.not_after.as_deref().unwrap() > info.not_before.as_deref().unwrap());
        assert!(info.days_until_expiry.unwrap() > 0);
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        let info = parse_der_cert(b"not a certificate");
        assert_eq!(info.subject, None);
        assert_eq!(info.days_until_expiry, None);
    }

    #[test]
    fn test_is_likely_ssl_port() {
        assert!(is_likely_ssl_port(443));
        assert!(is_likely_ssl_port(8443));
        assert!(is_likely_ssl_port(993));
        assert!(is_likely_ssl_port(995));
        assert!(!is_likely_ssl_port(80));
        assert!(!is_likely_ssl_port(22));
    }

    #[test]
    fn test_is_ssl_port_for_probe() {
        assert!(is_ssl_port_for_probe(443, None));
        assert!(!is_ssl_port_for_probe(80, None));
        assert!(is_ssl_port_for_probe(8080, Some(&vec![8080, 9090])));
        assert!(!is_ssl_port_for_probe(80, Some(&vec![8080, 9090])));
    }

    #[test]
    fn test_tls_cert_info_serialize() {
        let info = TlsCertInfo {
            subject: Some("CN=example.com".to_string()),
            issuer: Some("CN=Let's Encrypt".to_string()),
            not_before: None,
            not_after: None,
            san: vec!["example.com".to_string(), "www.example.com".to_string()],
            version: "TLSv1.3".to_string(),
            cipher_suite: Some("TLS13_AES_256_GCM_SHA384".to_string()),
            days_until_expiry: Some(30),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("TLSv1.3"));
    }
}
