use anyhow::Result;
use rustls::ClientConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

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

pub async fn tls_connect(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Option<TlsCertInfo>)> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
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

pub async fn tls_probe_service(
    ip: IpAddr,
    port: u16,
    probe_payload: &[u8],
    connect_timeout: Duration,
) -> Result<(Vec<u8>, Option<TlsCertInfo>)> {
    let (mut tls_stream, cert_info) = tls_connect(ip, port, connect_timeout).await?;

    if !probe_payload.is_empty() {
        tls_stream.write_all(probe_payload).await?;
    }

    let mut buffer = vec![0u8; 4096];
    let mut total_read = 0;

    loop {
        match timeout(Duration::from_millis(800), tls_stream.read(&mut buffer[total_read..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total_read += n;
                if total_read >= 4096 {
                    break;
                }
            }
            _ => break,
        }
    }

    Ok((buffer[..total_read].to_vec(), cert_info))
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

    let (subject, issuer, not_before, not_after, san) = parse_der_cert(cert.as_ref());

    Some(TlsCertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        san,
        version: tls_version.to_string(),
        cipher_suite: cipher,
    })
}

fn parse_der_cert(der: &[u8]) -> (Option<String>, Option<String>, Option<String>, Option<String>, Vec<String>) {
    let mut subject = None;
    let mut issuer = None;
    let san = Vec::new();

    if der.len() > 10 {
        let hex_preview = der.iter().take(20).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        subject = Some(format!("DER cert ({}...)", hex_preview));
        issuer = Some("See certificate details".to_string());
    }

    (subject, issuer, None, None, san)
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
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("TLSv1.3"));
    }
}
