use tokmap::service_db::{parse_service_probes, ServiceMatcher};

#[test]
fn test_nmap_database_loads() {
    // Try to load the actual nmap-service-probes file
    let paths = [
        "nmap-service-probes",
        "../nmap-service-probes",
        "../../nmap-service-probes",
    ];

    let mut loaded = false;
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            match parse_service_probes(&content) {
                Ok(db) => {
                    println!("✓ Loaded database from {}", path);
                    println!("  Probes: {}", db.probes.len());
                    println!("  Excluded ports: {}", db.excluded_ports.len());

                    // Verify we have reasonable data
                    assert!(db.probes.len() > 100, "Should have at least 100 probes");

                    // Test matching
                    let matcher = ServiceMatcher::new(db);

                    // Test SSH banner
                    let ssh_match = matcher.match_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", 22);
                    assert!(ssh_match.is_some(), "Should match SSH banner");
                    if let Some(m) = ssh_match {
                        println!("  SSH Match: {}", m.service_name);
                        assert!(m.service_name.to_lowercase().contains("ssh"));
                    }

                    // Test HTTP banner
                    let http_match = matcher.match_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", 80);
                    assert!(http_match.is_some(), "Should match HTTP banner");
                    if let Some(m) = http_match {
                        println!("  HTTP Match: {}", m.service_name);
                    }

                    loaded = true;
                    break;
                }
                Err(e) => {
                    eprintln!("Failed to parse {}: {}", path, e);
                }
            }
        }
    }

    assert!(loaded, "Failed to load nmap-service-probes from any path");
}
