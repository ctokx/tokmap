use tokmap::service_db::parse_service_probes;

#[test]
fn test_database_statistics() {
    let content = std::fs::read_to_string("nmap-service-probes")
        .expect("nmap-service-probes file not found");

    let db = parse_service_probes(&content)
        .expect("Failed to parse database");

    let mut total_matches = 0;
    let mut total_soft_matches = 0;

    for probe in &db.probes {
        total_matches += probe.matches.len();
        total_soft_matches += probe.soft_matches.len();
    }

    assert!(db.probes.len() > 100, "Expected >100 probes, got {}", db.probes.len());
    assert!(total_matches > 5000, "Expected >5000 hard matches, got {}", total_matches);
    assert!(total_matches + total_soft_matches > 7000, "Expected >7000 total signatures, got {}", total_matches + total_soft_matches);
}
