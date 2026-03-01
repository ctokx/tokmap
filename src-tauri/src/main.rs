// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokmap::{ScanConfig, Scanner};

#[derive(Debug, Serialize, Deserialize)]
struct ScanRequest {
    targets: Vec<String>,
    ports: Vec<u16>,
    timeout_ms: u64,
    max_concurrent: usize,
    rate_limit: Option<u32>,
    service_detection: bool,
    llm_enabled: bool,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    success: bool,
    results: Option<tokmap::ScanResults>,
    error: Option<String>,
}

#[tauri::command]
async fn run_scan(request: ScanRequest) -> ScanResponse {
    // Parse target IPs
    let targets: Result<Vec<IpAddr>, _> = request
        .targets
        .iter()
        .map(|s| s.parse())
        .collect();

    let targets = match targets {
        Ok(t) => t,
        Err(e) => {
            return ScanResponse {
                success: false,
                results: None,
                error: Some(format!("Invalid IP address: {}", e)),
            };
        }
    };

    // Create scan config
    let config = ScanConfig {
        targets,
        ports: request.ports,
        timeout: Duration::from_millis(request.timeout_ms),
        max_concurrent: request.max_concurrent,
        rate_limit: request.rate_limit,
        service_detection: request.service_detection,
        llm_enabled: request.llm_enabled,
    };

    // Run scan
    println!("DEBUG: Starting scan with config: {:?}", config);
    let scanner = Scanner::new(config);
    println!("DEBUG: Scanner initialized, beginning scan...");
    match scanner.scan().await {
        Ok(results) => ScanResponse {
            success: true,
            results: Some(results),
            error: None,
        },
        Err(e) => ScanResponse {
            success: false,
            results: None,
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_scan, get_version])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
