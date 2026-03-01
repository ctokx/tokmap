use anyhow::Result;
use clap::Parser;
use std::time::Duration;
use tokmap::{output, parse_targets, ports, Scanner, ScanConfig, ScanType, TimingTemplate};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target specification (IP, CIDR, hostname, range)
    #[arg(short, long, value_delimiter = ',')]
    targets: Vec<String>,

    /// Ports to scan (comma-separated or range like 1-1000)
    #[arg(short, long, value_delimiter = ',')]
    ports: Option<Vec<String>>,

    /// Scan top N most common ports
    #[arg(long = "top-ports")]
    top_ports: Option<usize>,

    /// Fast mode - scan top 100 ports
    #[arg(short = 'F', long)]
    fast: bool,

    /// Timing template: paranoid(0), sneaky(1), polite(2), normal(3), aggressive(4), insane(5)
    #[arg(short = 'T', long, value_parser = clap::value_parser!(u8).range(0..=5))]
    timing: Option<u8>,

    /// Timeout per port in milliseconds (overrides timing template)
    #[arg(long)]
    timeout: Option<u64>,

    /// Maximum concurrent scans (overrides timing template)
    #[arg(short, long)]
    concurrency: Option<usize>,

    /// Rate limit (packets per second)
    #[arg(short, long)]
    rate_limit: Option<u32>,

    /// TCP SYN scan (default, requires raw socket privileges)
    #[arg(long = "syn", short = 'S')]
    syn_scan: bool,

    /// TCP connect scan (no privileges required)
    #[arg(long = "connect", short = 'T')]
    connect_scan: bool,

    /// TCP ACK scan (firewall rule discovery)
    #[arg(long = "ack", short = 'A')]
    ack_scan: bool,

    /// TCP Window scan
    #[arg(long = "window", short = 'W')]
    window_scan: bool,

    /// TCP FIN scan (stealth)
    #[arg(long = "fin", short = 'F')]
    fin_scan: bool,

    /// TCP NULL scan (stealth)
    #[arg(long = "null", short = 'N')]
    null_scan: bool,

    /// TCP Xmas scan (stealth)
    #[arg(long = "xmas", short = 'X')]
    xmas_scan: bool,

    /// UDP scan
    #[arg(long = "udp", short = 'U')]
    udp_scan: bool,

    /// Treat all hosts as online (skip host discovery)
    #[arg(short = 'P', long)]
    skip_discovery: bool,

    /// Ping scan only (no port scan)
    #[arg(long)]
    ping_scan: bool,

    /// Enable service/version detection (banner grabbing)
    #[arg(short = 's', long = "service-detect")]
    service_detection: bool,

    /// Version detection intensity (0-9, default 7)
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=9))]
    version_intensity: Option<u8>,

    /// Enable OS detection
    #[arg(short = 'O', long = "os-detect")]
    os_detection: bool,

    /// Aggressive scan (-O -sV --traceroute)
    #[arg(short = 'A', long)]
    aggressive: bool,

    /// Enable LLM-powered analysis (requires GEMINI_API_KEY env var)
    #[arg(long = "llm")]
    llm_enabled: bool,

    /// Never do DNS resolution
    #[arg(short = 'n', long)]
    no_dns: bool,

    /// Always resolve (default behavior)
    #[arg(short = 'R', long)]
    dns_servers: bool,

    /// Output file for JSON results
    #[arg(short, long)]
    output: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// JSON-only output (no summary)
    #[arg(long)]
    json_only: bool,

    /// Nmap-style table output (default for terminal)
    #[arg(long)]
    nmap_style: bool,
}

impl Args {
    fn get_scan_type(&self) -> ScanType {
        if self.connect_scan {
            ScanType::Connect
        } else if self.ack_scan {
            ScanType::Ack
        } else if self.window_scan {
            ScanType::Window
        } else if self.fin_scan {
            ScanType::Fin
        } else if self.null_scan {
            ScanType::Null
        } else if self.xmas_scan {
            ScanType::Xmas
        } else {
            ScanType::Syn
        }
    }

    fn get_timing_template(&self) -> TimingTemplate {
        TimingTemplate::from_level(self.timing.unwrap_or(3))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    if args.targets.is_empty() {
        eprintln!("Error: At least one target must be specified");
        eprintln!("Example: tokmap -t 192.168.1.1");
        eprintln!("         tokmap -t 192.168.1.0/24 -F");
        eprintln!("         tokmap -t scanme.nmap.org --service-detect");
        std::process::exit(1);
    }

    info!("Parsing targets: {:?}", args.targets);
    let target_ips = parse_targets(&args.targets)?;
    info!("Expanded to {} target IPs", target_ips.len());

    if target_ips.is_empty() {
        eprintln!("Error: No valid targets found");
        std::process::exit(1);
    }

    let ports = if let Some(ref port_specs) = args.ports {
        ports::parse_port_spec(port_specs)?
    } else if args.fast {
        ports::get_ports(Some(100), true)
    } else if let Some(n) = args.top_ports {
        ports::get_ports(Some(n), false)
    } else {
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
            5900, 8080,
        ]
    };

    if ports.is_empty() {
        eprintln!("Error: At least one port must be specified");
        std::process::exit(1);
    }

    let timing = args.get_timing_template();
    let timing_config = timing.to_config();

    info!(
        "Tokmap v{} - Network Scanner",
        env!("CARGO_PKG_VERSION")
    );
    info!("Timing: {}", timing);
    info!("Targets: {} hosts", target_ips.len());
    info!("Ports: {} ports per host", ports.len());

    let service_detection = args.service_detection || args.aggressive;
    let os_detection = args.os_detection || args.aggressive;

    let config = ScanConfig {
        targets: target_ips.clone(),
        ports,
        timeout: Duration::from_millis(args.timeout.unwrap_or(timing_config.timeout.as_millis() as u64)),
        max_concurrent: args.concurrency.unwrap_or(timing_config.max_concurrent),
        rate_limit: args.rate_limit.or(timing_config.rate_limit),
        service_detection,
        llm_enabled: args.llm_enabled,
        scan_type: args.get_scan_type(),
        udp_scan: args.udp_scan,
        host_discovery: !args.skip_discovery,
        ping_scan_only: args.ping_scan,
        version_intensity: args.version_intensity.unwrap_or(7),
        os_detection,
        resolve_dns: !args.no_dns,
    };

    let scanner = Scanner::new(config);
    let results = scanner.scan().await?;

    let open_ports: usize = results
        .targets
        .iter()
        .map(|h| h.ports.iter().filter(|p| p.state == tokmap::PortState::Open).count())
        .sum();

    if let Some(output_path) = &args.output {
        info!("Writing results to: {}", output_path);
        output::OutputFormatter::write_json_file(&results, output_path)?;
    }

    if args.json_only {
        output::OutputFormatter::write_json(&results)?;
    } else if args.nmap_style || atty::is(atty::Stream::Stdout) {
        output::OutputFormatter::print_summary(&results);
        if args.verbose {
            println!("\n--- JSON Output ---");
            output::OutputFormatter::write_json(&results)?;
        }
    } else {
        output::OutputFormatter::write_json(&results)?;
    }

    info!(
        "Scan complete! {} open ports found across {} hosts in {:.2}s",
        open_ports,
        results.targets.len(),
        results.total_duration_ms as f64 / 1000.0
    );

    Ok(())
}
