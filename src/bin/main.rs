use anyhow::Result;
use clap::Parser;
use std::time::Duration;
use tokmap::{connect, output, parse_targets, ports, Scanner, ScanConfig, ScanType, TimingTemplate, LLMAnalyzer};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about = "Tokmap - AI-powered network scanner", long_about = None, disable_version_flag = true)]
struct Args {
    #[arg(short, long, value_delimiter = ',')]
    targets: Vec<String>,

    #[arg(short, long, value_delimiter = ',')]
    ports: Option<Vec<String>>,

    #[arg(long = "top-ports")]
    top_ports: Option<usize>,

    #[arg(short = 'F', long)]
    fast: bool,

    #[arg(short = 'T', long, value_parser = clap::value_parser!(u8).range(0..=5))]
    timing: Option<u8>,

    #[arg(long)]
    timeout: Option<u64>,

    #[arg(short, long)]
    concurrency: Option<usize>,

    #[arg(short, long)]
    rate_limit: Option<u32>,

    #[arg(long = "syn", short = 'S')]
    syn_scan: bool,

    #[arg(long = "connect")]
    connect_scan: bool,

    #[arg(long = "ack")]
    ack_scan: bool,

    #[arg(long = "window")]
    window_scan: bool,

    #[arg(long = "fin")]
    fin_scan: bool,

    #[arg(long = "null")]
    null_scan: bool,

    #[arg(long = "xmas")]
    xmas_scan: bool,

    #[arg(long = "udp", short = 'U')]
    udp_scan: bool,

    #[arg(short = 'P', long)]
    skip_discovery: bool,

    #[arg(long)]
    ping_scan: bool,

    #[arg(short = 's', long = "service-detect")]
    service_detection: bool,

    /// Same as -s, so `-sV` works
    #[arg(short = 'V', hide = true)]
    version_detect: bool,

    /// Print version
    #[arg(long, action = clap::ArgAction::Version)]
    version: Option<bool>,

    /// Extra signature file, added to the built-in ones. Repeatable.
    #[arg(long = "signatures", value_name = "FILE")]
    signatures: Vec<String>,

    /// Save every probe's raw reply to DIR, as evidence for building signatures
    #[arg(long = "record", value_name = "DIR")]
    record: Option<String>,

    /// Trace the network path to each host
    #[arg(long)]
    traceroute: bool,

    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=9))]
    version_intensity: Option<u8>,

    #[arg(short = 'O', long = "os-detect")]
    os_detection: bool,

    #[arg(short = 'A', long)]
    aggressive: bool,

    #[arg(long = "llm")]
    llm_enabled: bool,

    #[arg(long = "llm-provider", value_name = "PROVIDER")]
    llm_provider: Option<String>,

    #[arg(long = "report")]
    generate_report: bool,

    #[arg(short = 'n', long)]
    no_dns: bool,

    #[arg(short = 'R', long)]
    dns_servers: bool,

    /// Write JSON results to FILE
    #[arg(short, long)]
    output: Option<String>,

    /// Write XML results to FILE
    #[arg(long, value_name = "FILE")]
    xml: Option<String>,

    /// Write one line per host to FILE
    #[arg(long, value_name = "FILE")]
    grepable: Option<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    json_only: bool,

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

    /// A UDP scan on its own scans no TCP, unless a TCP scan type is also asked for.
    fn tcp_requested(&self) -> bool {
        let tcp_type = self.syn_scan || self.connect_scan || self.ack_scan || self.window_scan
            || self.fin_scan || self.null_scan || self.xmas_scan;
        !self.udp_scan || tcp_type
    }

    fn get_timing_template(&self) -> TimingTemplate {
        TimingTemplate::from_level(self.timing.unwrap_or(3))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let max_sockets = args.concurrency.unwrap_or(args.get_timing_template().to_config().max_concurrent);
    // Must run before the runtime starts any threads.
    connect::prepare_socket_table(max_sockets);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    if args.targets.is_empty() {
        eprintln!("Error: At least one target must be specified");
        eprintln!("Example: tokmap -t 192.168.1.1");
        eprintln!("         tokmap -t 192.168.1.0/24 -F");
        eprintln!("         tokmap -t scanme.nmap.org --service-detect --llm --llm-provider claude");
        std::process::exit(1);
    }

    info!("Parsing targets: {:?}", args.targets);
    let target_ips = parse_targets(&args.targets)?;
    info!("Expanded to {} target IPs", target_ips.len());

    if target_ips.is_empty() {
        eprintln!("Error: No valid targets found");
        std::process::exit(1);
    }

    let (ports, udp_ports) = if let Some(ref port_specs) = args.ports {
        ports::split_port_spec(port_specs)?
    } else {
        let tcp = if args.fast {
            ports::get_ports(Some(100), true)
        } else if let Some(n) = args.top_ports {
            ports::get_ports(Some(n), false)
        } else {
            vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
                5900, 8080,
            ]
        };
        (tcp, ports::TOP_UDP_PORTS.to_vec())
    };

    let tcp_scan = args.tcp_requested();
    let nothing_to_scan = (!tcp_scan || ports.is_empty()) && (!args.udp_scan || udp_ports.is_empty());
    if nothing_to_scan && !args.ping_scan {
        eprintln!("Error: At least one port must be specified");
        std::process::exit(1);
    }

    let timing = args.get_timing_template();
    let timing_config = timing.to_config();

    info!(
        "Tokmap v{} - AI-Powered Network Scanner",
        env!("CARGO_PKG_VERSION")
    );
    info!("Timing: {}", timing);
    info!("Targets: {} hosts", target_ips.len());
    info!("Ports: {} ports per host", ports.len());

    let service_detection = args.service_detection || args.version_detect || args.aggressive;
    let os_detection = args.os_detection || args.aggressive;

    if args.llm_enabled {
        let provider_name = args.llm_provider.as_deref().unwrap_or("auto");
        info!("LLM analysis enabled (provider: {})", provider_name);
    }

    let config = ScanConfig {
        targets: target_ips.clone(),
        ports,
        udp_ports,
        timeout: Duration::from_millis(args.timeout.unwrap_or(timing_config.timeout.as_millis() as u64)),
        max_concurrent: args.concurrency.unwrap_or(timing_config.max_concurrent),
        max_retries: timing_config.max_retries,
        rate_limit: args.rate_limit.or(timing_config.rate_limit),
        service_detection,
        llm_enabled: args.llm_enabled,
        scan_type: args.get_scan_type(),
        tcp_scan,
        udp_scan: args.udp_scan,
        traceroute: args.traceroute,
        host_discovery: !args.skip_discovery,
        ping_scan_only: args.ping_scan,
        version_intensity: args.version_intensity.unwrap_or(7),
        os_detection,
        resolve_dns: !args.no_dns,
        signature_files: args.signatures.clone(),
        record_dir: args.record.clone(),
    };

    let scanner = Scanner::with_llm_provider(config, args.llm_provider.clone());
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
    if let Some(path) = &args.xml {
        output::OutputFormatter::write_xml(&results, Some(path))?;
    }
    if let Some(path) = &args.grepable {
        output::OutputFormatter::write_grepable(&results, Some(path))?;
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

    if args.generate_report {
        let llm = if let Some(ref provider_name) = args.llm_provider {
            LLMAnalyzer::from_provider_name(provider_name)
        } else {
            LLMAnalyzer::from_env()
        };

        if llm.is_enabled() {
            info!("Generating security report...");
            let scan_json = serde_json::to_string_pretty(&results)?;
            match llm.generate_report(&scan_json).await {
                Ok(Some(report)) => {
                    println!("\n{}", "=".repeat(60));
                    println!("SECURITY REPORT (Generated by {} LLM)", llm.provider_name());
                    println!("{}", "=".repeat(60));
                    println!("{}", report);
                }
                Ok(None) => {
                    warn!("Report generation returned empty result");
                }
                Err(e) => {
                    warn!("Report generation failed: {}", e);
                }
            }
        } else {
            eprintln!("Error: --report requires an LLM provider. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY");
        }
    }

    info!(
        "Scan complete! {} open ports found across {} hosts in {:.2}s",
        open_ports,
        results.targets.len(),
        results.total_duration_ms as f64 / 1000.0
    );

    Ok(())
}
