use anyhow::Result;
use clap::Parser;
use rust_network_scanner::scanner::{NetworkScanner, HostResult};
use tracing::{info, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "network-scanner")]
#[command(about = "Network scanner that discovers gateway, network, and scans for active hosts")]
#[command(version)]
struct Cli {
    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Scan specific network (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    network: Option<String>,

    /// Scan ports on discovered hosts
    #[arg(short, long)]
    ports: bool,

    /// Common ports to scan (comma-separated)
    #[arg(long, default_value = "80,443,22,8080")]
    port_list: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    info!("Starting Network Scanner");

    let scanner = NetworkScanner::new();

    // Discover network configuration
    let network_info = scanner.discover_network()?;

    // Output network information
    match cli.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&network_info)?);
        }
        _ => {
            print_network_info(&network_info);
        }
    }

    // Determine which network to scan
    let networks_to_scan = if let Some(network_str) = cli.network {
        vec![network_str.parse()?]
    } else {
        // Use networks from interfaces
        network_info.interfaces.iter()
            .map(|iface| iface.network)
            .collect()
    };

    // Scan networks
    let mut all_results: Vec<HostResult> = Vec::new();
    for network in networks_to_scan {
        info!("Scanning network: {}", network);
        let results = scanner.scan_network(&network).await?;
        all_results.extend(results);
    }

    // Port scanning if requested
    if cli.ports {
        let ports: Vec<u16> = cli.port_list
            .split(',')
            .map(|s| s.trim().parse().unwrap_or(0))
            .filter(|&p| p > 0)
            .collect();

        for host in &all_results {
            if host.is_up {
                let open_ports = scanner.scan_ports(host.ip, &ports).await?;
                info!("Host {} has open ports: {:?}", host.ip, open_ports);
            }
        }
    }

    // Output results
    match cli.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&all_results)?);
        }
        _ => {
            print_scan_results(&all_results);
        }
    }

    info!("Scan complete. Found {} active hosts", all_results.len());
    Ok(())
}

fn print_network_info(info: &rust_network_scanner::scanner::NetworkInfo) {
    println!("\n=== Network Configuration ===\n");
    
    if let Some(gateway) = info.gateway {
        println!("Default Gateway: {}", gateway);
    } else {
        println!("Default Gateway: Not found");
    }

    println!("\n--- Interfaces ---");
    for iface in &info.interfaces {
        println!("  {}: {} ({})", iface.name, iface.ip, iface.network);
    }

    println!("\n--- Routes ---");
    for route in &info.routes {
        let gw_str = route.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".to_string());
        println!("  {} via {} dev {}", route.destination, gw_str, route.interface);
    }
    println!();
}

fn print_scan_results(results: &[HostResult]) {
    println!("\n=== Scan Results ===\n");
    
    if results.is_empty() {
        println!("No active hosts found.");
        return;
    }

    println!("Found {} active host(s):\n", results.len());
    
    for host in results {
        let hostname = host.hostname.as_deref().unwrap_or("unknown");
        let response_time = host.response_time_ms.map(|t| format!("{}ms", t)).unwrap_or_else(|| "N/A".to_string());
        let mac = host.mac_address.as_deref().unwrap_or("-");
        
        println!("  {} ({})", host.ip, hostname);
        println!("    Response time: {}", response_time);
        println!("    MAC address: {}", mac);
        println!();
    }
}
