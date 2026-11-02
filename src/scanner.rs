use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub gateway: Option<IpAddr>,
    pub interfaces: Vec<InterfaceInfo>,
    pub routes: Vec<RouteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: IpAddr,
    pub netmask: IpAddr,
    pub network: IpNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub destination: String,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub is_up: bool,
    pub hostname: Option<String>,
    pub response_time_ms: Option<u64>,
    pub mac_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkScanner;

impl NetworkScanner {
    pub fn new() -> Self {
        Self
    }

    /// Discover network information using system routes
    pub fn discover_network(&self) -> Result<NetworkInfo> {
        info!("Discovering network configuration...");

        let gateway = self.find_gateway()?;
        let interfaces = self.list_interfaces()?;
        let routes = self.list_routes()?;

        let network_info = NetworkInfo {
            gateway,
            interfaces,
            routes,
        };

        info!("Network discovery complete");
        Ok(network_info)
    }

    /// Find the default gateway using ip route
    fn find_gateway(&self) -> Result<Option<IpAddr>> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .context("Failed to execute 'ip route' command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("ip route output: {}", stdout);

        // Parse output like: "default via 192.168.1.1 dev eth0"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                if let Ok(ip) = parts[2].parse::<IpAddr>() {
                    info!("Found default gateway: {}", ip);
                    return Ok(Some(ip));
                }
            }
        }

        warn!("No default gateway found");
        Ok(None)
    }

    /// List network interfaces with their IPs and networks
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let output = Command::new("ip")
            .args(["-o", "-f", "inet", "addr", "show"])
            .output()
            .context("Failed to execute 'ip addr' command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();

        // Parse output like: "2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let name = parts[1].trim_end_matches(':').to_string();
                
                // Parse CIDR notation (e.g., "192.168.1.100/24")
                if let Ok(network) = parts[3].parse::<IpNetwork>() {
                    let ip = network.ip();
                    let netmask = Self::prefix_to_netmask(network.prefix());
                    
                    interfaces.push(InterfaceInfo {
                        name,
                        ip,
                        netmask,
                        network,
                    });
                }
            }
        }

        info!("Found {} interfaces", interfaces.len());
        Ok(interfaces)
    }

    /// List routing table entries
    fn list_routes(&self) -> Result<Vec<RouteInfo>> {
        let output = Command::new("ip")
            .args(["route", "show"])
            .output()
            .context("Failed to execute 'ip route' command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut routes = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let destination = parts[0].to_string();
                let mut gateway = None;
                let mut interface = String::new();
                let mut flags = String::new();

                for (i, part) in parts.iter().enumerate() {
                    match *part {
                        "via" => {
                            if i + 1 < parts.len() {
                                gateway = parts[i + 1].parse::<IpAddr>().ok();
                            }
                        }
                        "dev" => {
                            if i + 1 < parts.len() {
                                interface = parts[i + 1].to_string();
                            }
                        }
                        _ => {
                            if part.starts_with("metric") || part.starts_with("proto") {
                                flags.push_str(&format!("{} ", part));
                            }
                        }
                    }
                }

                routes.push(RouteInfo {
                    destination,
                    gateway,
                    interface,
                    flags: flags.trim().to_string(),
                });
            }
        }

        Ok(routes)
    }

    /// Convert prefix length to netmask
    fn prefix_to_netmask(prefix: u8) -> IpAddr {
        let mask = match prefix {
            0 => 0u32,
            n => u32::MAX << (32 - n),
        };
        IpAddr::V4(Ipv4Addr::from(mask.to_be()))
    }

    /// Scan a network range for active hosts
    pub async fn scan_network(&self, network: &IpNetwork) -> Result<Vec<HostResult>> {
        info!("Scanning network: {}", network);
        
        let mut results = Vec::new();
        let hosts: Vec<IpAddr> = network.iter().collect();
        
        // Limit scan to reasonable number of hosts
        let hosts_to_scan = if hosts.len() > 254 {
            warn!("Network too large, limiting scan to first 254 hosts");
            hosts.into_iter().take(254).collect()
        } else {
            hosts
        };

        // Scan hosts concurrently
        let mut tasks = Vec::new();
        for host in hosts_to_scan {
            let task = tokio::spawn(async move {
                match Self::ping_host(host).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        debug!("Failed to ping {}: {}", host, e);
                        None
                    }
                }
            });
            tasks.push(task);
        }

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                if result.is_up {
                    info!("Host found: {} ({}ms)", result.ip, 
                        result.response_time_ms.map(|t| t.to_string()).unwrap_or_else(|| "N/A".to_string()));
                    results.push(result);
                }
            }
        }

        info!("Scan complete. Found {} active hosts", results.len());
        Ok(results)
    }

    /// Ping a single host using TCP connect (works without root)
    async fn ping_host(ip: IpAddr) -> Result<HostResult> {
        let start = Instant::now();
        
        // Try TCP connection to common ports (works without root)
        let common_ports = [80, 443, 22, 8080, 3000, 8000, 9000];
        let mut is_up = false;
        
        for port in &common_ports {
            if let Ok(Ok(_)) = timeout(
                Duration::from_millis(500),
                tokio::net::TcpStream::connect((ip, *port))
            ).await {
                is_up = true;
                break;
            }
        }

        let response_time = if is_up {
            Some(start.elapsed().as_millis() as u64)
        } else {
            None
        };

        // Try to resolve hostname
        let hostname = Self::resolve_hostname(ip).await.ok();

        Ok(HostResult {
            ip,
            is_up,
            hostname,
            response_time_ms: response_time,
            mac_address: None,
        })
    }

    /// Resolve hostname for an IP address
    async fn resolve_hostname(ip: IpAddr) -> Result<String> {
        let output = Command::new("host")
            .arg(ip.to_string())
            .output()
            .context("Failed to execute 'host' command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse output like: "1.2.3.4.in-addr.arpa. domain name pointer example.com."
        if let Some(pos) = stdout.find("domain name pointer") {
            let hostname = stdout[pos + 19..].trim().trim_end_matches('.').to_string();
            return Ok(hostname);
        }

        Err(anyhow::anyhow!("Could not resolve hostname"))
    }

    /// Get MAC address from ARP table
    pub fn get_mac_address(&self, ip: IpAddr) -> Result<Option<String>> {
        let output = Command::new("ip")
            .args(["neigh", "show", &ip.to_string()])
            .output()
            .context("Failed to execute 'ip neigh' command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse output like: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p == "lladdr") {
                if pos + 1 < parts.len() {
                    return Ok(Some(parts[pos + 1].to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Perform a port scan on a specific host
    pub async fn scan_ports(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>> {
        info!("Scanning ports on {}: {:?}", ip, ports);
        
        let mut open_ports = Vec::new();
        
        for &port in ports {
            match timeout(
                Duration::from_millis(1000),
                tokio::net::TcpStream::connect((ip, port))
            ).await {
                Ok(Ok(_)) => {
                    info!("Port {} open on {}", port, ip);
                    open_ports.push(port);
                }
                _ => {
                    debug!("Port {} closed on {}", port, ip);
                }
            }
        }

        Ok(open_ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask() {
        let mask = NetworkScanner::prefix_to_netmask(24);
        assert_eq!(mask, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[tokio::test]
    async fn test_ping_localhost() {
        let result = NetworkScanner::ping_host(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(result.is_ok());
        let host = result.unwrap();
        assert!(host.is_up);
    }
}
