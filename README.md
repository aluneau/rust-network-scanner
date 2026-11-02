# rust-network-scanner

A Rust-based network scanner that discovers the gateway, network configuration, and scans for active hosts using TCP connections.

## Features

- **Gateway Discovery**: Automatically finds the default gateway using system routes
- **Network Interface Detection**: Lists all network interfaces with their IPs and subnets
- **Host Discovery**: Scans networks for active hosts using TCP connection attempts
- **Port Scanning**: Optional port scanning on discovered hosts
- **JSON Output**: Supports both text and JSON output formats
- **Kubernetes Ready**: Designed to run in containerized environments

## Installation

```bash
# Clone the repository
git clone https://github.com/aluneau/rust-network-scanner.git
cd rust-network-scanner

# Build the project
cargo build --release

# The binary will be at target/release/network-scanner
```

## Usage

```bash
# Basic scan - discovers network and scans all interfaces
./network-scanner

# Scan a specific network
./network-scanner --network 192.168.1.0/24

# Scan with port detection
./network-scanner --ports

# Custom port list
./network-scanner --ports --port-list 22,80,443,8080,3000

# JSON output
./network-scanner --format json

# Verbose output
./network-scanner --verbose
```

## Running in Kubernetes

The scanner is designed to work in Kubernetes environments. When running in a pod:

1. It will detect the pod's network interfaces
2. Scan the local network for active hosts
3. Works without requiring privileged access (uses TCP connections instead of ICMP)

### Example Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: network-scanner
spec:
  template:
    spec:
      containers:
      - name: scanner
        image: your-registry/rust-network-scanner:latest
        command: ["./network-scanner"]
        args: ["--format", "json"]
      restartPolicy: Never
```

## How It Works

1. **Network Discovery**: Uses the `ip route` and `ip addr` commands to discover:
   - Default gateway
   - Network interfaces
   - Routing table

2. **Host Scanning**: For each IP in the network range:
   - Attempts TCP connections to common ports (80, 443, 22, 8080, etc.)
   - Reports hosts that respond as "up"
   - Measures response time

3. **Port Scanning** (optional): When enabled, scans specified ports on discovered hosts

## License

MIT
