# Rust VPN Server

A high-performance VPN server written in Rust, designed to run on Digital Ocean with FoxRay client support.

## Features

- High-performance packet processing with async Rust
- FoxRay client compatibility
- Automatic IP allocation and management
- Traffic metrics and monitoring
- JWT-based authentication
- Configurable encryption (AES-256-GCM)
- Automatic key rotation
- Rate limiting support

## Advanced Traffic Features

### Traffic Obfuscation

1. **Shadowsocks Integration**
```rust
// In config.json
{
  "shadowsocks": {
    "enabled": true,
    "method": "chacha20-ietf-poly1305",
    "password": "your-secure-password"
  }
}
```

2. **Traffic Camouflage**
- HTTP Header Simulation
- TLS Traffic Mimicry
- WebSocket Wrapping
```rust
// In config.json
{
  "camouflage": {
    "type": "websocket",  // or "http" or "tls"
    "host": "www.example.com",
    "path": "/ws"
  }
}
```

3. **Protocol Transformations**
- V2Ray Plugin Support
- OBFS4 Integration
- SNI Spoofing
```rust
// In config.json
{
  "protocol_transform": {
    "type": "v2ray",
    "settings": {
      "host": "www.microsoft.com",
      "path": "/update"
    }
  }
}
```

### Traffic Optimization

1. **Compression**
- LZ4 Fast Compression
- ZSTD Advanced Compression
```rust
// In config.json
{
  "compression": {
    "enabled": true,
    "algorithm": "lz4",  // or "zstd"
    "level": 3  // 1-9, higher = better compression but more CPU
  }
}
```

2. **TCP Optimization**
- BBR Congestion Control
- TCP Fast Open
- Custom TCP Parameters
```rust
// In config.json
{
  "tcp_optimization": {
    "bbr_enabled": true,
    "fast_open": true,
    "keepalive_interval": 25,
    "mss_clamp": 1460
  }
}
```

3. **Multi-Path TCP**
- Load Balancing
- Connection Redundancy
```rust
// In config.json
{
  "mptcp": {
    "enabled": true,
    "interfaces": ["eth0", "wlan0"],
    "scheduler": "redundant"  // or "default", "roundrobin"
  }
}
```

### Traffic Analysis Prevention

1. **Packet Size Normalization**
- Fixed Packet Sizes
- Random Padding
```rust
// In config.json
{
  "packet_normalization": {
    "enabled": true,
    "size": 1400,  // or "random"
    "padding_range": [100, 200]  // for random mode
  }
}
```

2. **Timing Obfuscation**
- Random Delays
- Traffic Pattern Masking
```rust
// In config.json
{
  "timing_obfuscation": {
    "enabled": true,
    "delay_range_ms": [10, 50],
    "burst_mode": true
  }
}
```

3. **Split Routing**
- Per-App Routing
- Domain-Based Routing
```rust
// In config.json
{
  "split_routing": {
    "enabled": true,
    "rules": [
      {"type": "app", "name": "browser", "action": "proxy"},
      {"type": "domain", "pattern": "*.google.com", "action": "direct"}
    ]
  }
}
```

### Anti-Censorship Features

1. **Domain Fronting**
- CDN-based Fronting
- Custom Domain Support
```rust
// In config.json
{
  "domain_fronting": {
    "enabled": true,
    "provider": "cloudfront",
    "front_domain": "d1234.cloudfront.net",
    "real_domain": "your-vpn.com"
  }
}
```

2. **Bridge Mode**
- Meek Bridge Support
- Snowflake Integration
```rust
// In config.json
{
  "bridges": {
    "type": "meek",  // or "snowflake"
    "settings": {
      "url": "https://your-bridge.com",
      "front": "ajax.aspnetcdn.com"
    }
  }
}
```

3. **Active Probing Resistance**
- Protocol Verification
- Handshake Obfuscation
```rust
// In config.json
{
  "probe_resistance": {
    "enabled": true,
    "knocker_password": "secret-knock",
    "fake_response": "HTTP/1.1 404 Not Found"
  }
}
```

### Implementation Notes

1. **Enabling Features**:
```bash
# Install additional dependencies
apt install -y \
  shadowsocks-libev \
  v2ray-plugin \
  obfs4proxy \
  zstd \
  liblz4-tool
```

2. **Performance Impact**:
- Obfuscation features may increase latency
- Compression can help with slow connections
- Monitor CPU usage when enabling multiple features

3. **Security Considerations**:
- Some features may weaken security if misconfigured
- Regular auditing of enabled features
- Keep all components updated

4. **Compatibility**:
- Not all features work with all clients
- Test thoroughly before deployment
- Document supported features for users

## Digital Ocean Setup

### 1. Create VPC Network

First, create a VPC network for your VPN server:

```bash
doctl vpcs create \
  --name vpn-network \
  --ip-range 10.10.0.0/16 \
  --region nyc1
```

Save the VPC UUID from the output.

### 2. Create Droplet

Create a Droplet in the VPC network:

```bash
doctl compute droplet create vpn-server \
  --vpc-uuid your-vpc-uuid \
  --image ubuntu-22-04-x64 \
  --size s-1vcpu-2gb \
  --region nyc1 \
  --ssh-keys your-ssh-key-id
```

### 3. Configure Firewall

Create a firewall for the VPN server:

```bash
doctl compute firewall create \
  --name vpn-firewall \
  --droplet-ids your-droplet-id \
  --inbound-rules "protocol:tcp,ports:1194,address:0.0.0.0/0 protocol:tcp,ports:8080,address:0.0.0.0/0" \
  --outbound-rules "protocol:icmp,address:0.0.0.0/0 protocol:tcp,ports:all,address:0.0.0.0/0 protocol:udp,ports:all,address:0.0.0.0/0"
```

### 4. Network Configuration

The VPN server uses the following IP ranges by default:
- VPC Network: `10.10.0.0/16`
- VPN Subnet: `10.10.1.0/24`
- Server VPN IP: `10.10.1.1`
- Client IP Range: `10.10.1.2` - `10.10.1.254`

You can modify these in `config.rs` if needed.

## Installation

1. SSH into your Droplet:
```bash
ssh root@your-droplet-ip
```

2. Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

3. Install dependencies:
```bash
apt update
apt install -y build-essential pkg-config libssl-dev
```

4. Clone and build:
```bash
git clone https://github.com/yourusername/vpn-server
cd vpn-server
cargo build --release
```

## Configuration

Create a configuration file at `config.json`:

```json
{
  "host": "0.0.0.0",
  "port": 1194,
  "api_port": 8080,
  "subnet": "10.8.0.0/24",
  "dns_servers": ["1.1.1.1", "8.8.8.8"],
  "mtu": 1500,
  "encryption_method": "aes-256-gcm",
  "key_rotation_interval": 24,
  "jwt_secret": "your-secret-key",
  "session_timeout": 1440,
  "max_clients": 100,
  "log_level": "info",
  "enable_traffic_logging": false,
  "vpc_network": "10.10.0.0/16",
  "vpn_subnet": "10.10.1.0/24",
  "server_vpn_ip": "10.10.1.1",
  "client_ip_start": "10.10.1.2",
  "client_ip_end": "10.10.1.254"
}
```

## Running

Start the server with root privileges (required for TUN device):

```bash
sudo ./target/release/vpn-server
```

For production, create a systemd service:

```bash
sudo nano /etc/systemd/system/vpn-server.service
```

Add:
```ini
[Unit]
Description=VPN Server
After=network.target

[Service]
ExecStart=/path/to/vpn-server
Restart=always
User=root
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable vpn-server
sudo systemctl start vpn-server
```

## Client Setup

1. Generate a client profile:
```bash
curl -X POST http://your-server:8080/profile/generate \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "my-device",
    "preferred_protocol": "tcp"
  }'
```

2. Use the generated profile in your FoxRay client.

## Monitoring

Check server status:
```bash
curl http://your-server:8080/status
```

View connected clients:
```bash
curl http://your-server:8080/clients
```

## Security Notes

1. Always change default JWT secret
2. Use strong passwords for client profiles
3. Regularly update the server
4. Monitor logs for suspicious activity
5. Consider enabling traffic logging in production

## Alternative Cloud Providers

While this guide focuses on Digital Ocean, the VPN server can be deployed on any cloud provider. Here are some popular alternatives:

### Linode/Akamai Cloud

Similar setup to Digital Ocean with competitive pricing:
```bash
# Install Linode CLI
curl -L https://raw.githubusercontent.com/linode/linode-cli/master/linode-cli.sh | sudo bash

# Create VPC Network equivalent (Linode VLAN)
linode-cli vlans create --label vpn-network --region us-east

# Create Instance
linode-cli linodes create \
  --type g6-standard-1 \
  --region us-east \
  --image linode/ubuntu22.04 \
  --label vpn-server \
  --root_pass "your-root-password"
```

### Vultr

Known for high performance and global presence:
```bash
# Install Vultr CLI
curl -L https://github.com/vultr/vultr-cli/releases/latest/download/vultr-cli_Linux_x86_64.tar.gz | tar xz

# Create Instance
vultr-cli instance create \
  --region ewr \
  --plan vc2-1c-1gb \
  --os 270 \
  --label vpn-server
```

### AWS Lightsail

Amazon's simplified VPS offering:
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Create Instance
aws lightsail create-instances \
  --instance-names vpn-server \
  --availability-zone us-east-1a \
  --blueprint-id ubuntu_22_04 \
  --bundle-id nano_2_0
```

### Oracle Cloud (Free Tier Available)

Offers generous free tier with 2 AMD-based VMs:
- Sign up at cloud.oracle.com
- Create a VM.Standard.A1.Flex instance (24GB RAM, 4 OCPUs free)
- Use the web interface or OCI CLI for setup

### Hetzner Cloud

European provider with excellent price/performance:
```bash
# Install hcloud CLI
wget -O hcloud.tar.gz https://github.com/hetznercloud/cli/releases/latest/download/hcloud-linux-amd64.tar.gz
tar -xf hcloud.tar.gz

# Create Server
hcloud server create \
  --name vpn-server \
  --type cx11 \
  --image ubuntu-22.04 \
  --location nbg1
```

### Network Configuration Notes

For all providers:
1. Ensure your chosen provider allows TUN/TAP devices
2. Check if custom VPC/private networking is supported
3. Configure provider's firewall rules similar to Digital Ocean example
4. Some providers might require additional steps to enable IPv6
5. Consider bandwidth costs and network performance

### Provider Selection Criteria

Choose based on your needs:
- **Cost**: Oracle Cloud (free tier), Hetzner (budget)
- **Performance**: Vultr, Linode (high performance)
- **Global Presence**: AWS Lightsail, Digital Ocean (many regions)
- **Simplicity**: Digital Ocean, Linode (easy setup)
- **Privacy**: Providers outside 14-eyes countries might be preferred

## License

MIT 