use crate::config::Config;
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};
use uuid::Uuid;
use tokio_tun::Tun;
use futures::StreamExt;
use bytes::{Buf, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::camouflage::WebSocketCamouflage;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug)]
struct IpHeader {
    version: u8,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    length: u16,
}

pub struct TunnelManager {
    config: Config,
    clients: Arc<Mutex<HashMap<Uuid, ClientInfo>>>,
    tun_device: Arc<Tun>,
    camouflage: Option<WebSocketCamouflage>,
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub id: Uuid,
    pub ip_address: IpAddr,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

impl TunnelManager {
    pub fn new(config: Config) -> Result<Self> {
        let tun = Tun::builder()
            .name("")  // kernel will assign a name
            .up()      // bring the interface up
            .build()
            .expect("Failed to create TUN device")
            .pop()
            .expect("No TUN device created");

        // Create WebSocket camouflage
        let camouflage = if config.camouflage.enabled {
            let tun_clone = Arc::clone(&Arc::new(tun));
            Some(WebSocketCamouflage::new(
                &config.camouflage.host,
                &config.camouflage.path,
                tun_clone,
            ))
        } else {
            None
        };

        Ok(TunnelManager {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            tun_device: Arc::new(tun),
            camouflage,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting tunnel manager");
        
        // Configure the TUN interface
        self.configure_tun_interface()?;

        // Start packet processing
        self.process_packets().await?;

        Ok(())
    }

    fn configure_tun_interface(&self) -> Result<()> {
        let network = self.config.get_subnet_network()?;
        
        // Set the TUN interface address and netmask
        let addr = network.ip();
        let netmask = network.netmask();
        
        info!("Configuring TUN interface with address: {}/{}", addr, network.prefix());
        
        // On Unix-like systems, we need to run these commands:
        // 1. Set the interface address
        std::process::Command::new("ip")
            .args(&["addr", "add", &format!("{}/{}", addr, network.prefix()), "dev", &self.tun_device.name()])
            .status()?;
            
        // 2. Set up NAT (assuming eth0 is the outgoing interface)
        std::process::Command::new("iptables")
            .args(&["-t", "nat", "-A", "POSTROUTING", "-s", &network.to_string(), "-o", "eth0", "-j", "MASQUERADE"])
            .status()?;
            
        // 3. Enable IP forwarding
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

        Ok(())
    }

    async fn process_packets(&mut self) -> Result<()> {
        let mut buf = vec![0u8; self.config.mtu as usize];
        
        loop {
            match self.tun_device.recv(&mut buf).await {
                Ok(n) => {
                    // Process the packet
                    self.handle_packet(&buf[..n]).await?;
                }
                Err(e) => {
                    warn!("Error reading from TUN device: {}", e);
                }
            }
        }
    }

    async fn handle_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        // Parse IP header
        let header = match self.parse_ip_header(packet)? {
            Some(h) => h,
            None => return Ok(()),
        };

        // Find the client based on destination IP
        let mut clients = self.clients.lock().await;
        let client = clients.values_mut().find(|c| c.ip_address == header.destination);

        match client {
            Some(client) => {
                // Update client metrics
                client.last_seen = chrono::Utc::now();
                client.bytes_rx += packet.len() as u64;

                // If camouflage is enabled, wrap packet in WebSocket
                if let Some(camouflage) = &self.camouflage {
                    camouflage.send_packet(packet).await?;
                } else {
                    // Forward the packet directly
                    if let Err(e) = self.tun_device.send(packet).await {
                        error!("Failed to forward packet to client {}: {}", client.id, e);
                    }
                }
            }
            None => {
                warn!("Received packet for unknown client IP: {}", header.destination);
            }
        }

        Ok(())
    }

    fn parse_ip_header(&self, packet: &[u8]) -> Result<Option<IpHeader>> {
        if packet.is_empty() {
            return Ok(None);
        }

        let version = (packet[0] >> 4) & 0xF;
        
        match version {
            4 => {
                if packet.len() < IPV4_HEADER_LEN {
                    warn!("Packet too short for IPv4 header");
                    return Ok(None);
                }

                let source = Ipv4Addr::new(
                    packet[12],
                    packet[13],
                    packet[14],
                    packet[15],
                );
                let destination = Ipv4Addr::new(
                    packet[16],
                    packet[17],
                    packet[18],
                    packet[19],
                );

                Ok(Some(IpHeader {
                    version,
                    source: IpAddr::V4(source),
                    destination: IpAddr::V4(destination),
                    protocol: packet[9],
                    length: u16::from_be_bytes([packet[2], packet[3]]),
                }))
            }
            6 => {
                if packet.len() < IPV6_HEADER_LEN {
                    warn!("Packet too short for IPv6 header");
                    return Ok(None);
                }

                let mut source_bytes = [0u8; 16];
                let mut dest_bytes = [0u8; 16];
                source_bytes.copy_from_slice(&packet[8..24]);
                dest_bytes.copy_from_slice(&packet[24..40]);

                Ok(Some(IpHeader {
                    version,
                    source: IpAddr::V6(Ipv6Addr::from(source_bytes)),
                    destination: IpAddr::V6(Ipv6Addr::from(dest_bytes)),
                    protocol: packet[6],
                    length: u16::from_be_bytes([packet[4], packet[5]]),
                }))
            }
            _ => {
                warn!("Unsupported IP version: {}", version);
                Ok(None)
            }
        }
    }

    async fn allocate_client_ip(&self) -> Result<IpAddr> {
        let mut clients = self.clients.lock().await;
        let (start_ip, end_ip) = self.config.get_client_ip_range()?;
        
        // Convert start and end IPs to u32 for easier iteration
        let start = u32::from(start_ip);
        let end = u32::from(end_ip);
        
        // Find first available IP
        for ip_int in start..=end {
            let ip = Ipv4Addr::from(ip_int);
            let ip_addr = IpAddr::V4(ip);
            
            // Check if IP is already allocated
            if !clients.values().any(|client| client.ip_address == ip_addr) {
                return Ok(ip_addr);
            }
        }
        
        anyhow::bail!("No available IP addresses in the pool")
    }

    pub async fn add_client(&self, client_id: Uuid) -> Result<IpAddr> {
        let ip_address = self.allocate_client_ip().await?;
        
        let mut clients = self.clients.lock().await;
        let client_info = ClientInfo {
            id: client_id,
            ip_address,
            connected_at: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            bytes_tx: 0,
            bytes_rx: 0,
        };

        clients.insert(client_id, client_info);
        info!("New client connected: {} ({})", client_id, ip_address);
        
        Ok(ip_address)
    }

    pub async fn remove_client(&self, client_id: &Uuid) -> Result<()> {
        let mut clients = self.clients.lock().await;
        if clients.remove(client_id).is_some() {
            info!("Client disconnected: {}", client_id);
        }
        Ok(())
    }

    pub async fn get_clients(&self) -> HashMap<Uuid, ClientInfo> {
        self.clients.lock().await.clone()
    }
} 