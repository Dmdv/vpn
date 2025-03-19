use crate::config::Config;
use crate::dns::DnsManager;
use crate::routing::RouteManager;
use crate::traffic::{TrafficManager, TrafficClass};
use crate::tunnel::TunnelManager;
use crate::crypto::CryptoManager;
use crate::auth::AuthManager;
use crate::metrics::MetricsManager;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use axum::{
    routing::{get, post},
    Router,
    extract::{State, Json},
    response::IntoResponse,
    http::StatusCode,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::net::IpAddr;
use parking_lot::RwLock as PlRwLock;
use dashmap::DashMap;

#[derive(Clone)]
pub struct Server {
    config: Config,
    tunnel_manager: Arc<RwLock<TunnelManager>>,
    dns_manager: Arc<DnsManager>,
    route_manager: Arc<RouteManager>,
    traffic_manager: Arc<TrafficManager>,
    crypto_manager: Arc<CryptoManager>,
    auth_manager: Arc<AuthManager>,
    metrics_manager: Arc<MetricsManager>,
    profile_cache: Arc<DashMap<Uuid, ProfileResponse>>,
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        // Initialize DNS manager
        let dns_manager = Arc::new(DnsManager::new(
            vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            vec![
                ("1.1.1.1".to_string(), 853),
                ("8.8.8.8".to_string(), 853),
            ],
            vec![], // Will be populated with client IPs
        )?);

        // Initialize route manager
        let route_manager = Arc::new(RouteManager::new());

        // Initialize traffic manager with configured bandwidth limit
        let traffic_manager = Arc::new(TrafficManager::new(
            config.bandwidth_limit_mbps.unwrap_or(100) * 1_000_000 // Convert to bps
        ));

        // Initialize tunnel manager with owned config
        let tunnel_manager = Arc::new(RwLock::new(TunnelManager::new(config.clone())?));

        // Initialize crypto manager
        let crypto_manager = Arc::new(CryptoManager::new(config.key_rotation_interval));

        // Initialize auth manager
        let auth_manager = Arc::new(AuthManager::new(
            config.jwt_secret.clone(),
            config.session_timeout as i64,
        ));

        // Initialize metrics manager
        let metrics_manager = Arc::new(MetricsManager::new());

        // Initialize profile cache
        let profile_cache = Arc::new(DashMap::new());

        Ok(Self {
            config,
            tunnel_manager,
            dns_manager,
            route_manager,
            traffic_manager,
            crypto_manager,
            auth_manager,
            metrics_manager,
            profile_cache,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting VPN server...");

        // Start cleanup tasks
        Arc::clone(&self.traffic_manager).start_cleanup_task().await;

        // Add default routing rules
        self.setup_default_routes().await?;

        // Start the server
        self.run_server().await
    }

    async fn setup_default_routes(&self) -> Result<()> {
        use crate::routing::{RouteRule, RouteMatch, RouteAction};

        // Local network direct access
        self.route_manager.add_rule(RouteRule {
            name: "local_network".to_string(),
            match_type: RouteMatch::IpRange {
                network: "192.168.0.0/16".to_string(),
                parsed_network: None,
            },
            action: RouteAction::Direct,
            priority: 100,
            enabled: true,
            temporary: false,
            expires: None,
        }).await?;

        // VPN subnet direct access
        self.route_manager.add_rule(RouteRule {
            name: "vpn_network".to_string(),
            match_type: RouteMatch::IpRange {
                network: self.config.vpn_subnet.clone(),
                parsed_network: None,
            },
            action: RouteAction::Direct,
            priority: 90,
            enabled: true,
            temporary: false,
            expires: None,
        }).await?;

        Ok(())
    }

    async fn run_server(&self) -> Result<()> {
        // Start listening for connections
        let listener = tokio::net::TcpListener::bind((
            &self.config.host,
            self.config.port
        )).await?;

        info!("VPN server listening on {}:{}", self.config.host, self.config.port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let tunnel_manager = Arc::clone(&self.tunnel_manager);
                    let dns_manager = Arc::clone(&self.dns_manager);
                    let route_manager = Arc::clone(&self.route_manager);
                    let traffic_manager = Arc::clone(&self.traffic_manager);

                    tokio::spawn(async move {
                        match Self::handle_client(
                            stream,
                            addr.ip(),
                            tunnel_manager,
                            dns_manager,
                            route_manager,
                            traffic_manager,
                        ).await
                        {
                            Ok(_) => debug!("Client connection handled successfully: {}", addr),
                            Err(e) => error!("Error handling client connection {}: {}", addr, e),
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        stream: tokio::net::TcpStream,
        client_ip: IpAddr,
        tunnel_manager: Arc<RwLock<TunnelManager>>,
        dns_manager: Arc<DnsManager>,
        route_manager: Arc<RouteManager>,
        traffic_manager: Arc<TrafficManager>,
    ) -> Result<()> {
        // Register client with traffic manager
        traffic_manager.register_client(
            client_ip,
            TrafficClass::Interactive, // Default class, can be changed based on client type
            None, // Use default rate limit
        ).await?;

        // Create tunnel for client
        let mut tunnel = {
            let mut tm = tunnel_manager.write().await;
            tm.create_tunnel(stream, client_ip).await?
        };

        // Main packet processing loop
        loop {
            // Read packet from tunnel
            let packet = match tunnel.read_packet().await {
                Ok(Some(packet)) => packet,
                Ok(None) => break, // Connection closed
                Err(e) => {
                    error!("Error reading packet: {}", e);
                    break;
                }
            };

            // Check if we can send (rate limiting)
            if !traffic_manager.can_send(&client_ip, packet.len() as u64).await? {
                warn!("Rate limit exceeded for client: {}", client_ip);
                continue;
            }

            // Get routing action
            let action = route_manager.get_route_action(&packet).await?;

            match action {
                RouteAction::Vpn => {
                    // Apply traffic shaping
                    let delay = traffic_manager.shape_packet(&client_ip, &packet).await?;
                    if delay.as_micros() > 0 {
                        tokio::time::sleep(delay).await;
                    }

                    // Forward packet
                    if let Err(e) = tunnel.write_packet(&packet).await {
                        error!("Error writing packet: {}", e);
                        break;
                    }

                    // Record traffic
                    traffic_manager.record_traffic(&client_ip, packet.len() as u64, 0).await?;
                }
                RouteAction::Direct => {
                    // Handle DNS queries
                    if Self::is_dns_packet(&packet) {
                        match dns_manager.resolve(&packet).await {
                            Ok(response) => {
                                if let Err(e) = tunnel.write_packet(&response).await {
                                    error!("Error writing DNS response: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("DNS resolution error: {}", e);
                            }
                        }
                    }
                    // Other direct traffic is handled by the OS routing table
                }
                RouteAction::Block => {
                    debug!("Blocked packet from {}", client_ip);
                }
            }
        }

        // Cleanup
        traffic_manager.unregister_client(&client_ip).await?;
        let mut tm = tunnel_manager.write().await;
        tm.remove_tunnel(&client_ip).await?;

        Ok(())
    }

    fn is_dns_packet(packet: &[u8]) -> bool {
        if packet.len() < 20 {
            return false;
        }

        // Check if it's UDP
        if packet[9] != 17 {
            return false;
        }

        // Get destination port (assuming IPv4)
        let dest_port = u16::from_be_bytes([packet[22], packet[23]]);
        dest_port == 53
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    tunnel_manager: Arc<RwLock<TunnelManager>>,
    crypto_manager: Arc<CryptoManager>,
    auth_manager: Arc<AuthManager>,
    metrics_manager: Arc<MetricsManager>,
    profile_cache: Arc<DashMap<Uuid, ProfileResponse>>,
}

async fn health_check() -> &'static str {
    "OK"
}

#[derive(Debug, Deserialize)]
struct ProfileRequest {
    device_name: String,
    #[serde(default)]
    preferred_protocol: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct ProfileResponse {
    profile_id: String,
    config: FoxRayConfig,
}

#[derive(Debug, Serialize, Clone)]
struct FoxRayConfig {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    encryption: String,
    protocol: String,
    network: String,
    dns: Vec<String>,
    mtu: u16,
    routes: Vec<String>,
}

async fn generate_profile(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProfileRequest>,
) -> impl IntoResponse {
    let profile_id = Uuid::new_v4();
    
    // Minimize time spent in write lock
    let client_ip = {
        let tunnel_manager = state.tunnel_manager.write().await;
        tunnel_manager.add_client(profile_id).await
    };

    let client_ip = match client_ip {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to add client: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to create client"
            }))).into_response();
        }
    };

    // Create config without holding the lock
    let config = FoxRayConfig {
        name: request.device_name,
        server: state.config.host.clone(),
        port: state.config.port,
        uuid: profile_id.to_string(),
        encryption: "aes-256-gcm".to_string(),
        protocol: request.preferred_protocol.unwrap_or_else(|| "tcp".to_string()),
        network: state.config.get_subnet_network().unwrap().to_string(),
        dns: state.config.dns_servers.clone(),
        mtu: state.config.mtu,
        routes: vec!["0.0.0.0/0".to_string()],
    };

    let response = ProfileResponse {
        profile_id: profile_id.to_string(),
        config,
    };

    // Cache the profile
    state.profile_cache.insert(profile_id, response.clone());

    (StatusCode::OK, Json(response)).into_response()
}

async fn allocate_client_ip(state: &Arc<AppState>) -> IpAddr {
    // Get the VPN subnet
    let network = state.config.get_subnet_network().unwrap();
    let mut ip_iter = network.iter();
    
    // Skip the first IP (network address) and the second IP (server address)
    ip_iter.next();
    ip_iter.next();
    
    // Find the first available IP
    let clients = state.tunnel_manager.read().await.get_clients().await;
    let used_ips: std::collections::HashSet<_> = clients.iter()
        .map(|(_, client)| client.ip_address)
        .collect();
    
    for ip in ip_iter {
        if !used_ips.contains(&ip) {
            return IpAddr::V4(ip);
        }
    }
    
    panic!("No available IP addresses in the subnet");
}

async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let metrics = state.metrics_manager.get_server_metrics().await;
    Json(serde_json::json!({
        "server_metrics": metrics
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn create_test_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            api_port: 8081,
            subnet: "10.8.0.0/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1500,
            encryption_method: "aes-256-gcm".to_string(),
            key_rotation_interval: 24,
            jwt_secret: "test-secret".to_string(),
            session_timeout: 1440,
            max_clients: 100,
            log_level: "debug".to_string(),
            enable_traffic_logging: true,
            bandwidth_limit_mbps: Some(100),
            vpc_network: "10.10.0.0/16".to_string(),
            vpn_subnet: "10.10.1.0/24".to_string(),
            server_vpn_ip: "10.10.1.1".to_string(),
            client_ip_start: "10.10.1.2".to_string(),
            client_ip_end: "10.10.1.254".to_string(),
            camouflage: crate::config::CamouflageConfig {
                enabled: false,
                type_: "websocket".to_string(),
                host: "example.com".to_string(),
                path: "/ws".to_string(),
                fake_server: Some("nginx/1.20.1".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn test_server_initialization() -> Result<()> {
        let config = create_test_config();
        let server = Server::new(config)?;

        // Test route manager initialization
        let route_manager = Arc::clone(&server.route_manager);
        let test_packet = create_test_packet("192.168.1.100");
        let action = route_manager.get_route_action(&test_packet).await?;
        assert_eq!(action, RouteAction::Direct);

        // Test traffic manager initialization
        let traffic_manager = Arc::clone(&server.traffic_manager);
        let client_ip = "192.168.1.100".parse()?;
        traffic_manager.register_client(client_ip, TrafficClass::RealTime, None).await?;
        assert!(traffic_manager.can_send(&client_ip, 1000).await?);

        Ok(())
    }

    fn create_test_packet(ip: &str) -> Vec<u8> {
        let mut packet = vec![0x45u8]; // IPv4, IHL=5
        packet.extend_from_slice(&[0; 15]); // Padding
        let ip_parts: Vec<u8> = ip.split('.')
            .map(|p| p.parse().unwrap())
            .collect();
        packet.extend_from_slice(&ip_parts);
        packet
    }
} 