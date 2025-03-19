use crate::config::Config;
use crate::tunnel::TunnelManager;
use crate::crypto::CryptoManager;
use crate::auth::AuthManager;
use crate::metrics::MetricsManager;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
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

pub struct Server {
    config: Config,
    tunnel_manager: Arc<RwLock<TunnelManager>>,
    crypto_manager: Arc<CryptoManager>,
    auth_manager: Arc<AuthManager>,
    metrics_manager: Arc<MetricsManager>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let crypto_manager = Arc::new(CryptoManager::new(config.key_rotation_interval));
        let auth_manager = Arc::new(AuthManager::new(
            config.jwt_secret.clone(),
            config.session_timeout as i64,
        ));
        let metrics_manager = Arc::new(MetricsManager::new());
        let tunnel_manager = Arc::new(RwLock::new(TunnelManager::new(&config)));

        Server {
            config,
            tunnel_manager,
            crypto_manager,
            auth_manager,
            metrics_manager,
        }
    }

    pub async fn run(&self) -> Result<()> {
        info!("Initializing VPN server on {}:{}", self.config.host, self.config.port);

        // Start the tunnel manager
        let tunnel_manager = self.tunnel_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = tunnel_manager.write().await.run().await {
                error!("Tunnel manager error: {}", e);
            }
        });

        // Start key rotation
        let crypto_manager = self.crypto_manager.clone();
        let key_rotation_interval = self.config.key_rotation_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(key_rotation_interval * 3600)).await;
                if let Err(e) = crypto_manager.rotate_key().await {
                    error!("Key rotation error: {}", e);
                }
            }
        });

        // Start the API server
        self.start_api_server().await?;

        Ok(())
    }

    async fn start_api_server(&self) -> Result<()> {
        let app_state = Arc::new(AppState {
            tunnel_manager: self.tunnel_manager.clone(),
            crypto_manager: self.crypto_manager.clone(),
            auth_manager: self.auth_manager.clone(),
            metrics_manager: self.metrics_manager.clone(),
        });

        let app = Router::new()
            .route("/health", get(health_check))
            .route("/profile/generate", post(generate_profile))
            .route("/metrics", get(get_metrics))
            .with_state(app_state);

        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.api_port)
            .parse()
            .unwrap();

        info!("Starting API server on {}", addr);
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    tunnel_manager: Arc<RwLock<TunnelManager>>,
    crypto_manager: Arc<CryptoManager>,
    auth_manager: Arc<AuthManager>,
    metrics_manager: Arc<MetricsManager>,
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

#[derive(Debug, Serialize)]
struct ProfileResponse {
    profile_id: String,
    config: FoxRayConfig,
}

#[derive(Debug, Serialize)]
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
    // Generate a unique ID for this profile
    let profile_id = Uuid::new_v4();
    
    // Create a new client in the tunnel manager
    let client_ip = allocate_client_ip(&state).await;
    
    if let Err(e) = state.tunnel_manager.write().await.add_client(profile_id, client_ip).await {
        error!("Failed to add client: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to create client"
        }))).into_response();
    }

    // Create FoxRay configuration
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
        routes: vec!["0.0.0.0/0".to_string()], // Route all traffic through VPN
    };

    let response = ProfileResponse {
        profile_id: profile_id.to_string(),
        config,
    };

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