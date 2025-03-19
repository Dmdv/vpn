use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ClientMetrics {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub connected_since: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerMetrics {
    pub total_bytes_tx: u64,
    pub total_bytes_rx: u64,
    pub total_packets_tx: u64,
    pub total_packets_rx: u64,
    pub active_connections: usize,
    pub peak_connections: usize,
    pub uptime: chrono::Duration,
    pub start_time: DateTime<Utc>,
}

pub struct MetricsManager {
    client_metrics: Arc<RwLock<HashMap<Uuid, ClientMetrics>>>,
    server_metrics: Arc<RwLock<ServerMetrics>>,
}

impl MetricsManager {
    pub fn new() -> Self {
        let start_time = Utc::now();
        let server_metrics = ServerMetrics {
            total_bytes_tx: 0,
            total_bytes_rx: 0,
            total_packets_tx: 0,
            total_packets_rx: 0,
            active_connections: 0,
            peak_connections: 0,
            uptime: chrono::Duration::zero(),
            start_time,
        };

        MetricsManager {
            client_metrics: Arc::new(RwLock::new(HashMap::new())),
            server_metrics: Arc::new(RwLock::new(server_metrics)),
        }
    }

    pub async fn register_client(&self, client_id: Uuid) {
        let now = Utc::now();
        let client_metrics = ClientMetrics {
            bytes_tx: 0,
            bytes_rx: 0,
            packets_tx: 0,
            packets_rx: 0,
            connected_since: now,
            last_seen: now,
        };

        let mut clients = self.client_metrics.write().await;
        clients.insert(client_id, client_metrics);

        let mut server = self.server_metrics.write().await;
        server.active_connections += 1;
        server.peak_connections = server.peak_connections.max(server.active_connections);
    }

    pub async fn unregister_client(&self, client_id: &Uuid) {
        let mut clients = self.client_metrics.write().await;
        clients.remove(client_id);

        let mut server = self.server_metrics.write().await;
        server.active_connections = server.active_connections.saturating_sub(1);
    }

    pub async fn update_client_traffic(&self, client_id: &Uuid, bytes_tx: u64, bytes_rx: u64) {
        let mut clients = self.client_metrics.write().await;
        if let Some(metrics) = clients.get_mut(client_id) {
            metrics.bytes_tx += bytes_tx;
            metrics.bytes_rx += bytes_rx;
            metrics.packets_tx += 1;
            metrics.packets_rx += 1;
            metrics.last_seen = Utc::now();
        }

        let mut server = self.server_metrics.write().await;
        server.total_bytes_tx += bytes_tx;
        server.total_bytes_rx += bytes_rx;
        server.total_packets_tx += 1;
        server.total_packets_rx += 1;
        server.uptime = Utc::now() - server.start_time;
    }

    pub async fn get_client_metrics(&self, client_id: &Uuid) -> Option<ClientMetrics> {
        let clients = self.client_metrics.read().await;
        clients.get(client_id).cloned()
    }

    pub async fn get_server_metrics(&self) -> ServerMetrics {
        let server = self.server_metrics.read().await;
        server.clone()
    }

    pub async fn get_all_client_metrics(&self) -> HashMap<Uuid, ClientMetrics> {
        let clients = self.client_metrics.read().await;
        clients.clone()
    }
} 