use async_trait::async_trait;
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;

pub mod tcp;
pub mod websocket;
pub mod http;
pub mod error;
pub mod pool;
pub mod tls;
pub mod metrics;

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub keepalive: u64,
    pub max_connections: usize,
    pub connection_timeout: u64,
    pub read_timeout: u64,
    pub write_timeout: u64,
    pub tls_config: Option<tls::TlsConfig>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            name: "tcp".to_string(),
            host: "127.0.0.1".to_string(),
            port: 0,
            path: None,
            headers: None,
            keepalive: 60,
            max_connections: 1000,
            connection_timeout: 10,
            read_timeout: 30,
            write_timeout: 30,
            tls_config: None,
        }
    }
}

#[async_trait]
pub trait Protocol: Send + Sync {
    /// Initialize the protocol
    async fn init(&self) -> ProtocolResult<()>;

    /// Handle incoming connection
    async fn handle_connection<T>(&self, stream: T) -> ProtocolResult<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// Create outbound connection
    async fn connect(&self) -> ProtocolResult<Box<dyn Tunnel>>;
}

#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Read data from tunnel
    async fn read(&mut self, buf: &mut BytesMut) -> ProtocolResult<usize>;

    /// Write data to tunnel
    async fn write(&mut self, buf: &[u8]) -> ProtocolResult<usize>;

    /// Close the tunnel
    async fn close(&mut self) -> ProtocolResult<()>;
}

pub fn create_protocol(config: ProtocolConfig, tls_manager: Arc<tls::TlsManager>) -> Arc<dyn Protocol> {
    match config.name.as_str() {
        "tcp" => Arc::new(tcp::TcpProtocol::new(config, tls_manager.clone())),
        "ws" => Arc::new(websocket::WebSocketProtocol::new(config, tls_manager.clone())),
        "http" => Arc::new(http::HttpProtocol::new(config, tls_manager)),
        _ => panic!("Unsupported protocol: {}", config.name),
    }
} 