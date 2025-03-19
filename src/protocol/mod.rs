use async_trait::async_trait;
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;

pub mod tcp;
pub mod websocket;
pub mod http;

#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub name: String,
    pub host: String,
    pub path: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub keepalive: u64,
}

#[async_trait]
pub trait Protocol: Send + Sync {
    /// Initialize the protocol
    async fn init(&self) -> Result<()>;

    /// Handle incoming connection
    async fn handle_connection<T>(&self, stream: T) -> Result<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// Create outbound connection
    async fn connect(&self) -> Result<Box<dyn Tunnel>>;
}

#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Read data from tunnel
    async fn read(&mut self, buf: &mut BytesMut) -> Result<usize>;

    /// Write data to tunnel
    async fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Close the tunnel
    async fn close(&mut self) -> Result<()>;
}

pub fn create_protocol(config: ProtocolConfig) -> Arc<dyn Protocol> {
    match config.name.as_str() {
        "tcp" => Arc::new(tcp::TcpProtocol::new(config)),
        "ws" => Arc::new(websocket::WebSocketProtocol::new(config)),
        "http" => Arc::new(http::HttpProtocol::new(config)),
        _ => panic!("Unsupported protocol: {}", config.name),
    }
} 