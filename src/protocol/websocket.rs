use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use crate::protocol::error::{ProtocolError, ProtocolResult};
use crate::protocol::pool::{ConnectionPool, PoolConfig};
use crate::protocol::tls::TlsManager;
use crate::protocol::metrics::ProtocolMetrics;
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    connect_async,
    WebSocketStream,
    MaybeTlsStream,
    tungstenite::protocol::Message,
};
use futures_util::{SinkExt, StreamExt};
use std::net::TcpStream;
use http::{Request, Uri};
use std::time::Duration;
use std::sync::Arc;
use compression::{prelude::*, Compressor, Decompressor};
use rand::{thread_rng, Rng};

pub struct WebSocketProtocol {
    config: ProtocolConfig,
    pool: Arc<ConnectionPool<WebSocketTunnel>>,
    tls_manager: Arc<TlsManager>,
    metrics: Arc<ProtocolMetrics>,
}

impl WebSocketProtocol {
    pub fn new(config: ProtocolConfig, tls_manager: Arc<TlsManager>) -> Self {
        let pool_config = PoolConfig {
            max_size: 32,
            min_idle: 4,
            max_lifetime: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(10),
        };

        Self {
            config: config.clone(),
            pool: Arc::new(ConnectionPool::new(pool_config)),
            tls_manager,
            metrics: Arc::new(ProtocolMetrics::new("websocket")),
        }
    }

    fn build_request(&self) -> ProtocolResult<Request<()>> {
        let path = self.config.path.as_deref().unwrap_or("/ws");
        let uri = format!("wss://{}:{}{}", self.config.host, self.config.port, path)
            .parse::<Uri>()
            .map_err(|e| ProtocolError::ConfigError(format!("Invalid URI: {}", e)))?;

        let mut request = Request::builder()
            .uri(uri)
            .header("Host", &self.config.host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13");

        // Add random WebSocket key
        let mut rng = thread_rng();
        let ws_key: [u8; 16] = rng.gen();
        let ws_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ws_key);
        request = request.header("Sec-WebSocket-Key", ws_key);

        // Add custom headers for better camouflage
        request = request
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache");

        // Add custom headers if specified
        if let Some(headers) = &self.config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        Ok(request.body(())?)
    }

    fn add_random_padding(data: &[u8]) -> Vec<u8> {
        let mut rng = thread_rng();
        let padding_len = rng.gen_range(16..64);
        let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
        
        let mut result = Vec::with_capacity(data.len() + padding_len + 8);
        result.extend_from_slice(&(data.len() as u32).to_be_bytes());
        result.extend_from_slice(&(padding_len as u32).to_be_bytes());
        result.extend_from_slice(&padding);
        result.extend_from_slice(data);
        
        result
    }

    fn remove_padding(data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if data.len() < 8 {
            return Err(ProtocolError::ObfuscationError("Data too short".to_string()));
        }

        let data_len = u32::from_be_bytes(data[0..4].try_into()?)
            .try_into()
            .map_err(|_| ProtocolError::ObfuscationError("Invalid data length".to_string()))?;
        let padding_len = u32::from_be_bytes(data[4..8].try_into()?)
            .try_into()
            .map_err(|_| ProtocolError::ObfuscationError("Invalid padding length".to_string()))?;

        if data.len() < 8 + padding_len + data_len {
            return Err(ProtocolError::ObfuscationError("Data truncated".to_string()));
        }

        Ok(data[8 + padding_len..8 + padding_len + data_len].to_vec())
    }
}

pub struct WebSocketTunnel {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    compressor: Compressor,
    decompressor: Decompressor,
    metrics: Arc<ProtocolMetrics>,
}

impl WebSocketTunnel {
    fn new(ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>, metrics: Arc<ProtocolMetrics>) -> Self {
        Self {
            ws_stream,
            compressor: Compressor::new(6), // compression level 6
            decompressor: Decompressor::new(),
            metrics,
        }
    }
}

#[async_trait]
impl Protocol for WebSocketProtocol {
    async fn init(&self) -> ProtocolResult<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, stream: T) -> ProtocolResult<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let _latency = self.metrics.start_latency_measurement();

        // Accept WebSocket connection
        let ws_stream = tokio_tungstenite::accept_async(stream).await
            .map_err(|e| ProtocolError::HandshakeFailed(e.to_string()))?;

        self.metrics.record_connection_established();

        Ok(Box::new(WebSocketTunnel::new(ws_stream, self.metrics.clone())))
    }

    async fn connect(&self) -> ProtocolResult<Box<dyn Tunnel>> {
        let _latency = self.metrics.start_latency_measurement();

        // Try to get connection from pool
        if let Ok(tunnel) = self.pool.get(|| async {
            let request = self.build_request()?;
            
            // Connect with timeout
            let (ws_stream, _) = tokio::time::timeout(
                Duration::from_secs(10),
                connect_async(request)
            ).await
                .map_err(|_| ProtocolError::ConnectionTimeout(10))?
                .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

            Ok(WebSocketTunnel::new(ws_stream, self.metrics.clone()))
        }).await {
            self.metrics.record_connection_established();
            return Ok(Box::new(tunnel));
        }

        self.metrics.record_connection_error();
        Err(ProtocolError::ConnectionError("Failed to get connection from pool".to_string()))
    }
}

#[async_trait]
impl Tunnel for WebSocketTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        while let Some(message) = self.ws_stream.next().await {
            match message.map_err(|e| ProtocolError::ConnectionError(e.to_string()))? {
                Message::Binary(data) => {
                    // Remove padding and decompress
                    let unpadded = WebSocketProtocol::remove_padding(&data)?;
                    let decompressed = self.decompressor.decompress(&unpadded)
                        .map_err(|e| ProtocolError::Other(e.into()))?;

                    buf.extend_from_slice(&decompressed);
                    self.metrics.record_bytes_received(data.len() as u64);
                    return Ok(decompressed.len());
                }
                Message::Close(_) => {
                    return Ok(0);
                }
                _ => continue,
            }
        }

        Ok(0)
    }

    async fn write(&mut self, buf: &[u8]) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        // Compress and add padding
        let compressed = self.compressor.compress(buf)
            .map_err(|e| ProtocolError::Other(e.into()))?;
        let padded = WebSocketProtocol::add_random_padding(&compressed);

        // Send as binary message
        self.ws_stream.send(Message::Binary(padded.clone())).await
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

        self.metrics.record_bytes_sent(padded.len() as u64);
        Ok(buf.len())
    }

    async fn close(&mut self) -> ProtocolResult<()> {
        self.metrics.record_connection_closed();
        self.ws_stream.close(None).await
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::net::Ipv4Addr;
    use crate::protocol::tls::TlsConfig;

    #[tokio::test]
    async fn test_websocket_protocol() -> ProtocolResult<()> {
        // Create TLS manager for testing
        let tls_config = TlsConfig {
            cert_path: "test/cert.pem".to_string(),
            key_path: "test/key.pem".to_string(),
            pinned_certs: vec![],
            verify_hostname: false,
        };
        let tls_manager = Arc::new(TlsManager::new(tls_config)?);

        // Create test config
        let config = ProtocolConfig {
            name: "websocket".to_string(),
            host: "127.0.0.1".to_string(),
            port: 0,
            path: Some("/ws".to_string()),
            headers: None,
            keepalive: 60,
        };

        // Create protocol instance
        let protocol = WebSocketProtocol::new(config.clone(), tls_manager.clone());

        // Start test server
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        // Update config with actual port
        let mut client_config = config;
        client_config.port = addr.port();

        // Client connection task
        let client_task = tokio::spawn(async move {
            let protocol = WebSocketProtocol::new(client_config, tls_manager);
            protocol.connect().await
        });

        // Accept server connection
        let (server_stream, _) = listener.accept().await?;
        let mut server_tunnel = protocol.handle_connection(server_stream).await?;

        // Get client tunnel
        let mut client_tunnel = client_task.await??;

        // Test data transfer
        let test_data = b"Hello, World!";
        let mut recv_buf = BytesMut::with_capacity(test_data.len());

        // Client -> Server
        client_tunnel.write(test_data).await?;
        let n = server_tunnel.read(&mut recv_buf).await?;
        assert_eq!(n, test_data.len());
        assert_eq!(&recv_buf[..], test_data);

        Ok(())
    }
} 