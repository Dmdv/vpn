use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use crate::protocol::error::{ProtocolError, ProtocolResult};
use crate::protocol::pool::{ConnectionPool, PoolConfig};
use crate::protocol::tls::TlsManager;
use crate::protocol::metrics::ProtocolMetrics;
use async_trait::async_trait;
use bytes::{BytesMut, BufMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use hyper::{
    Body, Client, Request, Response, StatusCode,
    client::HttpConnector, header::{HeaderMap, HeaderValue},
};
use hyper_rustls::HttpsConnector;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{thread_rng, Rng};
use std::time::Duration;
use std::sync::Arc;
use compression::{prelude::*, Compressor, Decompressor};
use dashmap::DashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct HttpProtocol {
    config: ProtocolConfig,
    pool: Arc<ConnectionPool<HttpTunnel>>,
    tls_manager: Arc<TlsManager>,
    metrics: Arc<ProtocolMetrics>,
    client: Client<HttpsConnector<HttpConnector>>,
    active_sessions: Arc<DashMap<String, mpsc::Sender<Vec<u8>>>>,
}

impl HttpProtocol {
    pub fn new(config: ProtocolConfig, tls_manager: Arc<TlsManager>) -> Self {
        let pool_config = PoolConfig {
            max_size: 32,
            min_idle: 4,
            max_lifetime: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(300),
            connection_timeout: Duration::from_secs(10),
        };

        // Create HTTPS client
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_manager.client_config.clone())
            .https_only()
            .enable_http1()
            .build();

        let client = Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(300)))
            .pool_max_idle_per_host(32)
            .build(https);

        Self {
            config: config.clone(),
            pool: Arc::new(ConnectionPool::new(pool_config)),
            tls_manager,
            metrics: Arc::new(ProtocolMetrics::new("http")),
            client,
            active_sessions: Arc::new(DashMap::new()),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_str(&self.config.host).unwrap());
        
        // Add common browser headers for better camouflage
        headers.insert("User-Agent", HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"));
        headers.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.5"));
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip, deflate"));
        headers.insert("Connection", HeaderValue::from_static("keep-alive"));
        headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));

        // Add custom headers if specified
        if let Some(custom_headers) = &self.config.headers {
            for (key, value) in custom_headers {
                if let Ok(val) = HeaderValue::from_str(value) {
                    headers.insert(key, val);
                }
            }
        }

        headers
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
        
        BASE64.encode(result).into_bytes()
    }

    fn remove_padding(data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let decoded = BASE64.decode(data)
            .map_err(|e| ProtocolError::ObfuscationError(format!("Base64 decode error: {}", e)))?;

        if decoded.len() < 8 {
            return Err(ProtocolError::ObfuscationError("Data too short".to_string()));
        }

        let data_len = u32::from_be_bytes(decoded[0..4].try_into()?)
            .try_into()
            .map_err(|_| ProtocolError::ObfuscationError("Invalid data length".to_string()))?;
        let padding_len = u32::from_be_bytes(decoded[4..8].try_into()?)
            .try_into()
            .map_err(|_| ProtocolError::ObfuscationError("Invalid padding length".to_string()))?;

        if decoded.len() < 8 + padding_len + data_len {
            return Err(ProtocolError::ObfuscationError("Data truncated".to_string()));
        }

        Ok(decoded[8 + padding_len..8 + padding_len + data_len].to_vec())
    }
}

pub struct HttpTunnel {
    session_id: String,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    client: Client<HttpsConnector<HttpConnector>>,
    base_url: String,
    headers: HeaderMap,
    read_buffer: BytesMut,
    compressor: Compressor,
    decompressor: Decompressor,
    metrics: Arc<ProtocolMetrics>,
}

impl HttpTunnel {
    fn new(
        client: Client<HttpsConnector<HttpConnector>>,
        base_url: String,
        headers: HeaderMap,
        metrics: Arc<ProtocolMetrics>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let session_id = Uuid::new_v4().to_string();

        Self {
            session_id,
            tx,
            rx,
            client,
            base_url,
            headers,
            read_buffer: BytesMut::with_capacity(16384),
            compressor: Compressor::new(6),
            decompressor: Decompressor::new(),
            metrics,
        }
    }

    async fn send_request(&self, data: Vec<u8>) -> ProtocolResult<Vec<u8>> {
        let padded = HttpProtocol::add_random_padding(&data);
        
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{}/data", self.base_url))
            .header("Session-Id", &self.session_id);

        // Add headers
        for (key, value) in self.headers.iter() {
            request = request.header(key, value);
        }

        let request = request.body(Body::from(padded))
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

        let response = self.client.request(request).await
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

        if response.status() != StatusCode::OK {
            return Err(ProtocolError::ConnectionError(format!("Server returned {}", response.status())));
        }

        let body = hyper::body::to_bytes(response.into_body()).await
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

        HttpProtocol::remove_padding(&body)
    }
}

#[async_trait]
impl Protocol for HttpProtocol {
    async fn init(&self) -> ProtocolResult<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, mut stream: T) -> ProtocolResult<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let _latency = self.metrics.start_latency_measurement();

        // Read HTTP request
        let mut buffer = BytesMut::with_capacity(4096);
        stream.read_buf(&mut buffer).await
            .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

        // Parse session ID from request
        let session_id = ""; // TODO: Parse from request headers

        // Create tunnel
        let tunnel = HttpTunnel::new(
            self.client.clone(),
            format!("https://{}:{}", self.config.host, self.config.port),
            self.build_headers(),
            self.metrics.clone(),
        );

        // Store session
        self.active_sessions.insert(session_id.to_string(), tunnel.tx.clone());

        self.metrics.record_connection_established();

        Ok(Box::new(tunnel))
    }

    async fn connect(&self) -> ProtocolResult<Box<dyn Tunnel>> {
        let _latency = self.metrics.start_latency_measurement();

        // Try to get connection from pool
        if let Ok(tunnel) = self.pool.get(|| async {
            Ok(HttpTunnel::new(
                self.client.clone(),
                format!("https://{}:{}", self.config.host, self.config.port),
                self.build_headers(),
                self.metrics.clone(),
            ))
        }).await {
            self.metrics.record_connection_established();
            return Ok(Box::new(tunnel));
        }

        self.metrics.record_connection_error();
        Err(ProtocolError::ConnectionError("Failed to get connection from pool".to_string()))
    }
}

#[async_trait]
impl Tunnel for HttpTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        // Try to read from buffer first
        if !self.read_buffer.is_empty() {
            let len = self.read_buffer.len();
            buf.extend_from_slice(&self.read_buffer);
            self.read_buffer.clear();
            return Ok(len);
        }

        // Receive data from channel or make HTTP request
        let data = if let Some(data) = self.rx.recv().await {
            data
        } else {
            let response = self.send_request(vec![]).await?;
            if response.is_empty() {
                return Ok(0);
            }
            response
        };

        // Decompress data
        let decompressed = self.decompressor.decompress(&data)
            .map_err(|e| ProtocolError::Other(e.into()))?;

        self.metrics.record_bytes_received(data.len() as u64);
        buf.extend_from_slice(&decompressed);
        Ok(decompressed.len())
    }

    async fn write(&mut self, buf: &[u8]) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        // Compress data
        let compressed = self.compressor.compress(buf)
            .map_err(|e| ProtocolError::Other(e.into()))?;

        // Send HTTP request
        let response = self.send_request(compressed.clone()).await?;

        self.metrics.record_bytes_sent(compressed.len() as u64);
        Ok(buf.len())
    }

    async fn close(&mut self) -> ProtocolResult<()> {
        self.metrics.record_connection_closed();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::net::Ipv4Addr;
    use crate::protocol::tls::TlsConfig;

    #[tokio::test]
    async fn test_http_protocol() -> ProtocolResult<()> {
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
            name: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: 0,
            path: Some("/data".to_string()),
            headers: None,
            keepalive: 60,
        };

        // Create protocol instance
        let protocol = HttpProtocol::new(config.clone(), tls_manager.clone());

        // Start test server
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        // Update config with actual port
        let mut client_config = config;
        client_config.port = addr.port();

        // Client connection task
        let client_task = tokio::spawn(async move {
            let protocol = HttpProtocol::new(client_config, tls_manager);
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