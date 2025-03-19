use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use crate::protocol::error::{ProtocolError, ProtocolResult};
use crate::protocol::pool::{ConnectionPool, PoolConfig};
use crate::protocol::tls::TlsManager;
use crate::protocol::metrics::ProtocolMetrics;
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;
use tokio_rustls::client::TlsStream;
use compression::{prelude::*, Compressor, Decompressor};

pub struct TcpProtocol {
    config: ProtocolConfig,
    pool: Arc<ConnectionPool<TcpTunnel>>,
    tls_manager: Arc<TlsManager>,
    metrics: Arc<ProtocolMetrics>,
}

impl TcpProtocol {
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
            metrics: Arc::new(ProtocolMetrics::new("tcp")),
        }
    }

    async fn configure_stream(stream: &TcpStream, keepalive: u64) -> ProtocolResult<()> {
        stream.set_keepalive(Some(Duration::from_secs(keepalive)))
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to set keepalive: {}", e)))?;
        
        stream.set_nodelay(true)
            .map_err(|e| ProtocolError::ConfigError(format!("Failed to set nodelay: {}", e)))?;
        
        Ok(())
    }
}

pub struct TcpTunnel {
    stream: TlsStream<TcpStream>,
    read_buffer: BytesMut,
    compressor: Compressor,
    decompressor: Decompressor,
    metrics: Arc<ProtocolMetrics>,
}

impl TcpTunnel {
    fn new(stream: TlsStream<TcpStream>, metrics: Arc<ProtocolMetrics>) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::with_capacity(16384), // 16KB buffer
            compressor: Compressor::new(6), // compression level 6
            decompressor: Decompressor::new(),
            metrics,
        }
    }
}

#[async_trait]
impl Protocol for TcpProtocol {
    async fn init(&self) -> ProtocolResult<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, stream: T) -> ProtocolResult<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let _latency = self.metrics.start_latency_measurement();
        
        // Convert generic stream to TcpStream
        let tcp_stream = match stream.into_std()? {
            std => TcpStream::from_std(std)?,
        };

        // Configure stream parameters
        Self::configure_stream(&tcp_stream, self.config.keepalive).await?;

        // Upgrade to TLS
        let acceptor = self.tls_manager.get_acceptor();
        let tls_stream = acceptor.accept(tcp_stream).await
            .map_err(|e| ProtocolError::TlsError(format!("TLS handshake failed: {}", e)))?;

        self.metrics.record_connection_established();

        Ok(Box::new(TcpTunnel::new(tls_stream, self.metrics.clone())))
    }

    async fn connect(&self) -> ProtocolResult<Box<dyn Tunnel>> {
        let _latency = self.metrics.start_latency_measurement();

        // Try to get connection from pool
        if let Ok(tunnel) = self.pool.get(|| async {
            let addr = format!("{}:{}", self.config.host, self.config.port)
                .parse::<SocketAddr>()
                .map_err(|e| ProtocolError::ConfigError(format!("Invalid address: {}", e)))?;

            // Connect with timeout
            let tcp_stream = tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(addr)
            ).await
                .map_err(|_| ProtocolError::ConnectionTimeout(10))?
                .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

            // Configure stream
            Self::configure_stream(&tcp_stream, self.config.keepalive).await?;

            // Upgrade to TLS
            let connector = self.tls_manager.get_connector();
            let server_name = ServerName::try_from(self.config.host.as_str())
                .map_err(|e| ProtocolError::TlsError(format!("Invalid server name: {}", e)))?;
            
            let tls_stream = connector.connect(server_name, tcp_stream).await
                .map_err(|e| ProtocolError::TlsError(format!("TLS handshake failed: {}", e)))?;

            Ok(TcpTunnel::new(tls_stream, self.metrics.clone()))
        }).await {
            self.metrics.record_connection_established();
            return Ok(Box::new(tunnel));
        }

        self.metrics.record_connection_error();
        Err(ProtocolError::ConnectionError("Failed to get connection from pool".to_string()))
    }
}

#[async_trait]
impl Tunnel for TcpTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        // Read into internal buffer
        let n = self.stream.read_buf(&mut self.read_buffer).await
            .map_err(|e| ProtocolError::IoError(e))?;

        if n == 0 {
            return Ok(0); // EOF
        }

        // Decompress data
        let decompressed = self.decompressor.decompress(&self.read_buffer[..n])
            .map_err(|e| ProtocolError::Other(e.into()))?;

        // Move data to output buffer
        buf.extend_from_slice(&decompressed);
        self.read_buffer.clear();

        self.metrics.record_bytes_received(n as u64);
        Ok(decompressed.len())
    }

    async fn write(&mut self, buf: &[u8]) -> ProtocolResult<usize> {
        let _latency = self.metrics.start_latency_measurement();

        // Compress data
        let compressed = self.compressor.compress(buf)
            .map_err(|e| ProtocolError::Other(e.into()))?;

        // Write and flush
        let n = self.stream.write(&compressed).await
            .map_err(|e| ProtocolError::IoError(e))?;
        self.stream.flush().await
            .map_err(|e| ProtocolError::IoError(e))?;

        self.metrics.record_bytes_sent(n as u64);
        Ok(buf.len())
    }

    async fn close(&mut self) -> ProtocolResult<()> {
        self.metrics.record_connection_closed();
        self.stream.shutdown().await
            .map_err(|e| ProtocolError::IoError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::net::Ipv4Addr;
    use crate::protocol::tls::TlsConfig;

    #[tokio::test]
    async fn test_tcp_protocol() -> ProtocolResult<()> {
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
            name: "tcp".to_string(),
            host: "127.0.0.1".to_string(),
            port: 0, // Let OS choose port
            path: None,
            headers: None,
            keepalive: 60,
        };

        // Create protocol instance
        let protocol = TcpProtocol::new(config.clone(), tls_manager.clone());

        // Start test server
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        // Update config with actual port
        let mut client_config = config;
        client_config.port = addr.port();

        // Client connection task
        let client_task = tokio::spawn(async move {
            let protocol = TcpProtocol::new(client_config, tls_manager);
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