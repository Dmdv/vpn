use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use async_trait::async_trait;
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use std::net::SocketAddr;
use std::time::Duration;

pub struct TcpProtocol {
    config: ProtocolConfig,
}

impl TcpProtocol {
    pub fn new(config: ProtocolConfig) -> Self {
        Self { config }
    }

    async fn configure_stream(stream: &TcpStream, keepalive: u64) -> Result<()> {
        // Set TCP keepalive
        stream.set_keepalive(Some(Duration::from_secs(keepalive)))?;
        
        // Set TCP_NODELAY for better performance
        stream.set_nodelay(true)?;
        
        Ok(())
    }
}

pub struct TcpTunnel {
    stream: TcpStream,
    read_buffer: BytesMut,
}

impl TcpTunnel {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::with_capacity(16384), // 16KB buffer
        }
    }
}

#[async_trait]
impl Protocol for TcpProtocol {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, stream: T) -> Result<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        // Convert generic stream to TcpStream
        let stream = match stream.into_std()? {
            std => TcpStream::from_std(std)?,
        };

        // Configure stream parameters
        Self::configure_stream(&stream, self.config.keepalive).await?;

        Ok(Box::new(TcpTunnel::new(stream)))
    }

    async fn connect(&self) -> Result<Box<dyn Tunnel>> {
        let addr = format!("{}:{}", self.config.host, self.config.port)
            .parse::<SocketAddr>()?;

        // Connect with timeout
        let stream = tokio::time::timeout(
            Duration::from_secs(10), // 10 second connection timeout
            TcpStream::connect(addr)
        ).await??;

        // Configure stream parameters
        Self::configure_stream(&stream, self.config.keepalive).await?;

        Ok(Box::new(TcpTunnel::new(stream)))
    }
}

#[async_trait]
impl Tunnel for TcpTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> Result<usize> {
        // Read into internal buffer
        let n = self.stream.read_buf(&mut self.read_buffer).await?;
        if n == 0 {
            return Ok(0); // EOF
        }

        // Move data from internal buffer to output buffer
        buf.extend_from_slice(&self.read_buffer[..n]);
        self.read_buffer.clear();

        Ok(n)
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.stream.write(buf).await?;
        self.stream.flush().await?;
        Ok(n)
    }

    async fn close(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_tcp_protocol() -> Result<()> {
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
        let protocol = TcpProtocol::new(config.clone());

        // Start test server
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        // Update config with actual port
        let mut client_config = config;
        client_config.port = addr.port();

        // Client connection task
        let client_task = tokio::spawn(async move {
            let protocol = TcpProtocol::new(client_config);
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