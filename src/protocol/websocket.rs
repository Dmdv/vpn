use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use async_trait::async_trait;
use anyhow::Result;
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

pub struct WebSocketProtocol {
    config: ProtocolConfig,
}

impl WebSocketProtocol {
    pub fn new(config: ProtocolConfig) -> Self {
        Self { config }
    }

    fn build_request(&self) -> Result<Request<()>> {
        let path = self.config.path.as_deref().unwrap_or("/ws");
        let uri = format!("ws://{}:{}{}", self.config.host, self.config.port, path)
            .parse::<Uri>()?;

        let mut request = Request::builder()
            .uri(uri)
            .header("Host", &self.config.host);

        // Add custom headers if specified
        if let Some(headers) = &self.config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        Ok(request.body(())?)
    }
}

pub struct WebSocketTunnel {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

#[async_trait]
impl Protocol for WebSocketProtocol {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, stream: T) -> Result<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let ws_stream = tokio_tungstenite::accept_async(stream).await?;
        Ok(Box::new(WebSocketTunnel { ws_stream }))
    }

    async fn connect(&self) -> Result<Box<dyn Tunnel>> {
        let request = self.build_request()?;
        let (ws_stream, _) = connect_async(request).await?;
        Ok(Box::new(WebSocketTunnel { ws_stream }))
    }
}

#[async_trait]
impl Tunnel for WebSocketTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> Result<usize> {
        if let Some(message) = self.ws_stream.next().await {
            match message? {
                Message::Binary(data) => {
                    buf.extend_from_slice(&data);
                    Ok(data.len())
                }
                Message::Close(_) => Ok(0),
                _ => Ok(0),
            }
        } else {
            Ok(0)
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.ws_stream.send(Message::Binary(buf.to_vec())).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> Result<()> {
        self.ws_stream.close(None).await?;
        Ok(())
    }
} 