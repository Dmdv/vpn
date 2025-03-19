use crate::protocol::{Protocol, Tunnel, ProtocolConfig};
use async_trait::async_trait;
use anyhow::Result;
use bytes::{BytesMut, BufMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use hyper::{
    Body, Client, Request, Response, StatusCode,
    client::HttpConnector, header::{HeaderMap, HeaderValue},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{thread_rng, Rng};

pub struct HttpProtocol {
    config: ProtocolConfig,
    client: Client<HttpConnector>,
}

impl HttpProtocol {
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_str(&self.config.host).unwrap());
        
        // Add custom headers for obfuscation
        if let Some(custom_headers) = &self.config.headers {
            for (key, value) in custom_headers {
                if let Ok(val) = HeaderValue::from_str(value) {
                    headers.insert(key, val);
                }
            }
        }

        // Add common browser headers for better camouflage
        headers.insert("User-Agent", HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"));
        headers.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.5"));
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip, deflate"));
        headers.insert("Connection", HeaderValue::from_static("keep-alive"));

        headers
    }

    fn obfuscate_data(&self, data: &[u8]) -> Vec<u8> {
        // Add random padding to make traffic look more like HTTP
        let mut rng = thread_rng();
        let padding_len = rng.gen_range(16..64);
        let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
        
        let mut obfuscated = Vec::with_capacity(data.len() + padding_len + 8);
        obfuscated.extend_from_slice(&(data.len() as u32).to_be_bytes());
        obfuscated.extend_from_slice(&(padding_len as u32).to_be_bytes());
        obfuscated.extend_from_slice(&padding);
        obfuscated.extend_from_slice(data);
        
        BASE64.encode(obfuscated).into_bytes()
    }

    fn deobfuscate_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let decoded = BASE64.decode(data)?;
        if decoded.len() < 8 {
            return Ok(Vec::new());
        }

        let data_len = u32::from_be_bytes(decoded[0..4].try_into()?) as usize;
        let padding_len = u32::from_be_bytes(decoded[4..8].try_into()?) as usize;
        
        if decoded.len() < 8 + padding_len + data_len {
            return Ok(Vec::new());
        }

        Ok(decoded[8 + padding_len..8 + padding_len + data_len].to_vec())
    }
}

pub struct HttpTunnel {
    protocol: HttpProtocol,
    buffer: BytesMut,
}

#[async_trait]
impl Protocol for HttpProtocol {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn handle_connection<T>(&self, mut stream: T) -> Result<Box<dyn Tunnel>>
    where
        T: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        // Read HTTP request
        let mut buffer = BytesMut::with_capacity(4096);
        stream.read_buf(&mut buffer).await?;

        // Send HTTP response with connection upgrade
        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                       Connection: Upgrade\r\n\
                       Upgrade: custom-protocol\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;

        Ok(Box::new(HttpTunnel {
            protocol: HttpProtocol::new(self.config.clone()),
            buffer: BytesMut::new(),
        }))
    }

    async fn connect(&self) -> Result<Box<dyn Tunnel>> {
        Ok(Box::new(HttpTunnel {
            protocol: HttpProtocol::new(self.config.clone()),
            buffer: BytesMut::new(),
        }))
    }
}

#[async_trait]
impl Tunnel for HttpTunnel {
    async fn read(&mut self, buf: &mut BytesMut) -> Result<usize> {
        // Create HTTP request
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{}:{}/data", self.protocol.config.host, self.protocol.config.port))
            .headers(self.protocol.build_headers())
            .body(Body::empty())?;

        // Send request and get response
        let response = self.protocol.client.request(request).await?;
        let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
        
        // Deobfuscate response
        let data = self.protocol.deobfuscate_data(&body_bytes)?;
        buf.extend_from_slice(&data);
        
        Ok(data.len())
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        // Obfuscate data
        let obfuscated = self.protocol.obfuscate_data(buf);
        
        // Create HTTP request with obfuscated data
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{}:{}/data", self.protocol.config.host, self.protocol.config.port))
            .headers(self.protocol.build_headers())
            .body(Body::from(obfuscated))?;

        // Send request
        let response = self.protocol.client.request(request).await?;
        
        if response.status() != StatusCode::OK {
            return Ok(0);
        }
        
        Ok(buf.len())
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
} 