use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    accept_async,
    tungstenite::protocol::{Message, frame::coding::CloseCode},
};
use http::{Request, Response, StatusCode};
use headers::{HeaderMap, HeaderValue};
use anyhow::Result;
use tracing::{info, error, debug};
use rand::Rng;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub struct WebSocketCamouflage {
    host: String,
    path: String,
    fake_server: String,
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl WebSocketCamouflage {
    pub fn new(host: &str, path: &str) -> Self {
        WebSocketCamouflage {
            host: host.to_string(),
            path: path.to_string(),
            fake_server: "nginx/1.20.1".to_string(), // Pretend to be nginx
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn handle_incoming(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        // Create fake HTTP response headers
        let mut headers = HeaderMap::new();
        headers.insert("Server", HeaderValue::from_str(&self.fake_server)?);
        headers.insert("Date", HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now()))?);
        
        // Handle WebSocket upgrade
        if let Ok(mut ws_stream) = accept_async(stream).await {
            info!("WebSocket connection established");
            
            // Main WebSocket communication loop
            while let Ok(msg) = ws_stream.next().await {
                match msg {
                    Message::Binary(data) => {
                        // Store received data in buffer
                        let mut buffer = self.buffer.lock().await;
                        buffer.extend_from_slice(&data);
                        
                        // Process VPN packets from buffer
                        self.process_buffer(&mut buffer).await?;
                    }
                    Message::Close(_) => {
                        info!("WebSocket connection closed by client");
                        break;
                    }
                    _ => {} // Ignore other message types
                }
            }
        } else {
            // If not a WebSocket connection, respond with fake HTTP
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Server", &self.fake_server)
                .body("<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>")?;
            
            // Send fake HTTP response
            stream.write_all(response.to_string().as_bytes()).await?;
        }
        
        Ok(())
    }

    async fn process_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if buffer.len() < 4 {
            return Ok(());
        }

        // Process VPN packets
        let packet_size = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        if buffer.len() >= packet_size + 4 {
            let packet = buffer[4..packet_size + 4].to_vec();
            buffer.drain(0..packet_size + 4);
            
            // Forward packet to TUN device
            self.forward_to_tun(&packet).await?;
        }

        Ok(())
    }

    async fn forward_to_tun(&self, packet: &[u8]) -> Result<()> {
        // Add random delay to make traffic pattern less predictable
        let delay = rand::thread_rng().gen_range(10..50);
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;

        // Add random padding to mask real packet size
        let mut padded_packet = packet.to_vec();
        let padding_size = rand::thread_rng().gen_range(16..64);
        padded_packet.extend(std::iter::repeat(0).take(padding_size));

        // TODO: Forward to TUN device
        // self.tun_device.write(&padded_packet).await?;

        Ok(())
    }

    pub async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        
        // Add packet size header
        let size = packet.len() as u32;
        buffer.extend_from_slice(&size.to_be_bytes());
        buffer.extend_from_slice(packet);

        Ok(())
    }

    // Generate random WebSocket key for client simulation
    fn generate_ws_key() -> String {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 16];
        rng.fill(&mut key[..]);
        BASE64.encode(key)
    }
} 