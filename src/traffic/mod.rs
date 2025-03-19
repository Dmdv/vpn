use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// Traffic classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    RealTime,    // Voice, video calls
    Interactive, // Gaming, remote desktop
    Streaming,   // Video streaming
    Bulk,        // Downloads, backups
    Background,  // Updates, sync
}

impl TrafficClass {
    fn priority(&self) -> u8 {
        match self {
            TrafficClass::RealTime => 1,
            TrafficClass::Interactive => 2,
            TrafficClass::Streaming => 3,
            TrafficClass::Bulk => 4,
            TrafficClass::Background => 5,
        }
    }

    fn bandwidth_share(&self) -> f32 {
        match self {
            TrafficClass::RealTime => 0.4,    // 40%
            TrafficClass::Interactive => 0.3,  // 30%
            TrafficClass::Streaming => 0.2,    // 20%
            TrafficClass::Bulk => 0.07,        // 7%
            TrafficClass::Background => 0.03,  // 3%
        }
    }
}

// Token bucket for rate limiting
pub struct TokenBucket {
    capacity: u64,
    tokens: f64,
    fill_rate: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, fill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            fill_rate,
            last_update: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u64) -> bool {
        self.refill();
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + self.fill_rate * elapsed).min(self.capacity as f64);
        self.last_update = now;
    }
}

// Client traffic state
#[derive(Debug)]
struct ClientState {
    ip: IpAddr,
    traffic_class: TrafficClass,
    token_bucket: TokenBucket,
    bytes_sent: u64,
    bytes_received: u64,
    last_active: Instant,
}

impl ClientState {
    fn new(ip: IpAddr, traffic_class: TrafficClass, rate_limit: u64) -> Self {
        Self {
            ip,
            traffic_class,
            token_bucket: TokenBucket::new(rate_limit, rate_limit as f64 / 8.0), // Fill rate = rate_limit/8 bytes per second
            bytes_sent: 0,
            bytes_received: 0,
            last_active: Instant::now(),
        }
    }
}

// Traffic manager
pub struct TrafficManager {
    clients: Arc<RwLock<HashMap<IpAddr, ClientState>>>,
    total_bandwidth: u64,
    class_buckets: HashMap<TrafficClass, TokenBucket>,
}

impl TrafficManager {
    pub fn new(total_bandwidth: u64) -> Self {
        let mut class_buckets = HashMap::new();
        for class in [
            TrafficClass::RealTime,
            TrafficClass::Interactive,
            TrafficClass::Streaming,
            TrafficClass::Bulk,
            TrafficClass::Background,
        ].iter() {
            let share = class.bandwidth_share();
            let capacity = (total_bandwidth as f32 * share) as u64;
            class_buckets.insert(
                *class,
                TokenBucket::new(capacity, capacity as f64 / 8.0)
            );
        }

        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            total_bandwidth,
            class_buckets,
        }
    }

    pub async fn register_client(
        &self,
        ip: IpAddr,
        traffic_class: TrafficClass,
        rate_limit: Option<u64>,
    ) -> Result<()> {
        let rate_limit = rate_limit.unwrap_or_else(|| {
            let share = traffic_class.bandwidth_share();
            (self.total_bandwidth as f32 * share) as u64
        });

        let mut clients = self.clients.write().await;
        clients.insert(
            ip,
            ClientState::new(ip, traffic_class, rate_limit),
        );

        Ok(())
    }

    pub async fn unregister_client(&self, ip: &IpAddr) -> Result<()> {
        let mut clients = self.clients.write().await;
        clients.remove(ip);
        Ok(())
    }

    pub async fn can_send(&self, ip: &IpAddr, bytes: u64) -> Result<bool> {
        let mut clients = self.clients.write().await;
        
        let client = clients.get_mut(ip)
            .ok_or_else(|| anyhow!("Client not registered: {}", ip))?;

        // Update last active time
        client.last_active = Instant::now();

        // Check class bucket first
        if !self.class_buckets.get(&client.traffic_class)
            .ok_or_else(|| anyhow!("Traffic class not found"))?
            .try_consume(bytes)
        {
            return Ok(false);
        }

        // Then check client bucket
        Ok(client.token_bucket.try_consume(bytes))
    }

    pub async fn record_traffic(&self, ip: &IpAddr, bytes_sent: u64, bytes_received: u64) -> Result<()> {
        let mut clients = self.clients.write().await;
        
        if let Some(client) = clients.get_mut(ip) {
            client.bytes_sent += bytes_sent;
            client.bytes_received += bytes_received;
            client.last_active = Instant::now();
        }

        Ok(())
    }

    pub async fn get_client_stats(&self, ip: &IpAddr) -> Result<(u64, u64, TrafficClass)> {
        let clients = self.clients.read().await;
        
        let client = clients.get(ip)
            .ok_or_else(|| anyhow!("Client not registered: {}", ip))?;

        Ok((client.bytes_sent, client.bytes_received, client.traffic_class))
    }

    pub async fn cleanup_inactive(&self, timeout: Duration) -> Result<()> {
        let mut clients = self.clients.write().await;
        
        clients.retain(|_, client| {
            client.last_active.elapsed() < timeout
        });

        Ok(())
    }

    // Traffic shaping helper methods
    pub async fn shape_packet(&self, ip: &IpAddr, packet: &[u8]) -> Result<Duration> {
        let clients = self.clients.read().await;
        
        let client = clients.get(ip)
            .ok_or_else(|| anyhow!("Client not registered: {}", ip))?;

        // Calculate delay based on traffic class and current usage
        let base_delay = match client.traffic_class {
            TrafficClass::RealTime => Duration::from_micros(100),
            TrafficClass::Interactive => Duration::from_micros(200),
            TrafficClass::Streaming => Duration::from_micros(500),
            TrafficClass::Bulk => Duration::from_millis(1),
            TrafficClass::Background => Duration::from_millis(2),
        };

        // Adjust delay based on current bandwidth usage
        let usage_factor = (client.bytes_sent as f64) / (self.total_bandwidth as f64);
        let adjusted_delay = base_delay.mul_f64(1.0 + usage_factor);

        Ok(adjusted_delay)
    }

    pub async fn start_cleanup_task(self: Arc<Self>) {
        let cleanup_interval = Duration::from_secs(60); // Run cleanup every minute
        let inactive_timeout = Duration::from_secs(300); // 5 minutes timeout

        tokio::spawn(async move {
            loop {
                sleep(cleanup_interval).await;
                if let Err(e) = self.cleanup_inactive(inactive_timeout).await {
                    error!("Error during cleanup: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_traffic_manager() -> Result<()> {
        let manager = TrafficManager::new(1_000_000); // 1 Mbps
        let client_ip = "192.168.1.100".parse()?;

        // Register client
        manager.register_client(client_ip, TrafficClass::RealTime, None).await?;

        // Test sending data
        assert!(manager.can_send(&client_ip, 1000).await?);
        manager.record_traffic(&client_ip, 1000, 500).await?;

        // Check stats
        let (sent, received, class) = manager.get_client_stats(&client_ip).await?;
        assert_eq!(sent, 1000);
        assert_eq!(received, 500);
        assert_eq!(class, TrafficClass::RealTime);

        // Test cleanup
        sleep(Duration::from_millis(100)).await;
        manager.cleanup_inactive(Duration::from_millis(50)).await?;
        assert!(manager.get_client_stats(&client_ip).await.is_err());

        Ok(())
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000, 100.0);
        
        // Should be able to consume initial tokens
        assert!(bucket.try_consume(500));
        assert!(!bucket.try_consume(600)); // Not enough tokens
        
        // Wait for refill
        std::thread::sleep(Duration::from_secs(2));
        assert!(bucket.try_consume(200)); // Should have refilled
    }
} 