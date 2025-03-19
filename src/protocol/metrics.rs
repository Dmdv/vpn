use metrics::{counter, gauge, histogram};
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct ProtocolMetrics {
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
    connection_errors: Arc<AtomicU64>,
    last_latency_ms: Arc<AtomicU64>,
}

impl ProtocolMetrics {
    pub fn new(protocol_name: &str) -> Self {
        let metrics = Self {
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            connection_errors: Arc::new(AtomicU64::new(0)),
            last_latency_ms: Arc::new(AtomicU64::new(0)),
        };

        // Register metrics
        gauge!(
            format!("protocol_{}_active_connections", protocol_name),
            metrics.active_connections.load(Ordering::Relaxed) as f64
        );
        counter!(
            format!("protocol_{}_bytes_sent", protocol_name),
            metrics.bytes_sent.load(Ordering::Relaxed) as f64
        );
        counter!(
            format!("protocol_{}_bytes_received", protocol_name),
            metrics.bytes_received.load(Ordering::Relaxed) as f64
        );
        counter!(
            format!("protocol_{}_connection_errors", protocol_name),
            metrics.connection_errors.load(Ordering::Relaxed) as f64
        );
        histogram!(
            format!("protocol_{}_latency_ms", protocol_name),
            metrics.last_latency_ms.load(Ordering::Relaxed) as f64
        );

        metrics
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        counter!(
            "protocol_bytes_sent",
            bytes as f64,
            "direction" => "sent"
        );
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        counter!(
            "protocol_bytes_received",
            bytes as f64,
            "direction" => "received"
        );
    }

    pub fn record_connection_established(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        gauge!(
            "protocol_active_connections",
            self.active_connections.load(Ordering::Relaxed) as f64
        );
    }

    pub fn record_connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        gauge!(
            "protocol_active_connections",
            self.active_connections.load(Ordering::Relaxed) as f64
        );
    }

    pub fn record_connection_error(&self) {
        self.connection_errors.fetch_add(1, Ordering::Relaxed);
        counter!("protocol_connection_errors", 1.0);
    }

    pub fn start_latency_measurement(&self) -> LatencyMeasurement {
        LatencyMeasurement {
            start_time: Instant::now(),
            metrics: self.clone(),
        }
    }
}

pub struct LatencyMeasurement {
    start_time: Instant,
    metrics: ProtocolMetrics,
}

impl Drop for LatencyMeasurement {
    fn drop(&mut self) {
        let latency = self.start_time.elapsed().as_millis() as u64;
        self.metrics.last_latency_ms.store(latency, Ordering::Relaxed);
        histogram!("protocol_latency_ms", latency as f64);
    }
} 