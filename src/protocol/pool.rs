use crate::protocol::error::{ProtocolError, ProtocolResult};
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;

#[derive(Clone)]
pub struct PoolConfig {
    pub max_size: usize,
    pub min_idle: usize,
    pub max_lifetime: Duration,
    pub idle_timeout: Duration,
    pub connection_timeout: Duration,
}

struct PooledConnection<T> {
    connection: T,
    created_at: Instant,
    last_used: Instant,
}

impl<T> PooledConnection<T> {
    fn new(connection: T) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
        }
    }

    fn is_expired(&self, max_lifetime: Duration, idle_timeout: Duration) -> bool {
        let now = Instant::now();
        now.duration_since(self.created_at) > max_lifetime ||
        now.duration_since(self.last_used) > idle_timeout
    }
}

pub struct ConnectionPool<T> {
    config: PoolConfig,
    connections: Arc<Mutex<VecDeque<PooledConnection<T>>>>,
}

impl<T: Send + 'static> ConnectionPool<T> {
    pub fn new(config: PoolConfig) -> Self {
        let pool = Self {
            config,
            connections: Arc::new(Mutex::new(VecDeque::new())),
        };

        // Start background cleanup task
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.run_cleanup().await;
        });

        pool
    }

    pub async fn get<F, Fut>(&self, create_connection: F) -> ProtocolResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ProtocolResult<T>>,
    {
        // Try to get an existing connection
        let mut connections = self.connections.lock().await;

        while let Some(mut pooled) = connections.pop_front() {
            if !pooled.is_expired(self.config.max_lifetime, self.config.idle_timeout) {
                pooled.last_used = Instant::now();
                return Ok(pooled.connection);
            }
        }

        // Create new connection if pool is not full
        if connections.len() < self.config.max_size {
            drop(connections); // Release lock before async operation
            
            // Create connection with timeout
            let connection = tokio::time::timeout(
                self.config.connection_timeout,
                create_connection()
            ).await
                .map_err(|_| ProtocolError::ConnectionTimeout(self.config.connection_timeout.as_secs()))?
                .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

            return Ok(connection);
        }

        Err(ProtocolError::ConnectionError("Connection pool is full".to_string()))
    }

    pub async fn put(&self, connection: T) -> ProtocolResult<()> {
        let mut connections = self.connections.lock().await;

        // Don't add if pool is full
        if connections.len() >= self.config.max_size {
            return Ok(());
        }

        connections.push_back(PooledConnection::new(connection));
        Ok(())
    }

    async fn run_cleanup(&self) {
        let cleanup_interval = Duration::from_secs(60); // Run cleanup every minute

        loop {
            sleep(cleanup_interval).await;

            let mut connections = self.connections.lock().await;
            let before_len = connections.len();

            // Remove expired connections
            connections.retain(|conn| {
                !conn.is_expired(self.config.max_lifetime, self.config.idle_timeout)
            });

            // Create new connections if below min_idle
            if connections.len() < self.config.min_idle {
                // Release lock and let get() handle creation
                drop(connections);
            }
        }
    }
}

impl<T> Clone for ConnectionPool<T> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            connections: self.connections.clone(),
        }
    }
} 