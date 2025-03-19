use anyhow::{Result, anyhow};
use async_trait::async_trait;
use reqwest::Client;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use trust_dns_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RecordType},
};

// DNS Provider trait for different DNS resolution methods
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn resolve(&self, query: &Message) -> Result<Message>;
    fn provider_type(&self) -> &str;
}

// DNS over HTTPS implementation
pub struct DoHProvider {
    client: Client,
    servers: Vec<String>,
    current_server: usize,
}

impl DoHProvider {
    pub fn new(servers: Vec<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        Ok(Self {
            client,
            servers,
            current_server: 0,
        })
    }

    fn next_server(&mut self) -> &str {
        let server = &self.servers[self.current_server];
        self.current_server = (self.current_server + 1) % self.servers.len();
        server
    }
}

#[async_trait]
impl DnsProvider for DoHProvider {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let query_data = query.to_vec()?;
        let query_base64 = base64::encode(&query_data);

        let mut attempts = 0;
        let max_attempts = self.servers.len();

        while attempts < max_attempts {
            let server = self.next_server();
            let url = format!("{}/dns-query", server);

            match self.client
                .get(&url)
                .header("accept", "application/dns-message")
                .query(&[("dns", &query_base64)])
                .send()
                .await
            {
                Ok(response) => {
                    let data = response.bytes().await?;
                    return Ok(Message::from_vec(&data)?);
                }
                Err(e) => {
                    warn!("DoH request failed for {}: {}", server, e);
                    attempts += 1;
                }
            }
        }

        Err(anyhow!("All DoH servers failed"))
    }

    fn provider_type(&self) -> &str {
        "DoH"
    }
}

// DNS over TLS implementation
pub struct DoTProvider {
    config: Arc<ClientConfig>,
    servers: Vec<(String, u16)>,
    current_server: usize,
}

impl DoTProvider {
    pub fn new(servers: Vec<(String, u16)>) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            config: Arc::new(config),
            servers,
            current_server: 0,
        })
    }

    fn next_server(&mut self) -> &(String, u16) {
        let server = &self.servers[self.current_server];
        self.current_server = (self.current_server + 1) % self.servers.len();
        server
    }
}

#[async_trait]
impl DnsProvider for DoTProvider {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let mut attempts = 0;
        let max_attempts = self.servers.len();

        while attempts < max_attempts {
            let (host, port) = self.next_server();
            
            match tokio::net::TcpStream::connect((host.as_str(), *port)).await {
                Ok(stream) => {
                    let connector = tokio_rustls::TlsConnector::from(self.config.clone());
                    match connector.connect(host.as_str().try_into()?, stream).await {
                        Ok(mut tls_stream) => {
                            // Send DNS query
                            let query_data = query.to_vec()?;
                            let length = (query_data.len() as u16).to_be_bytes();
                            
                            tls_stream.write_all(&length).await?;
                            tls_stream.write_all(&query_data).await?;

                            // Read response length
                            let mut length_buf = [0u8; 2];
                            tls_stream.read_exact(&mut length_buf).await?;
                            let length = u16::from_be_bytes(length_buf) as usize;

                            // Read response
                            let mut response_buf = vec![0u8; length];
                            tls_stream.read_exact(&mut response_buf).await?;

                            return Ok(Message::from_vec(&response_buf)?);
                        }
                        Err(e) => {
                            warn!("DoT TLS connection failed for {}: {}", host, e);
                            attempts += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("DoT TCP connection failed for {}: {}", host, e);
                    attempts += 1;
                }
            }
        }

        Err(anyhow!("All DoT servers failed"))
    }

    fn provider_type(&self) -> &str {
        "DoT"
    }
}

// DNS Cache implementation
#[derive(Debug)]
struct CacheEntry {
    response: Message,
    expires: SystemTime,
}

pub struct DnsCache {
    cache: RwLock<HashMap<String, CacheEntry>>,
    max_size: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(max_size: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_size,
            min_ttl,
            max_ttl,
        }
    }

    pub async fn get(&self, query: &Message) -> Option<Message> {
        let cache = self.cache.read().await;
        let key = self.cache_key(query);
        
        if let Some(entry) = cache.get(&key) {
            if SystemTime::now() < entry.expires {
                return Some(entry.response.clone());
            }
        }
        
        None
    }

    pub async fn insert(&self, query: &Message, response: Message) {
        let mut cache = self.cache.write().await;
        
        // Enforce cache size limit
        if cache.len() >= self.max_size {
            // Remove expired entries first
            cache.retain(|_, entry| SystemTime::now() < entry.expires);
            
            // If still too large, remove oldest entries
            if cache.len() >= self.max_size {
                let mut entries: Vec<_> = cache.iter().collect();
                entries.sort_by_key(|(_, entry)| entry.expires);
                let to_remove = entries.len() - self.max_size + 1;
                for (key, _) in entries.iter().take(to_remove) {
                    cache.remove(*key);
                }
            }
        }

        // Calculate TTL and expiration
        let ttl = response.answers()
            .iter()
            .map(|record| record.ttl())
            .min()
            .unwrap_or(self.min_ttl)
            .clamp(self.min_ttl, self.max_ttl);

        let expires = SystemTime::now() + Duration::from_secs(ttl as u64);
        
        cache.insert(
            self.cache_key(query),
            CacheEntry {
                response,
                expires,
            },
        );
    }

    fn cache_key(&self, message: &Message) -> String {
        let mut key = String::new();
        for query in message.queries() {
            key.push_str(&format!(
                "{}:{}:",
                query.name().to_ascii(),
                query.query_type().to_string()
            ));
        }
        key
    }
}

// DNS Manager implementation
pub struct DnsManager {
    doh_provider: DoHProvider,
    dot_provider: DoTProvider,
    cache: DnsCache,
    allowed_ips: Vec<IpAddr>,
}

impl DnsManager {
    pub fn new(
        doh_servers: Vec<String>,
        dot_servers: Vec<(String, u16)>,
        allowed_ips: Vec<IpAddr>,
    ) -> Result<Self> {
        Ok(Self {
            doh_provider: DoHProvider::new(doh_servers)?,
            dot_provider: DoTProvider::new(dot_servers)?,
            cache: DnsCache::new(1000, 60, 86400), // 1000 entries, 1 min to 24 hour TTL
            allowed_ips,
        })
    }

    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        // Check cache first
        if let Some(cached) = self.cache.get(query).await {
            debug!("DNS cache hit");
            return Ok(cached);
        }

        // Verify query is allowed
        self.verify_query(query)?;

        // Try DoH first, fallback to DoT
        let response = match self.doh_provider.resolve(query).await {
            Ok(response) => {
                debug!("DoH resolution successful");
                response
            }
            Err(e) => {
                warn!("DoH resolution failed: {}, falling back to DoT", e);
                match self.dot_provider.resolve(query).await {
                    Ok(response) => {
                        debug!("DoT resolution successful");
                        response
                    }
                    Err(e) => {
                        error!("Both DoH and DoT resolution failed: {}", e);
                        return Err(e);
                    }
                }
            }
        };

        // Cache successful response
        self.cache.insert(query, response.clone()).await;

        Ok(response)
    }

    fn verify_query(&self, query: &Message) -> Result<()> {
        // Only allow queries from configured IPs
        if !self.allowed_ips.is_empty() {
            // In practice, you'd get the client IP from the connection
            // This is just a placeholder for the verification logic
            return Err(anyhow!("DNS query not allowed from this IP"));
        }

        // Verify query type
        if query.message_type() != MessageType::Query {
            return Err(anyhow!("Only DNS queries are allowed"));
        }

        // Additional security checks can be added here
        // - DNSSEC validation
        // - Query rate limiting
        // - Query type restrictions
        // - Domain restrictions

        Ok(())
    }
} 