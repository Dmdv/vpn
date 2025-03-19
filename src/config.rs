use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use ipnetwork::Ipv4Network;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    // Server settings
    pub host: String,
    pub port: u16,
    pub api_port: u16,
    
    // VPN settings
    pub subnet: String,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    
    // Crypto settings
    pub encryption_method: String,
    pub key_rotation_interval: u64, // in hours
    
    // Authentication
    pub jwt_secret: String,
    pub session_timeout: u64, // in minutes
    
    // Rate limiting
    pub max_clients: usize,
    pub bandwidth_limit_mbps: Option<u32>,
    
    // Logging
    pub log_level: String,
    pub enable_traffic_logging: bool,

    // VPC Network configuration
    pub vpc_network: String,        // e.g. "10.10.0.0/16"
    pub vpn_subnet: String,         // e.g. "10.10.1.0/24"
    pub server_vpn_ip: String,      // e.g. "10.10.1.1"
    pub client_ip_start: String,    // e.g. "10.10.1.2"
    pub client_ip_end: String,      // e.g. "10.10.1.254"
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: "0.0.0.0".to_string(),
            port: 1194,
            api_port: 8080,
            subnet: "10.8.0.0/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: 1500,
            encryption_method: "aes-256-gcm".to_string(),
            key_rotation_interval: 24,
            jwt_secret: std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string()),
            session_timeout: 1440, // 24 hours
            max_clients: 100,
            bandwidth_limit_mbps: None,
            log_level: "info".to_string(),
            enable_traffic_logging: false,
            vpc_network: "10.10.0.0/16".to_string(),
            vpn_subnet: "10.10.1.0/24".to_string(),
            server_vpn_ip: "10.10.1.1".to_string(),
            client_ip_start: "10.10.1.2".to_string(),
            client_ip_end: "10.10.1.254".to_string(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        Ok(Config::default())
    }

    pub fn get_subnet_network(&self) -> Result<Ipv4Network> {
        Ok(self.vpn_subnet.parse()?)
    }

    pub fn get_server_ip(&self) -> Result<IpAddr> {
        Ok(self.server_vpn_ip.parse()?)
    }

    pub fn get_client_ip_range(&self) -> Result<(Ipv4Addr, Ipv4Addr)> {
        Ok((
            self.client_ip_start.parse()?,
            self.client_ip_end.parse()?
        ))
    }
} 