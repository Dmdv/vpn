use crate::config::Config;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct FoxRayProfile {
    pub id: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub encryption: String,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub routes: Vec<String>,
}

impl FoxRayProfile {
    pub fn new(config: &Config, client_id: Uuid) -> Self {
        FoxRayProfile {
            id: client_id.to_string(),
            name: format!("vpn-{}", client_id.as_simple()),
            server: config.host.clone(),
            port: config.port,
            encryption: config.encryption_method.clone(),
            dns: config.dns_servers.clone(),
            mtu: config.mtu,
            routes: vec!["0.0.0.0/0".to_string()], // Route all traffic through VPN
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| anyhow::anyhow!("Failed to serialize profile: {}", e))
    }

    pub fn generate_obfuscation_rules(&self) -> Vec<String> {
        // TODO: Implement traffic obfuscation rules
        // This will help hide VPN traffic characteristics
        vec![
            "randomize_packet_size".to_string(),
            "pad_headers".to_string(),
            "randomize_timing".to_string(),
        ]
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileRequest {
    pub name: Option<String>,
    pub custom_routes: Option<Vec<String>>,
}

pub async fn generate_profile(config: &Config, request: ProfileRequest) -> Result<FoxRayProfile> {
    let client_id = Uuid::new_v4();
    let mut profile = FoxRayProfile::new(config, client_id);
    
    if let Some(name) = request.name {
        profile.name = name;
    }
    
    if let Some(routes) = request.custom_routes {
        profile.routes = routes;
    }
    
    Ok(profile)
} 