use anyhow::{Result, anyhow};
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteAction {
    Vpn,
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteMatch {
    Application {
        name: String,
        path: Option<String>,
        hash: Option<String>,
    },
    Domain {
        pattern: String,
        #[serde(skip)]
        regex: Option<Regex>,
    },
    IpRange {
        network: String,
        #[serde(skip)]
        parsed_network: Option<IpNetwork>,
    },
    Port {
        port: u16,
        protocol: Protocol,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    pub match_type: RouteMatch,
    pub action: RouteAction,
    pub priority: i32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub temporary: bool,
    #[serde(skip)]
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
}

impl RouteRule {
    fn compile(&mut self) -> Result<()> {
        match &mut self.match_type {
            RouteMatch::Domain { pattern, regex } => {
                *regex = Some(Regex::new(pattern)?);
            }
            RouteMatch::IpRange { network, parsed_network } => {
                *parsed_network = Some(network.parse()?);
            }
            _ => {}
        }
        Ok(())
    }
}

pub struct RouteManager {
    rules: Arc<RwLock<Vec<RouteRule>>>,
    process_cache: Arc<RwLock<HashMap<u32, String>>>,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            process_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_rule(&self, mut rule: RouteRule) -> Result<()> {
        rule.compile()?;
        let mut rules = self.rules.write().await;
        rules.push(rule);
        rules.sort_by_key(|r| -r.priority); // Higher priority first
        Ok(())
    }

    pub async fn remove_rule(&self, name: &str) -> Result<()> {
        let mut rules = self.rules.write().await;
        if let Some(pos) = rules.iter().position(|r| r.name == name) {
            rules.remove(pos);
            Ok(())
        } else {
            Err(anyhow!("Rule not found: {}", name))
        }
    }

    pub async fn get_route_action(&self, packet: &[u8]) -> Result<RouteAction> {
        let rules = self.rules.read().await;
        
        // Extract packet information
        let (source_ip, dest_ip, source_port, dest_port, protocol) = 
            self.extract_packet_info(packet)?;

        // Check process (application) rules
        if let Some(process_name) = self.get_process_by_port(source_port).await? {
            for rule in rules.iter() {
                if !rule.enabled {
                    continue;
                }
                
                if let RouteMatch::Application { name, path, hash } = &rule.match_type {
                    if self.match_application(&process_name, name, path, hash)? {
                        return Ok(rule.action);
                    }
                }
            }
        }

        // Check domain rules if it's a DNS packet
        if dest_port == 53 {
            if let Some(domain) = self.extract_dns_query(packet)? {
                for rule in rules.iter() {
                    if !rule.enabled {
                        continue;
                    }
                    
                    if let RouteMatch::Domain { regex, .. } = &rule.match_type {
                        if let Some(regex) = regex {
                            if regex.is_match(&domain) {
                                return Ok(rule.action);
                            }
                        }
                    }
                }
            }
        }

        // Check IP range rules
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            
            if let RouteMatch::IpRange { parsed_network, .. } = &rule.match_type {
                if let Some(network) = parsed_network {
                    if network.contains(dest_ip) {
                        return Ok(rule.action);
                    }
                }
            }
        }

        // Check port rules
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            
            if let RouteMatch::Port { port, protocol: rule_protocol } = &rule.match_type {
                if *port == dest_port && (
                    *rule_protocol == Protocol::Both ||
                    (*rule_protocol == Protocol::Tcp && protocol == Protocol::Tcp) ||
                    (*rule_protocol == Protocol::Udp && protocol == Protocol::Udp)
                ) {
                    return Ok(rule.action);
                }
            }
        }

        // Default to VPN
        Ok(RouteAction::Vpn)
    }

    async fn get_process_by_port(&self, port: u16) -> Result<Option<String>> {
        let cache = self.process_cache.read().await;
        
        // Check cache first
        if let Some(pid) = self.get_pid_by_port(port)? {
            if let Some(name) = cache.get(&pid) {
                return Ok(Some(name.clone()));
            }
            
            // Not in cache, get process name
            if let Ok(name) = self.get_process_name(pid) {
                let mut cache = self.process_cache.write().await;
                cache.insert(pid, name.clone());
                return Ok(Some(name));
            }
        }
        
        Ok(None)
    }

    fn get_pid_by_port(&self, port: u16) -> Result<Option<u32>> {
        // Platform-specific implementation
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ss")
                .args(&["-tunlp", &format!("sport = {}", port)])
                .output()?;
            
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output.lines().nth(1) {
                if let Some(pid) = line.split("pid=").nth(1) {
                    if let Some(pid) = pid.split(',').next() {
                        return Ok(Some(pid.parse()?));
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("lsof")
                .args(&["-i", &format!(":{}", port)])
                .output()?;
            
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output.lines().nth(1) {
                if let Some(pid) = line.split_whitespace().nth(1) {
                    return Ok(Some(pid.parse()?));
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("netstat")
                .args(&["-ano", "|", "findstr", &format!(":{}", port)])
                .output()?;
            
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output.lines().next() {
                if let Some(pid) = line.split_whitespace().last() {
                    return Ok(Some(pid.parse()?));
                }
            }
        }
        
        Ok(None)
    }

    fn get_process_name(&self, pid: u32) -> Result<String> {
        // Platform-specific implementation
        #[cfg(target_os = "linux")]
        {
            let path = format!("/proc/{}/comm", pid);
            Ok(std::fs::read_to_string(path)?.trim().to_string())
        }
        
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("ps")
                .args(&["-p", &pid.to_string(), "-o", "comm="])
                .output()?;
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("tasklist")
                .args(&["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()?;
            let output = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output.lines().next() {
                if let Some(name) = line.split_whitespace().next() {
                    return Ok(name.to_string());
                }
            }
            Err(anyhow!("Process not found"))
        }
    }

    fn match_application(
        &self,
        process_name: &str,
        rule_name: &str,
        rule_path: &Option<String>,
        rule_hash: &Option<String>,
    ) -> Result<bool> {
        // Basic name match
        if !process_name.contains(rule_name) {
            return Ok(false);
        }

        // Path match if specified
        if let Some(path) = rule_path {
            let process_path = self.get_process_path(process_name)?;
            if !process_path.contains(path) {
                return Ok(false);
            }
        }

        // Hash match if specified
        if let Some(hash) = rule_hash {
            let process_path = self.get_process_path(process_name)?;
            let file_hash = self.calculate_file_hash(&process_path)?;
            if file_hash != *hash {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn get_process_path(&self, process_name: &str) -> Result<PathBuf> {
        // Platform-specific implementation
        #[cfg(target_os = "linux")]
        {
            Ok(PathBuf::from(format!("/proc/{}/exe", process_name)))
        }
        
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("which")
                .arg(process_name)
                .output()?;
            Ok(PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
        }
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("where")
                .arg(process_name)
                .output()?;
            Ok(PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
        }
    }

    fn calculate_file_hash(&self, path: &PathBuf) -> Result<String> {
        use sha2::{Sha256, Digest};
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn extract_packet_info(&self, packet: &[u8]) -> Result<(IpAddr, IpAddr, u16, u16, Protocol)> {
        // Basic IPv4 header parsing
        if packet.len() < 20 {
            return Err(anyhow!("Packet too short"));
        }

        let version = (packet[0] >> 4) & 0xF;
        match version {
            4 => {
                let ihl = (packet[0] & 0xF) as usize * 4;
                if packet.len() < ihl {
                    return Err(anyhow!("IPv4 packet too short"));
                }

                let protocol = packet[9];
                let source_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15]
                ));
                let dest_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19]
                ));

                let (source_port, dest_port) = if protocol == 6 || protocol == 17 {
                    if packet.len() < ihl + 4 {
                        return Err(anyhow!("TCP/UDP packet too short"));
                    }
                    let source_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    let dest_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    (source_port, dest_port)
                } else {
                    (0, 0)
                };

                Ok((
                    source_ip,
                    dest_ip,
                    source_port,
                    dest_port,
                    if protocol == 6 { Protocol::Tcp } else { Protocol::Udp }
                ))
            }
            6 => {
                // IPv6 parsing (simplified)
                if packet.len() < 40 {
                    return Err(anyhow!("IPv6 packet too short"));
                }

                let protocol = packet[6];
                let mut source_ip_bytes = [0u8; 16];
                let mut dest_ip_bytes = [0u8; 16];
                source_ip_bytes.copy_from_slice(&packet[8..24]);
                dest_ip_bytes.copy_from_slice(&packet[24..40]);

                let source_ip = IpAddr::V6(std::net::Ipv6Addr::from(source_ip_bytes));
                let dest_ip = IpAddr::V6(std::net::Ipv6Addr::from(dest_ip_bytes));

                let (source_port, dest_port) = if protocol == 6 || protocol == 17 {
                    if packet.len() < 44 {
                        return Err(anyhow!("TCP/UDP packet too short"));
                    }
                    let source_port = u16::from_be_bytes([packet[40], packet[41]]);
                    let dest_port = u16::from_be_bytes([packet[42], packet[43]]);
                    (source_port, dest_port)
                } else {
                    (0, 0)
                };

                Ok((
                    source_ip,
                    dest_ip,
                    source_port,
                    dest_port,
                    if protocol == 6 { Protocol::Tcp } else { Protocol::Udp }
                ))
            }
            _ => Err(anyhow!("Unsupported IP version: {}", version)),
        }
    }

    fn extract_dns_query(&self, packet: &[u8]) -> Result<Option<String>> {
        // Basic DNS query parsing (simplified)
        if packet.len() < 12 {
            return Ok(None);
        }

        let mut pos = 12;
        let mut domain = String::new();

        while pos < packet.len() {
            let len = packet[pos] as usize;
            if len == 0 {
                break;
            }
            pos += 1;
            if pos + len > packet.len() {
                return Ok(None);
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(std::str::from_utf8(&packet[pos..pos + len])?);
            pos += len;
        }

        Ok(Some(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_route_manager() -> Result<()> {
        let manager = RouteManager::new();

        // Add some test rules
        manager.add_rule(RouteRule {
            name: "block_ads".to_string(),
            match_type: RouteMatch::Domain {
                pattern: r".*\.ads\..*".to_string(),
                regex: None,
            },
            action: RouteAction::Block,
            priority: 100,
            enabled: true,
            temporary: false,
            expires: None,
        }).await?;

        manager.add_rule(RouteRule {
            name: "direct_local".to_string(),
            match_type: RouteMatch::IpRange {
                network: "192.168.0.0/16".to_string(),
                parsed_network: None,
            },
            action: RouteAction::Direct,
            priority: 90,
            enabled: true,
            temporary: false,
            expires: None,
        }).await?;

        // Test domain matching
        let dns_packet = create_test_dns_packet("test.ads.example.com");
        let action = manager.get_route_action(&dns_packet).await?;
        assert_eq!(action, RouteAction::Block);

        // Test IP matching
        let ip_packet = create_test_ip_packet("192.168.1.100");
        let action = manager.get_route_action(&ip_packet).await?;
        assert_eq!(action, RouteAction::Direct);

        Ok(())
    }

    fn create_test_dns_packet(domain: &str) -> Vec<u8> {
        let mut packet = vec![0u8; 12]; // DNS header
        for part in domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0); // Root label
        packet
    }

    fn create_test_ip_packet(ip: &str) -> Vec<u8> {
        let mut packet = vec![0x45u8]; // IPv4, IHL=5
        packet.extend_from_slice(&[0; 15]); // Padding
        let ip_parts: Vec<u8> = ip.split('.')
            .map(|p| p.parse().unwrap())
            .collect();
        packet.extend_from_slice(&ip_parts);
        packet
    }
} 