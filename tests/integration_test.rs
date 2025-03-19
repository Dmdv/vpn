use anyhow::Result;
use reqwest;
use serde_json::json;
use std::time::Duration;
use tokio;

const API_URL: &str = "http://127.0.0.1:8081";

async fn wait_for_server() {
    let client = reqwest::Client::new();
    for _ in 0..30 {
        if client.get(&format!("{}/health", API_URL))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .is_ok() 
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("Server did not start within 30 seconds");
}

#[tokio::test]
async fn test_server_health() -> Result<()> {
    wait_for_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(&format!("{}/health", API_URL))
        .send()
        .await?;
    
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await?, "OK");
    Ok(())
}

#[tokio::test]
async fn test_profile_creation() -> Result<()> {
    wait_for_server().await;
    
    let client = reqwest::Client::new();
    let response = client.post(&format!("{}/profile/generate", API_URL))
        .json(&json!({
            "device_name": "test-device",
            "preferred_protocol": "tcp"
        }))
        .send()
        .await?;
    
    assert_eq!(response.status(), 200);
    
    let profile: serde_json::Value = response.json().await?;
    assert!(profile.get("profile_id").is_some());
    assert!(profile.get("config").is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_metrics_endpoint() -> Result<()> {
    wait_for_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(&format!("{}/metrics", API_URL))
        .send()
        .await?;
    
    assert_eq!(response.status(), 200);
    
    let metrics: serde_json::Value = response.json().await?;
    assert!(metrics.get("server_metrics").is_some());
    
    Ok(())
} 