mod config;
mod server;
mod tunnel;
mod crypto;
mod profile;
mod auth;
mod metrics;

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .build();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load environment variables from .env file if present
    dotenv::dotenv().ok();

    info!("Starting VPN server...");

    // Initialize server configuration
    let config = config::Config::load()?;
    
    // Start the VPN server
    let server = server::Server::new(config);
    server.run().await?;

    Ok(())
}
