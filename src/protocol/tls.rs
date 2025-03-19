use crate::protocol::error::{ProtocolError, ProtocolResult};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, ServerName,
};
use std::sync::Arc;
use tokio_rustls::{TlsConnector, TlsAcceptor};
use std::time::SystemTime;

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub pinned_certs: Vec<Vec<u8>>,
    pub verify_hostname: bool,
}

pub struct CertificatePinner {
    pinned_certs: Vec<Certificate>,
    verify_hostname: bool,
}

impl CertificatePinner {
    pub fn new(pinned_certs: Vec<Vec<u8>>, verify_hostname: bool) -> Self {
        let certs = pinned_certs
            .into_iter()
            .map(Certificate)
            .collect();
        
        Self {
            pinned_certs: certs,
            verify_hostname,
        }
    }
}

impl ServerCertVerifier for CertificatePinner {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Check if the certificate matches any of our pinned certificates
        if !self.pinned_certs.contains(end_entity) {
            return Err(rustls::Error::General("Certificate not in pinned set".into()));
        }

        // Verify hostname if required
        if self.verify_hostname {
            if !webpki::verify_server_name_match(
                end_entity.0.as_ref(),
                server_name.to_owned(),
            ) {
                return Err(rustls::Error::General("Hostname verification failed".into()));
            }
        }

        Ok(ServerCertVerified::assertion())
    }
}

pub struct TlsManager {
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
}

impl TlsManager {
    pub fn new(config: TlsConfig) -> ProtocolResult<Self> {
        // Set up client config with certificate pinning
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(CertificatePinner::new(
                config.pinned_certs,
                config.verify_hostname,
            )))
            .with_no_client_auth();

        // Set up server config
        let cert_file = std::fs::File::open(&config.cert_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open cert file: {}", e)))?;
        let key_file = std::fs::File::open(&config.key_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open key file: {}", e)))?;
        
        let cert_chain = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .map_err(|e| ProtocolError::TlsError(format!("Failed to parse cert: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(key_file))
            .map_err(|e| ProtocolError::TlsError(format!("Failed to parse key: {}", e)))?;

        if keys.is_empty() {
            return Err(ProtocolError::TlsError("No private keys found".to_string()));
        }

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, rustls::PrivateKey(keys.remove(0)))
            .map_err(|e| ProtocolError::TlsError(format!("Failed to create server config: {}", e)))?;

        Ok(Self {
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
        })
    }

    pub fn get_connector(&self) -> TlsConnector {
        TlsConnector::from(self.client_config.clone())
    }

    pub fn get_acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config.clone())
    }
} 