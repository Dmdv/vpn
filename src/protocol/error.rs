use std::error::Error;
use std::fmt;
use std::io;
use std::array::TryFromSliceError;

#[derive(Debug)]
pub enum ProtocolError {
    ConfigError(String),
    ConnectionError(String),
    ConnectionTimeout(u64),
    HandshakeFailed(String),
    TlsError(String),
    IoError(io::Error),
    ObfuscationError(String),
    Other(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            ProtocolError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            ProtocolError::ConnectionTimeout(secs) => write!(f, "Connection timed out after {} seconds", secs),
            ProtocolError::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            ProtocolError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            ProtocolError::IoError(err) => write!(f, "I/O error: {}", err),
            ProtocolError::ObfuscationError(msg) => write!(f, "Obfuscation error: {}", msg),
            ProtocolError::Other(err) => write!(f, "Other error: {}", err),
        }
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProtocolError::IoError(err) => Some(err),
            ProtocolError::Other(err) => err.source(),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(err: io::Error) -> Self {
        ProtocolError::IoError(err)
    }
}

impl From<TryFromSliceError> for ProtocolError {
    fn from(err: TryFromSliceError) -> Self {
        ProtocolError::Other(Box::new(err))
    }
}

impl From<Box<dyn Error + Send + Sync>> for ProtocolError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        ProtocolError::Other(err)
    }
}

pub type ProtocolResult<T> = Result<T, ProtocolError>; 