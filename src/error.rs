#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid identity: {0}")]
    Identity(String),
    #[error("invalid protocol message: {0}")]
    Protocol(String),
    #[error("network: {0}")]
    Network(String),
    #[error("operation timed out")]
    Timeout,
    #[error("node stopped")]
    Stopped,
    #[error("access denied")]
    Denied,
    #[error("service not found")]
    NotFound,
    #[error("resource limit reached")]
    Capacity,
}

pub type Result<T> = std::result::Result<T, Error>;
