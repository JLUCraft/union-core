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
    #[error("current authorization cannot be confirmed; synchronize identity history")]
    AuthorityUnavailable,
    #[error("access denied")]
    Denied,
    #[error("service not found")]
    NotFound,
    #[error("resource limit reached")]
    Capacity,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Malformed or unacceptable protocol data, keeping only the cause's message.
    pub fn protocol(cause: impl std::fmt::Display) -> Self {
        Self::Protocol(cause.to_string())
    }
    pub fn failure(&self) -> crate::protocol::ClientFailure {
        use crate::protocol::ClientErrorCode as Code;
        let code = match self {
            Self::Identity(_) => Code::IdentityUnavailable,
            Self::AuthorityUnavailable => Code::AuthorityUnavailable,
            Self::Denied => Code::AccessDenied,
            Self::Protocol(_) => Code::InvalidRequest,
            Self::Network(_) | Self::Stopped => Code::Network,
            Self::Timeout => Code::Timeout,
            Self::NotFound => Code::NotFound,
            Self::Capacity => Code::Capacity,
            Self::Io(_) => Code::OperationFailed,
        };
        crate::protocol::ClientFailure {
            code,
            message: self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_codes_do_not_depend_on_diagnostic_text() {
        use crate::protocol::ClientErrorCode;
        assert_eq!(
            Error::AuthorityUnavailable.failure().code,
            ClientErrorCode::AuthorityUnavailable
        );
        assert_eq!(
            Error::Protocol("current authorization".into())
                .failure()
                .code,
            ClientErrorCode::InvalidRequest
        );
        let encoded = serde_json::to_value(Error::Denied.failure()).expect("serialize failure");
        assert_eq!(encoded["code"], "access_denied");
    }
}
