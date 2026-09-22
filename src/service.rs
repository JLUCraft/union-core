use std::{fmt, str::FromStr};

use crate::{AccessPolicy, Error, Result, protocol::ServiceRecord};

/// Stable service identity, separate from the hosting node's PeerId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServiceId(uuid::Uuid);

impl ServiceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ServiceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ServiceId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        uuid::Uuid::parse_str(value)
            .map(Self)
            .map_err(|e| Error::Protocol(e.to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct Service {
    pub id: ServiceId,
    pub name: String,
    pub protocol: String,
    pub access: AccessPolicy,
}

impl Service {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
            || self.protocol.is_empty()
            || self.protocol.len() > 128
            || !self.protocol.is_ascii()
            || self.protocol.chars().any(char::is_control)
        {
            return Err(Error::Protocol("invalid service name or protocol".into()));
        }
        Ok(())
    }

    pub(crate) fn record(&self) -> ServiceRecord {
        ServiceRecord {
            id: self.id.to_string(),
            name: self.name.clone(),
            protocol: self.protocol.clone(),
        }
    }
}
