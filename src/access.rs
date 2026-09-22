use std::collections::HashSet;

use libp2p::{PeerId, identity::PublicKey};
use prost::Message;

use crate::{
    Error, Identity, Result, ServiceId,
    protocol::{GrantClaims, GrantEnvelope, MAX_FRAME},
};

const GRANT_DOMAIN: &[u8] = b"jlucraft/union/grant/1\0";

#[derive(Clone, Debug, Default)]
pub enum AccessPolicy {
    #[default]
    Deny,
    Public,
    Peers(HashSet<PeerId>),
    Grants {
        issuers: HashSet<PeerId>,
        revoked: HashSet<String>,
    },
    Students {
        trust: Box<crate::federation::TrustPolicy>,
        minimum: crate::federation::Circle,
        current_enrollment: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub subject: PeerId,
    pub audience: PeerId,
    pub service: ServiceId,
    pub not_before: u64,
    pub expires_at: u64,
}

/// Reusable, holder-bound access grant, not a bearer token or a Minecraft login.
#[derive(Clone)]
pub struct SignedGrant(pub(crate) GrantEnvelope);

impl SignedGrant {
    pub fn issue(issuer: &Identity, grant: Grant) -> Result<Self> {
        if grant.expires_at <= grant.not_before {
            return Err(Error::Protocol(
                "grant expiry must follow not_before".into(),
            ));
        }
        let claims = GrantClaims {
            id: uuid::Uuid::new_v4().to_string(),
            subject: grant.subject.to_bytes(),
            audience: grant.audience.to_bytes(),
            service_id: grant.service.to_string(),
            not_before: grant.not_before,
            expires_at: grant.expires_at,
        }
        .encode_to_vec();
        let signature = issuer
            .0
            .sign(&[GRANT_DOMAIN, &claims].concat())
            .map_err(|e| Error::Identity(e.to_string()))?;
        Ok(Self(GrantEnvelope {
            claims,
            issuer_key: issuer.0.public().encode_protobuf(),
            signature,
        }))
    }

    pub fn encode(&self) -> Vec<u8> {
        self.0.encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Protocol("grant too large".into()));
        }
        GrantEnvelope::decode(bytes)
            .map(Self)
            .map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Inspect only; authorization must always call AccessPolicy::authorize.
    pub fn id(&self) -> Result<String> {
        Ok(GrantClaims::decode(self.0.claims.as_slice())
            .map_err(|e| Error::Protocol(e.to_string()))?
            .id)
    }
}

impl AccessPolicy {
    pub fn authorize(
        &self,
        peer: PeerId,
        audience: PeerId,
        service: ServiceId,
        grant: Option<&SignedGrant>,
        now: u64,
    ) -> Result<()> {
        match self {
            Self::Public => Ok(()),
            Self::Peers(peers) if peers.contains(&peer) => Ok(()),
            Self::Grants { issuers, revoked } => {
                let envelope = &grant.ok_or(Error::Denied)?.0;
                let key = PublicKey::try_decode_protobuf(&envelope.issuer_key)
                    .map_err(|_| Error::Denied)?;
                if !issuers.contains(&key.to_peer_id())
                    || !key.verify(
                        &[GRANT_DOMAIN, &envelope.claims].concat(),
                        &envelope.signature,
                    )
                {
                    return Err(Error::Denied);
                }
                let claims =
                    GrantClaims::decode(envelope.claims.as_slice()).map_err(|_| Error::Denied)?;
                if claims.subject != peer.to_bytes()
                    || claims.audience != audience.to_bytes()
                    || claims.service_id != service.to_string()
                    || claims.not_before > now
                    || claims.expires_at <= now
                    || claims.expires_at <= claims.not_before
                    || revoked.contains(&claims.id)
                    || uuid::Uuid::parse_str(&claims.id).is_err()
                {
                    return Err(Error::Denied);
                }
                Ok(())
            }
            _ => Err(Error::Denied),
        }
    }
}
