//! Institutional identity is delegated independently of infrastructure ownership.
//! Trust circles are computed by each relying service, never accepted from clients.
use crate::{Error, Identity, PeerId, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Circle {
    Unknown,
    Mua,
    Province,
    Local,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    InstitutionalEmail,
    MuaStudentVerification,
    MuaAccountOnly,
    CurrentEnrollment,
    Alumni,
}

/// Student-only delegation: this wire type cannot grant management/consensus roles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StudentDelegation {
    pub id: String,
    pub school: String,
    pub issuer: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub max_credential_seconds: u64,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StudentClaims {
    pub id: String,
    pub school: String,
    pub subject: String,
    pub game_profile: String,
    pub holder: String,
    pub evidence: Evidence,
    pub verified_at: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDocument {
    pub payload: Vec<u8>,
    pub key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedDocument {
    fn sign<T: Serialize>(identity: &Identity, domain: &[u8], value: &T) -> Result<Self> {
        let payload = serde_json::to_vec(value).map_err(protocol)?;
        let signature = identity
            .0
            .sign(&[domain, &payload].concat())
            .map_err(protocol)?;
        Ok(Self {
            payload,
            key: identity.0.public().encode_protobuf(),
            signature,
        })
    }
    fn verify<T: serde::de::DeserializeOwned>(&self, domain: &[u8]) -> Result<(PeerId, T)> {
        if self.payload.len() > 16 * 1024 {
            return Err(Error::Capacity);
        }
        let key = libp2p::identity::PublicKey::try_decode_protobuf(&self.key)
            .map_err(|_| Error::Denied)?;
        if !key.verify(&[domain, &self.payload].concat(), &self.signature) {
            return Err(Error::Denied);
        }
        Ok((
            key.to_peer_id(),
            serde_json::from_slice(&self.payload).map_err(protocol)?,
        ))
    }
}

const DELEGATION: &[u8] = b"jlucraft/student-delegation/1\0";
const STUDENT: &[u8] = b"jlucraft/student-credential/1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StudentCredential {
    pub delegation: SignedDocument,
    pub student: SignedDocument,
}

/// Transport admission evidence. The game proxy must independently match the
/// authenticated Minecraft profile to these verified claims before entering play.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StudentPresentation {
    pub credential: StudentCredential,
    pub profile: String,
}

pub fn delegate(root: &Identity, claims: StudentDelegation) -> Result<SignedDocument> {
    SignedDocument::sign(root, DELEGATION, &claims)
}

pub fn issue(
    issuer: &Identity,
    delegation: SignedDocument,
    claims: StudentClaims,
) -> Result<StudentCredential> {
    Ok(StudentCredential {
        delegation,
        student: SignedDocument::sign(issuer, STUDENT, &claims)?,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub local_school: String,
    pub province_schools: BTreeSet<String>,
    pub mua_schools: BTreeSet<String>,
    /// Authenticated, explicitly configured school roots. Membership sets alone grant no trust.
    pub school_roots: BTreeMap<String, BTreeSet<String>>,
    pub revoked: BTreeSet<String>,
    pub max_verification_age_seconds: u64,
}

impl TrustPolicy {
    pub fn verify(
        &self,
        credential: &StudentCredential,
        holder: PeerId,
        profile: &str,
        now: u64,
    ) -> Result<(Circle, StudentClaims)> {
        let (root, delegation): (PeerId, StudentDelegation) =
            credential.delegation.verify(DELEGATION)?;
        let (issuer, claims): (PeerId, StudentClaims) = credential.student.verify(STUDENT)?;
        if !self
            .school_roots
            .get(&delegation.school)
            .is_some_and(|roots| roots.contains(&root.to_string()))
            || delegation.issuer != issuer.to_string()
            || claims.school != delegation.school
            || claims.holder != holder.to_string()
            || claims.game_profile != profile
            || claims.subject.is_empty()
            || claims.id.is_empty()
            || delegation.id.is_empty()
            || self.revoked.contains(&delegation.id)
            || self.revoked.contains(&claims.id)
            || self.revoked.contains(&delegation.issuer)
            || delegation.not_before > now
            || delegation.expires_at <= now
            || claims.issued_at < delegation.not_before
            || claims.issued_at > now
            || claims.expires_at <= now
            || claims.expires_at > delegation.expires_at
            || claims.expires_at <= claims.issued_at
            || claims.expires_at - claims.issued_at > delegation.max_credential_seconds
            || claims.verified_at > claims.issued_at
            || now.saturating_sub(claims.verified_at) > self.max_verification_age_seconds
            || !delegation.evidence.contains(&claims.evidence)
        {
            return Err(Error::Denied);
        }
        let circle = if matches!(claims.evidence, Evidence::MuaAccountOnly | Evidence::Alumni) {
            Circle::Unknown
        } else if claims.school == self.local_school {
            Circle::Local
        } else if self.province_schools.contains(&claims.school) {
            Circle::Province
        } else if self.mua_schools.contains(&claims.school) {
            Circle::Mua
        } else {
            Circle::Unknown
        };
        Ok((circle, claims))
    }

    /// Email ownership establishes affiliation, not current enrollment. Leagues
    /// requiring current students must explicitly use this stricter admission check.
    pub fn verify_current_student(
        &self,
        credential: &StudentCredential,
        holder: PeerId,
        profile: &str,
        now: u64,
    ) -> Result<(Circle, StudentClaims)> {
        let result = self.verify(credential, holder, profile, now)?;
        if !matches!(
            result.1.evidence,
            Evidence::CurrentEnrollment | Evidence::MuaStudentVerification
        ) {
            return Err(Error::Denied);
        }
        Ok(result)
    }
}

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}
