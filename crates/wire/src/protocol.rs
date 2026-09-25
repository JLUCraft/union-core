//! Version 1 wire types. These `derive(Message)` definitions are the canonical wire schema.
/// Shared human-readable identifier syntax. Protocol names additionally require ASCII.
pub fn validate_identifier(value: &str) -> crate::Result<()> {
    const MAX_IDENTIFIER_BYTES: usize = 128;
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(crate::Error::Denied);
    }
    Ok(())
}

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const DIRECTORY_PROTOCOL: &str = "/jlucraft/union/directory/1";
pub const GOVERNANCE_PROTOCOL: &str = "/jlucraft/union/governance/3";
pub const EVENTS_PROTOCOL: &str = "/jlucraft/union/events/1";
pub const RAFT_PROTOCOL: &str = "/jlucraft/union/raft/1";
pub const LLM_PROTOCOL: &str = "/jlucraft/union/llm/1";
pub const OPS_PROTOCOL: &str = "jlucraft/federated-ops/1";
pub const SESSION_PROTOCOL: &str = "/jlucraft/union/session/1";
pub const MAX_FRAME: usize = 64 * 1024;
pub const MAX_SERVICE_METADATA: usize = 512;
pub const MAX_DIRECTORY_ADDRESSES: usize = 8;
pub const MAX_DIRECTORY_ADDRESS_BYTES: usize = 1024;
const MAX_ROOM_TEXT_BYTES: usize = 128;
pub const ROOM_PROTOCOL: &str = "minecraft/java/tcp";
pub const MAX_SERVICES: usize = 64;

#[derive(Clone, PartialEq, Message)]
pub struct DirectoryRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ServiceRecord {
    /// Bounded application JSON; directory claims confer no authority.
    #[prost(bytes = "vec", tag = "4")]
    pub metadata: Vec<u8>,
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub protocol: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct DirectoryResponse {
    #[prost(string, repeated, tag = "2")]
    pub addresses: Vec<String>,
    #[prost(message, repeated, tag = "1")]
    pub services: Vec<ServiceRecord>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OpenRequest {
    #[prost(string, tag = "1")]
    pub service_id: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct OpenResponse {
    #[prost(enumeration = "Status", tag = "1")]
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Status {
    Unspecified = 0,
    Accepted = 1,
    Denied = 2,
    NotFound = 3,
    Busy = 4,
    AuthorityUnavailable = 5,
}

/// A four-byte big-endian size followed by protobuf; bounded before allocation.
pub async fn read_frame<M: Message + Default>(reader: &mut (impl AsyncRead + Unpin)) -> Result<M> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_FRAME {
        return Err(Error::Protocol("frame too large".into()));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).await?;
    M::decode(bytes.as_slice()).map_err(|e| Error::Protocol(e.to_string()))
}

pub async fn write_frame<M: Message>(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &M,
) -> Result<()> {
    let size = message.encoded_len();
    if size > MAX_FRAME {
        return Err(Error::Protocol("frame too large".into()));
    }
    writer.write_all(&(size as u32).to_be_bytes()).await?;
    writer.write_all(&message.encode_to_vec()).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Clone, PartialEq, Message)]
pub struct JsonFrame {
    #[prost(bytes = "vec", tag = "1")]
    pub json: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub sequence: u32,
    #[prost(bool, tag = "3")]
    pub last: bool,
}

/// SHA-256 encoded as lowercase hexadecimal for canonical JSON commitments.
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Text-only LLM schema. Provider-specific parameters never cross this boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmMessage {
    pub role: String,
    pub content: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privacy {
    Public,
    Sensitive,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    /// Factual payload for purposes whose prompt template the gateway owns;
    /// the client never sees or composes the template itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub stream: bool,
    pub max_tokens: u32,
    pub purpose: String,
    pub privacy: Privacy,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LlmUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LlmFrame {
    Delta {
        content: String,
    },
    Done {
        usage: Option<LlmUsage>,
        truncated: bool,
    },
    Error {
        error: String,
        truncated: bool,
    },
}

/// Identity-authorized, content-addressed documents.
pub const DOCUMENT_PROTOCOL: &str = "/jlucraft/union/documents/1";
#[derive(Clone, PartialEq, Message)]
pub struct DocumentRequest {
    #[prost(string, tag = "1")]
    pub hash: String,
}
#[derive(Clone, PartialEq, Message)]
pub struct DocumentChunk {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub sequence: u32,
    #[prost(bool, tag = "3")]
    pub last: bool,
}

// Federated-server operations schema. One request frame, one response frame; no streaming.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpsOp {
    ListInstances {},
    Status { instance: String },
    Start { instance: String },
    Stop { instance: String },
    Restart { instance: String },
    Kill { instance: String },
    Logs { instance: String },
}
/// The operation owns its target; there is no second, potentially conflicting instance field.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsRequest {
    pub op: OpsOp,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpsInstanceState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Busy,
    Error,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsInstance {
    pub id: String,
    pub kind: String,
    pub state: OpsInstanceState,
    /// Nonnegative ping player count; adapters must validate signed backend counts.
    pub players_online: u32,
    pub players_max: u32,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<OpsInstance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_metadata_is_bounded_and_strict() {
        let room = RoomMetadata {
            school: "a".into(),
            version: "26.3".into(),
            players_max: 12,
        };
        room.validate().unwrap();
        let value = serde_json::to_value(&room).unwrap();
        assert_eq!(
            serde_json::from_value::<RoomMetadata>(value.clone()).unwrap(),
            room
        );
        let mut unknown = value;
        unknown["admin"] = true.into();
        assert!(serde_json::from_value::<RoomMetadata>(unknown).is_err());
        for room in [
            RoomMetadata {
                school: String::new(),
                ..room.clone()
            },
            RoomMetadata {
                version: "x".repeat(MAX_ROOM_TEXT_BYTES + 1),
                ..room.clone()
            },
            RoomMetadata {
                players_max: 0,
                ..room
            },
        ] {
            assert!(room.validate().is_err());
        }
    }

    fn sample_instance() -> OpsInstance {
        OpsInstance {
            id: "survival-1".into(),
            kind: "java".into(),
            state: OpsInstanceState::Running,
            players_online: 5,
            players_max: 20,
            version: "1.20.4".into(),
            description: Some("A Minecraft Server".into()),
        }
    }

    #[test]
    fn ops_request_roundtrip() {
        for op in [
            OpsOp::ListInstances {},
            OpsOp::Status {
                instance: "a".into(),
            },
            OpsOp::Start {
                instance: "a".into(),
            },
            OpsOp::Stop {
                instance: "a".into(),
            },
            OpsOp::Restart {
                instance: "a".into(),
            },
            OpsOp::Kill {
                instance: "a".into(),
            },
            OpsOp::Logs {
                instance: "a".into(),
            },
        ] {
            let request = OpsRequest { op };
            let json = serde_json::to_string(&request).unwrap();
            let parsed: OpsRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(request, parsed);
        }
    }

    #[test]
    fn ops_op_serializes_with_snake_case_tag() {
        let json = serde_json::to_string(&OpsRequest {
            op: OpsOp::ListInstances {},
        })
        .unwrap();
        assert_eq!(json, r#"{"op":{"op":"list_instances"}}"#);
        let json = serde_json::to_string(&OpsRequest {
            op: OpsOp::Restart {
                instance: "a".into(),
            },
        })
        .unwrap();
        assert_eq!(json, r#"{"op":{"op":"restart","instance":"a"}}"#);
    }

    #[test]
    fn ops_response_roundtrip() {
        let response = OpsResponse {
            ok: true,
            instances: vec![sample_instance()],
            logs: None,
            error: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"ok":true,"instances":[{"id":"survival-1","kind":"java","state":"running","players_online":5,"players_max":20,"version":"1.20.4","description":"A Minecraft Server"}]}"#
        );
        let parsed: OpsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, parsed);
    }

    #[test]
    fn ops_response_with_logs_and_error() {
        let response = OpsResponse {
            ok: false,
            instances: Vec::new(),
            logs: Some("booting...".into()),
            error: Some("instance locked".into()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"ok":false,"logs":"booting...","error":"instance locked"}"#
        );
        let parsed: OpsResponse = serde_json::from_str(&json).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.logs.as_deref(), Some("booting..."));
        assert_eq!(parsed.error.as_deref(), Some("instance locked"));
    }

    #[test]
    fn ops_request_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<OpsRequest>(r#"{"op":{"op":"start","instance":"a"},"extra":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<OpsRequest>(r#"{"op":{"op":"start","instance":"a","extra":1}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<OpsRequest>(r#"{"op":{"op":"nuke","instance":"a"}}"#).is_err()
        );
    }

    #[test]
    fn ops_request_rejects_missing_targets_and_unit_payloads() {
        for op in ["status", "start", "stop", "restart", "kill", "logs"] {
            for payload in [
                serde_json::json!({"op": {"op": op}}),
                serde_json::json!({"op": {"op": op, "instance": null}}),
                serde_json::json!({"op": {"op": op, "instance": "a", "extra": true}}),
            ] {
                assert!(serde_json::from_value::<OpsRequest>(payload).is_err());
            }
        }
        assert!(
            serde_json::from_str::<OpsRequest>(r#"{"op":{"op":"list_instances","instance":"a"}}"#)
                .is_err()
        );
    }

    #[test]
    fn ops_instance_states_roundtrip() {
        for (state, name) in [
            (OpsInstanceState::Stopped, "stopped"),
            (OpsInstanceState::Starting, "starting"),
            (OpsInstanceState::Running, "running"),
            (OpsInstanceState::Stopping, "stopping"),
            (OpsInstanceState::Busy, "busy"),
            (OpsInstanceState::Error, "error"),
        ] {
            let mut instance = sample_instance();
            instance.state = state;
            let value = serde_json::to_value(&instance).unwrap();
            assert_eq!(value["state"], name);
            assert_eq!(
                serde_json::from_value::<OpsInstance>(value).unwrap(),
                instance
            );
        }
    }

    #[test]
    fn ops_instance_rejects_unknown_fields_and_bad_state() {
        let json = serde_json::to_string(&sample_instance()).unwrap();
        assert!(
            serde_json::from_str::<OpsInstance>(
                &json.replace("\"kind\":\"java\"", "\"kind\":\"java\",\"extra\":true")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OpsInstance>(&json.replace("\"running\"", "\"onfire\""))
                .is_err()
        );
        assert_eq!(
            serde_json::from_str::<OpsInstance>(
                &json.replace(r#","description":"A Minecraft Server""#, "")
            )
            .unwrap()
            .description,
            None
        );
    }

    #[test]
    fn ops_response_rejects_unknown_fields() {
        let response = OpsResponse {
            ok: true,
            ..OpsResponse::default()
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(
            serde_json::from_str::<OpsResponse>(
                &json.replace("\"ok\":true", "\"ok\":true,\"extra\":1")
            )
            .is_err()
        );
    }
}

/// Host-asserted display metadata. Authentication uses delegated credentials only.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomMetadata {
    pub school: String,
    pub version: String,
    pub players_max: u32,
}

impl RoomMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.school.is_empty()
            || self.school.len() > MAX_ROOM_TEXT_BYTES
            || self.version.is_empty()
            || self.version.len() > MAX_ROOM_TEXT_BYTES
            || self.school.chars().any(char::is_control)
            || self.version.chars().any(char::is_control)
            || self.players_max == 0
        {
            return Err(Error::Protocol("invalid room metadata".into()));
        }
        Ok(())
    }
}

/// CIDv1, SHA2-256; this profile supports raw (0x55) and DAG-JSON (0x0129).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct Cid(pub(crate) String);
impl<'de> serde::Deserialize<'de> for Cid {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(decoder)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpldLink {
    #[serde(rename = "/")]
    pub cid: Cid,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpldBlock {
    pub cid: Cid,
    pub data: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileLayout {
    Full {
        tree: IpldLink,
    },
    Diff {
        offset: u64,
        remove: u64,
        insert: IpldLink,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileNode {
    Chunks {
        children: Vec<IpldLink>,
    },
    File {
        parent: Option<IpldLink>,
        size: u64,
        checksum: String,
        depth: u32,
        layout: FileLayout,
    },
    Commit {
        parent: Option<IpldLink>,
        files: std::collections::BTreeMap<String, IpldLink>,
        message: String,
    },
}

/// Unified, explicitly revoked federation identity history. No qualification expires.
pub const TRUST_PROTOCOL: &str = "/jlucraft/union/trust/1";
pub const TRUST_SIGNING_DOMAIN: &[u8] = b"jlucraft/union/trust/1\0";
pub const MAX_TRUST_RECORD: usize = 48 * 1024;
pub const MAX_TRUST_PAGE: usize = 64;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustFounder {
    pub member: String,
    pub club: String,
    pub public_key: Vec<u8>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustGenesis {
    pub federation: String,
    pub founders: Vec<TrustFounder>,
    pub quorum: usize,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustSignature {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRecord {
    pub federation: String,
    pub genesis: String,
    pub sequence: u64,
    pub previous: String,
    pub action: TrustAction,
    pub signatures: Vec<TrustSignature>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustAction {
    ConfirmMember {
        member: String,
        club: String,
        device: Option<String>,
        evidence: String,
        verifier: Option<String>,
    },
    RevokeMembership {
        member: String,
        club: String,
    },
    BindDevice {
        member: String,
        device: String,
    },
    BindGameProfile {
        member: String,
        club: String,
        profile: String,
    },
    RevokeDevice {
        member: String,
        device: String,
    },
    ProposeSuccession {
        id: String,
        chairs: std::collections::BTreeMap<String, String>,
        quorum: usize,
    },
    ApproveSuccession {
        id: String,
    },
    ExecuteSuccession {
        id: String,
    },
    CancelSuccession {
        id: String,
    },
    ReplaceChairs {
        chairs: std::collections::BTreeMap<String, String>,
        quorum: usize,
    },
    AuthorizeVerifier {
        id: String,
        club: String,
        device: String,
        evidence: std::collections::BTreeSet<String>,
    },
    RevokeVerifier {
        id: String,
    },
    RegisterService {
        service: String,
        audience: String,
        club: String,
    },
    GrantPermission {
        id: String,
        member: String,
        service: String,
        permission: String,
    },
    RevokePermission {
        id: String,
    },
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustCheckpoint {
    pub genesis: String,
    pub sequence: u64,
    pub head: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)] // Keep the signed wire record directly available to callers.
pub enum TrustRequest {
    Read { checkpoint: TrustCheckpoint },
    Append { record: TrustRecord },
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustResponse {
    pub checkpoint: TrustCheckpoint,
    pub records: Vec<TrustRecord>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRequirement {
    /// Empty means no membership requirement; otherwise one listed club is required.
    pub clubs: std::collections::BTreeSet<String>,
    /// A service-scoped permission, evaluated independently of membership.
    pub permission: Option<String>,
}

/// A business chain pins the unified identity genesis but keeps its own service/role boundary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBusinessBinding {
    pub genesis: String,
    pub namespace: String,
    pub audience: String,
    pub service: String,
    pub club: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAdmission {
    pub member: String,
    pub clubs: std::collections::BTreeSet<String>,
    pub game_profile: Option<String>,
}

#[cfg(test)]
mod identifier_tests {
    use super::validate_identifier;
    #[test]
    fn identifiers_have_shared_whitespace_control_and_byte_limits() {
        for invalid in ["", " ", "\n", "a\0b", &"x".repeat(129)] {
            assert!(validate_identifier(invalid).is_err());
        }
        for valid in ["member-a", "社团", &"x".repeat(128)] {
            assert!(validate_identifier(valid).is_ok());
        }
    }
}

/// Stable application error classification for native/UI boundaries. Messages are diagnostic only.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientErrorCode {
    IdentityNotConfigured,
    IdentityUnavailable,
    AuthorityUnavailable,
    AccessDenied,
    InvalidRequest,
    Network,
    Timeout,
    NotFound,
    Capacity,
    OperationFailed,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFailure {
    pub code: ClientErrorCode,
    pub message: String,
}
impl From<String> for ClientFailure {
    fn from(message: String) -> Self {
        Self {
            code: ClientErrorCode::OperationFailed,
            message,
        }
    }
}
impl From<&str> for ClientFailure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
