//! Shared presentation inputs for native management terminals. Protocol actions are the source of truth.
use crate::protocol::{TrustAction, TrustFounder, TrustGenesis, TrustRecord, validate_identifier};
use crate::trust::{Config, TrustState};
use crate::{Error, Identity, PeerId, Result, ServiceId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
pub struct ActionForm {
    pub action: String,
    pub fields: Vec<Field>,
}
#[derive(Serialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub optional: bool,
    pub generated: bool,
    pub choices: Vec<&'static str>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Peer,
    Profile,
    Number,
    Choices,
    Chairs,
}

// These are empty form templates, not identities or sample production records. Serializing the
// actual protocol enum keeps field names, action names and collection shapes tied to that definition.
fn templates() -> Vec<TrustAction> {
    let empty = String::new;
    vec![
        TrustAction::ConfirmMember {
            member: empty(),
            club: empty(),
            device: None,
            evidence: "manual".into(),
            verifier: None,
        },
        TrustAction::RevokeMembership {
            member: empty(),
            club: empty(),
        },
        TrustAction::BindDevice {
            member: empty(),
            device: empty(),
        },
        TrustAction::BindGameProfile {
            member: empty(),
            club: empty(),
            profile: empty(),
        },
        TrustAction::RevokeDevice {
            member: empty(),
            device: empty(),
        },
        TrustAction::RegisterService {
            service: empty(),
            audience: empty(),
            club: empty(),
        },
        TrustAction::GrantPermission {
            id: empty(),
            member: empty(),
            service: empty(),
            permission: empty(),
        },
        TrustAction::RevokePermission { id: empty() },
        TrustAction::AuthorizeVerifier {
            id: empty(),
            club: empty(),
            device: empty(),
            evidence: BTreeSet::new(),
        },
        TrustAction::RevokeVerifier { id: empty() },
        TrustAction::ProposeSuccession {
            id: empty(),
            chairs: BTreeMap::new(),
            quorum: 0,
        },
        TrustAction::ApproveSuccession { id: empty() },
        TrustAction::ExecuteSuccession { id: empty() },
        TrustAction::CancelSuccession { id: empty() },
    ]
}
fn template(action: &str) -> Result<Value> {
    for value in templates() {
        let value = serde_json::to_value(value).map_err(Error::protocol)?;
        if value["type"] == action {
            return Ok(value);
        }
    }
    Err(Error::Denied)
}
fn form(value: &Value) -> Result<ActionForm> {
    let action = value["type"].as_str().ok_or(Error::Denied)?;
    let mut fields = Vec::new();
    for (name, value) in value.as_object().ok_or(Error::Denied)? {
        if name == "type"
            || (action == "confirm_member" && matches!(name.as_str(), "evidence" | "verifier"))
        {
            continue;
        }
        fields.push(Field {
            name: name.clone(),
            optional: action == "confirm_member" && name == "device",
            generated: matches!(
                (action, name.as_str()),
                ("register_service", "service")
                    | (
                        "grant_permission" | "authorize_verifier" | "propose_succession",
                        "id"
                    )
            ),
            choices: if name == "evidence" {
                vec!["institutional_email", "game_profile"]
            } else {
                vec![]
            },
            kind: match name.as_str() {
                "device" | "audience" => FieldKind::Peer,
                "profile" => FieldKind::Profile,
                _ if value.is_number() => FieldKind::Number,
                _ if value.is_array() => FieldKind::Choices,
                _ if value.is_object() => FieldKind::Chairs,
                _ => FieldKind::Text,
            },
        });
    }
    Ok(ActionForm {
        action: action.into(),
        fields,
    })
}
pub fn forms() -> Result<Vec<ActionForm>> {
    templates()
        .into_iter()
        .map(|value| form(&serde_json::to_value(value).map_err(Error::protocol)?))
        .collect()
}
pub fn build_action(action: &str, fields: Map<String, Value>) -> Result<TrustAction> {
    let mut value = template(action)?;
    let form = form(&value)?;
    if fields
        .keys()
        .any(|key| !form.fields.iter().any(|f| &f.name == key))
    {
        return Err(Error::Denied);
    }
    for field in form.fields {
        let input = fields.get(&field.name).cloned().unwrap_or(Value::Null);
        let input = match field.kind {
            FieldKind::Text | FieldKind::Peer | FieldKind::Profile => {
                let text = if input.is_null() && field.optional {
                    ""
                } else {
                    let value = input.as_str().ok_or(Error::Denied)?;
                    if matches!(field.kind, FieldKind::Text) {
                        value
                    } else {
                        value.trim()
                    }
                };
                if field.optional && (input.is_null() || text.is_empty()) {
                    Value::Null
                } else {
                    validate_identifier(text)?;
                    match field.kind {
                        FieldKind::Peer => {
                            text.parse::<PeerId>().map_err(Error::protocol)?;
                        }
                        FieldKind::Profile => crate::protocol::validate_game_profile(text)?,
                        _ => {}
                    }
                    Value::String(text.into())
                }
            }
            FieldKind::Number => {
                let number = input.as_u64().ok_or(Error::Denied)?;
                if number == 0 {
                    return Err(Error::Denied);
                }
                number.into()
            }
            FieldKind::Choices => {
                let values = input.as_array().ok_or(Error::Denied)?;
                if values.is_empty() {
                    return Err(Error::Denied);
                }
                let mut choices = BTreeSet::new();
                for value in values {
                    let text = value.as_str().ok_or(Error::Denied)?;
                    if !field.choices.contains(&text) || !choices.insert(text) {
                        return Err(Error::Denied);
                    }
                }
                input
            }
            FieldKind::Chairs => {
                let chairs = input.as_object().ok_or(Error::Denied)?;
                if chairs.is_empty() {
                    return Err(Error::Denied);
                }
                for (club, member) in chairs {
                    validate_identifier(club)?;
                    validate_identifier(member.as_str().ok_or(Error::Denied)?)?;
                }
                input
            }
        };
        value[&field.name] = input;
    }
    if let Some(chairs) = value.get("chairs") {
        let chairs: BTreeMap<String, String> =
            serde_json::from_value(chairs.clone()).map_err(Error::protocol)?;
        let quorum = value["quorum"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(Error::Denied)?;
        identity::trust::validate_chairs(&chairs, quorum)?;
    }
    serde_json::from_value(value).map_err(Error::protocol)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub peer: String,
    #[serde(
        serialize_with = "serialize_public_key",
        deserialize_with = "deserialize_public_key"
    )]
    pub public_key: Vec<u8>,
}
fn serialize_public_key<S: serde::Serializer>(
    key: &[u8],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex_encode(key))
}
fn deserialize_public_key<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct PublicKeyVisitor;
    impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a lowercase hex string or an array of byte values")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Vec<u8>, E> {
            decode_hex(value).map_err(serde::de::Error::custom)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_any(PublicKeyVisitor)
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_hex(text: &str) -> std::result::Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut chars = text.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = high
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex character: {high}"))?;
        let low = low
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex character: {low}"))?;
        bytes.push((high * 16 + low) as u8);
    }
    Ok(bytes)
}
impl PublicIdentity {
    pub fn from_identity(identity: &Identity) -> Self {
        Self {
            peer: identity.peer_id().to_string(),
            public_key: identity.public_key().encode_protobuf(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        let key =
            identity::PublicKey::try_decode_protobuf(&self.public_key).map_err(Error::protocol)?;
        key.clone().try_into_ed25519().map_err(Error::protocol)?;
        if key.to_peer_id().to_string() != self.peer {
            return Err(Error::Denied);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FounderInput {
    pub member: String,
    pub club: String,
    pub identity: PublicIdentity,
}
pub fn build_genesis(
    federation: String,
    founders: Vec<FounderInput>,
    quorum: usize,
) -> Result<Value> {
    let founders = founders
        .into_iter()
        .map(|founder| {
            founder.identity.validate()?;
            Ok(TrustFounder {
                member: founder.member,
                club: founder.club,
                public_key: founder.identity.public_key,
            })
        })
        .collect::<Result<_>>()?;
    review_genesis(TrustGenesis {
        federation,
        founders,
        quorum,
    })
}
pub fn review_genesis(genesis: TrustGenesis) -> Result<Value> {
    let hash = TrustState::genesis_digest(&genesis)?;
    TrustState::new(&genesis, &hash)?;
    Ok(json!({"genesis":genesis,"genesis_hash":hash}))
}
pub fn review_config(config: &Config) -> Result<Value> {
    TrustState::new(&config.genesis, &config.genesis_hash)?;
    crate::endpoint(&config.address, &config.peer)?;
    // Never share another terminal's private filesystem/cache path.
    Ok(
        json!({"genesis":config.genesis,"genesis_hash":config.genesis_hash,"address":config.address,"peer":config.peer}),
    )
}
pub fn review_record(genesis: &TrustGenesis, pin: &str, record: &TrustRecord) -> Result<Value> {
    TrustState::new(genesis, pin)?;
    if record.genesis != pin || record.federation != genesis.federation || record.sequence == 0 {
        return Err(Error::Denied);
    }
    crate::protocol::validate_digest(&record.previous)?;
    if !record.signatures.is_empty() {
        identity::trust::verify_signatures(record)?;
    }
    serde_json::to_value(record).map_err(Error::protocol)
}
pub fn sign_offline(
    identity: &Identity,
    config: &Config,
    mut record: TrustRecord,
) -> Result<Value> {
    review_record(&config.genesis, &config.genesis_hash, &record)?;
    crate::trust::sign(&mut record, identity)?;
    serde_json::to_value(record).map_err(Error::protocol)
}

pub fn build_anchor(id: String, digest: String) -> Result<Value> {
    validate_identifier(&id)?;
    crate::protocol::validate_digest(&digest)?;
    serde_json::to_value(
        state::governance::Action::<state::EmptyDomain>::AnchorDigest { id, digest },
    )
    .map_err(Error::protocol)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaInput {
    // JSON/JS numbers cannot represent every u64 node ID without rounding.
    pub id: String,
    pub node: state::governance::ConsensusPeer,
}
pub fn build_roles(member: String, roles: Vec<String>) -> Result<Value> {
    validate_identifier(&member)?;
    let roles: BTreeSet<_> = roles.into_iter().collect();
    state::governance::validate_member_roles(&roles)?;
    serde_json::to_value(
        state::governance::Action::<state::EmptyDomain>::SetMemberRoles { member, roles },
    )
    .map_err(Error::protocol)
}
pub fn build_consensus(members: Vec<ReplicaInput>) -> Result<Value> {
    let mut peers = BTreeMap::new();
    for member in members {
        let id: u64 = member.id.parse().map_err(|_| Error::Denied)?;
        if id.to_string() != member.id {
            return Err(Error::Denied);
        }
        if peers.insert(id, member.node).is_some() {
            return Err(Error::Denied);
        }
    }
    state::governance::validate_consensus_members(&peers)?;
    serde_json::to_value(
        state::governance::Action::<state::EmptyDomain>::SetConsensusMembers { members: peers },
    )
    .map_err(Error::protocol)
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Forms,
    BuildAction {
        action: String,
        fields: Map<String, Value>,
    },
    BuildGenesis {
        federation: String,
        founders: Vec<FounderInput>,
        quorum: usize,
    },
    ReviewGenesis {
        genesis: TrustGenesis,
    },
    ReviewConfiguration {
        config: Config,
    },
    ReviewRecord {
        genesis: TrustGenesis,
        genesis_hash: String,
        record: TrustRecord,
    },
    BuildAnchor {
        id: String,
        digest: String,
    },
    BuildRoles {
        member: String,
        roles: Vec<String>,
    },
    BuildConsensus {
        members: Vec<ReplicaInput>,
    },
    NewServiceId,
}
pub fn execute(request: Request) -> Result<Value> {
    match request {
        Request::Forms => serde_json::to_value(forms()?).map_err(Error::protocol),
        Request::BuildAction { action, fields } => {
            serde_json::to_value(build_action(&action, fields)?).map_err(Error::protocol)
        }
        Request::BuildGenesis {
            federation,
            founders,
            quorum,
        } => build_genesis(federation, founders, quorum),
        Request::ReviewGenesis { genesis } => review_genesis(genesis),
        Request::ReviewConfiguration { config } => review_config(&config),
        Request::ReviewRecord {
            genesis,
            genesis_hash,
            record,
        } => review_record(&genesis, &genesis_hash, &record),
        Request::BuildAnchor { id, digest } => build_anchor(id, digest),
        Request::BuildRoles { member, roles } => build_roles(member, roles),
        Request::BuildConsensus { members } => build_consensus(members),
        Request::NewServiceId => Ok(Value::String(ServiceId::new().to_string())),
    }
}
