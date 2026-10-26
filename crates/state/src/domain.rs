//! Deterministic domain boundary. The core owns identity, revision and approvals.
use crate::{
    Error, Result,
    governance::{CoreState, Member},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned, ser::SerializeMap};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, DerefMut},
};

pub trait Domain:
    Clone + std::fmt::Debug + Default + PartialEq + Eq + Send + Sync + 'static
{
    type State: Clone
        + std::fmt::Debug
        + Default
        + PartialEq
        + Eq
        + Serialize
        + DeserializeOwned
        + Send
        + Sync;
    type Action: Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Serialize
        + DeserializeOwned
        + Send
        + Sync;
    fn point_balance(
        _state: &Self::State,
        _account: &crate::protocol::PointAccount,
    ) -> Result<u64> {
        Err(Error::Denied)
    }
    fn debit_points(
        _state: &mut Self::State,
        _account: &crate::protocol::PointAccount,
        _amount: u64,
    ) -> Result<()> {
        Err(Error::Denied)
    }
    fn credit_points(
        _state: &mut Self::State,
        _account: &crate::protocol::PointAccount,
        _amount: u64,
    ) -> Result<()> {
        Err(Error::Denied)
    }
    /// Automatic tasks require a payer's signed, scoped budget authorization.
    fn workflow_payer(
        _state: &Self::State,
        _action: &Self::Action,
    ) -> Result<(crate::protocol::PointAccount, crate::protocol::AiAllowance)> {
        Err(Error::Denied)
    }
    fn debit_ai_allowance(
        _state: &mut Self::State,
        _account: &crate::protocol::PointAccount,
        _allowance: &crate::protocol::AiAllowance,
        _amount: u64,
    ) -> Result<()> {
        Err(Error::Denied)
    }
    fn refund_ai_allowance(
        _state: &mut Self::State,
        _account: &crate::protocol::PointAccount,
        _allowance: &crate::protocol::AiAllowance,
        _amount: u64,
    ) -> Result<()> {
        Err(Error::Denied)
    }
    fn ai_document_action(_id: &str, _member: &str, _worker: &str) -> Result<Self::Action> {
        Err(Error::Denied)
    }
    /// Resolve an immutable domain artifact; never performs I/O during replay.
    fn artifact(_state: &Self::State, _cid: &str) -> Result<Vec<u8>> {
        Err(Error::NotFound)
    }
    /// Resolve the authoritative material for a review of this action.
    /// Domains opt in explicitly; an arbitrary caller-supplied file is not review evidence.
    fn review_artifact(_state: &Self::State, _action: &Self::Action) -> Result<String> {
        Err(Error::Denied)
    }
    fn workflow_input(_state: &Self::State, _action: &Self::Action) -> Result<Vec<u8>> {
        Err(Error::Denied)
    }
    fn workflow_worker(_state: &Self::State, _action: &Self::Action) -> Option<String> {
        None
    }
    fn requires_ai_review(_state: &Self::State, _action: &Self::Action) -> bool {
        false
    }
    /// Clubs whose presidents must sign the action before execution.
    fn approval_clubs(_state: &Self::State, _action: &Self::Action) -> Result<BTreeSet<String>> {
        Ok(BTreeSet::new())
    }
    fn transition_with_artifact(
        state: &mut Self::State,
        ctx: &Context<'_>,
        action: Self::Action,
        _artifact: Option<String>,
    ) -> Result<()> {
        Self::transition(state, ctx, action)
    }
    fn transition(state: &mut Self::State, ctx: &Context<'_>, action: Self::Action) -> Result<()>;
}

#[derive(Clone, Copy)]
pub struct CoreView<'a> {
    pub admins: &'a BTreeSet<String>,
    pub members: &'a BTreeMap<String, Member>,
}
pub struct Context<'a> {
    pub actor: &'a str,
    pub now_ms: u64,
    pub revision: u64,
    pub core: CoreView<'a>,
    pub approved: bool,
}
impl CoreState {
    pub fn view(&self) -> CoreView<'_> {
        CoreView {
            admins: &self.admins,
            members: &self.members,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct State<D: Domain> {
    #[serde(flatten)]
    pub core: CoreState,
    #[serde(flatten)]
    pub domain: D::State,
}
impl<D: Domain> Deref for State<D> {
    type Target = CoreState;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}
impl<D: Domain> DerefMut for State<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}
impl<D: Domain> Serialize for State<D> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        // RawValue retains the nested declaration order used by signed hashes.
        type Fields = BTreeMap<String, Box<serde_json::value::RawValue>>;
        let fields = |value: String| -> std::result::Result<Fields, S::Error> {
            serde_json::from_str(&value).map_err(serde::ser::Error::custom)
        };
        let mut core =
            fields(serde_json::to_string(&self.core).map_err(serde::ser::Error::custom)?)?;
        let domain =
            fields(serde_json::to_string(&self.domain).map_err(serde::ser::Error::custom)?)?;
        for (key, value) in domain {
            if core.insert(key, value).is_some() {
                return Err(serde::ser::Error::custom("domain field collides with core"));
            }
        }
        let mut map = serializer.serialize_map(Some(core.len()))?;
        for (key, value) in core {
            map.serialize_entry(&key, &value)?;
        }
        map.end()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmptyDomain;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmptyState {}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum EmptyAction {}
impl Domain for EmptyDomain {
    type State = EmptyState;
    type Action = EmptyAction;
    fn transition(
        _state: &mut Self::State,
        _ctx: &Context<'_>,
        action: Self::Action,
    ) -> Result<()> {
        match action {}
    }
}
impl<'a> Context<'a> {
    pub fn member(&self) -> Result<(&'a str, &'a Member)> {
        self.core
            .members
            .iter()
            .find(|(_, m)| m.owns(self.actor))
            .map(|(id, member)| (id.as_str(), member))
            .ok_or(Error::Denied)
    }
}
