//! Consent-based device linking; voting and team membership remain person-scoped.
use crate::{
    Error, Result,
    governance::{Action, State},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invitation {
    pub member: String,
    pub device: String,
    pub expires_ms: u64,
}
impl State {
    pub(crate) fn device_transition(
        &mut self,
        actor: &str,
        now: u64,
        action: Action,
    ) -> Result<()> {
        match action {
            Action::InviteMemberDevice {
                id,
                device,
                expires_ms,
            } => {
                if id.is_empty()
                    || id.len() > 128
                    || expires_ms <= now
                    || expires_ms > now.saturating_add(600_000)
                {
                    return Err(Error::Denied);
                }
                device.parse::<crate::PeerId>().map_err(|_| Error::Denied)?;
                if self.revoked_devices.contains(&device)
                    || self.members.values().any(|m| m.owns(&device))
                {
                    return Err(Error::Denied);
                }
                let (member, m) = self
                    .members
                    .iter()
                    .find(|(_, m)| m.owns(actor))
                    .ok_or(Error::Denied)?;
                if m.additional_devices.len() >= 7 {
                    return Err(Error::Capacity);
                }
                let member = member.clone();
                self.device_invitations.retain(|_, i| i.expires_ms > now);
                if self.device_invitations.len() >= 4096
                    || self.device_invitations.contains_key(&id)
                {
                    return Err(Error::Capacity);
                }
                self.device_invitations.insert(
                    id,
                    Invitation {
                        member,
                        device,
                        expires_ms,
                    },
                );
            }
            Action::AcceptMemberDevice { id } => {
                let i = self.device_invitations.get(&id).ok_or(Error::NotFound)?;
                if i.device != actor
                    || i.expires_ms <= now
                    || self.revoked_devices.contains(actor)
                    || self.members.values().any(|m| m.owns(actor))
                {
                    return Err(Error::Denied);
                }
                let m = self.members.get_mut(&i.member).ok_or(Error::NotFound)?;
                if m.additional_devices.len() >= 7 {
                    return Err(Error::Capacity);
                }
                m.additional_devices.insert(actor.into());
                self.device_invitations.remove(&id);
            }
            Action::RevokeMemberDevice { device } => {
                let m = self
                    .members
                    .values_mut()
                    .find(|m| m.owns(actor))
                    .ok_or(Error::Denied)?;
                if !m.owns(&device) || (m.device == device && m.additional_devices.is_empty()) {
                    return Err(Error::Denied);
                }
                if m.device == device {
                    m.device = m.additional_devices.pop_first().ok_or(Error::Denied)?;
                } else {
                    m.additional_devices.remove(&device);
                }
                self.revoked_devices.insert(device.clone());
                self.device_invitations.retain(|_, i| i.device != device);
            }
            _ => return Err(Error::Denied),
        }
        Ok(())
    }
}
