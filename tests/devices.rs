use union_core::{
    Identity,
    governance::{Action, State},
};
type R = Result<(), Box<dyn std::error::Error>>;
fn apply(s: &mut State, a: &str, action: Action) -> union_core::Result<()> {
    s.apply(a, s.revision, s.clock_ms + 1, action)
}
#[test]
fn linking_needs_both_devices_and_revocation_cannot_be_reversed_by_reenrollment() -> R {
    let admin = Identity::generate().peer_id().to_string();
    let old = Identity::generate().peer_id().to_string();
    let new = Identity::generate().peer_id().to_string();
    let mut s = State::new([admin.clone()].into())?;
    apply(
        &mut s,
        &admin,
        Action::Enroll {
            member: "m".into(),
            club: "jlu".into(),
            device: old.clone(),
        },
    )?;
    apply(
        &mut s,
        &old,
        Action::InviteMemberDevice {
            id: "link".into(),
            device: new.clone(),
            expires_ms: 600_000,
        },
    )?;
    assert!(
        apply(
            &mut s,
            &old,
            Action::AcceptMemberDevice { id: "link".into() }
        )
        .is_err()
    );
    apply(
        &mut s,
        &new,
        Action::AcceptMemberDevice { id: "link".into() },
    )?;
    assert!(s.can_read(&new));
    assert_eq!(s.members.len(), 1);
    apply(
        &mut s,
        &admin,
        Action::CreateBallot {
            id: "vote".into(),
            title: "活动日期".into(),
            options: vec!["周六".into(), "周日".into()],
            closes_ms: 1000,
        },
    )?;
    apply(
        &mut s,
        &old,
        Action::MemberVote {
            id: "vote".into(),
            option: 0,
        },
    )?;
    assert!(
        apply(
            &mut s,
            &new,
            Action::MemberVote {
                id: "vote".into(),
                option: 1
            }
        )
        .is_err()
    );
    apply(
        &mut s,
        &new,
        Action::RevokeMemberDevice {
            device: old.clone(),
        },
    )?;
    assert!(!s.can_read(&old));
    assert_eq!(s.members["m"].device, new);
    assert!(
        apply(
            &mut s,
            &old,
            Action::SubmitFeedback {
                id: "bad".into(),
                category: "x".into(),
                text: "x".into()
            }
        )
        .is_err()
    );
    assert!(
        apply(
            &mut s,
            &admin,
            Action::Enroll {
                member: "revived".into(),
                club: "jlu".into(),
                device: old
            }
        )
        .is_err()
    );
    assert!(
        apply(
            &mut s,
            &new,
            Action::RevokeMemberDevice {
                device: new.clone()
            }
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn journal_refuses_any_other_or_missing_format_version() -> R {
    use union_core::journal::{Command, Journal, SignedCommand};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal");
    let admin = Identity::generate();
    let state = State::new([admin.peer_id().to_string()].into())?;
    let mut j = Journal::open(&path, state.clone())?;
    j.execute(
        SignedCommand::sign(
            &admin,
            Command {
                revision: 0,
                expires_ms: 100,
                action: Action::Enroll {
                    member: "m".into(),
                    club: "jlu".into(),
                    device: Identity::generate().peer_id().to_string(),
                },
            },
        )?,
        1,
    )?;
    drop(j);
    let current: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    for version in [None, Some(0), Some(2)] {
        let mut value = current.clone();
        if let Some(version) = version {
            value[0]["version"] = version.into();
        } else {
            value[0].as_object_mut().unwrap().remove("version");
        }
        std::fs::write(&path, serde_json::to_vec(&value)?)?;
        assert!(Journal::open(&path, state.clone()).is_err());
    }
    std::fs::write(&path, serde_json::to_vec(&current)?)?;
    assert_eq!(Journal::open(&path, state)?.state().revision, 1);
    Ok(())
}
