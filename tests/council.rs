use std::collections::BTreeMap;
use union_core::{
    Identity,
    council::Council,
    governance::{Action, State},
};
type R = Result<(), Box<dyn std::error::Error>>;
fn act(s: &mut State, actor: &str, action: Action) -> R {
    s.apply(actor, s.revision, s.clock_ms + 1, action)?;
    Ok(())
}
#[test]
fn school_quorum_is_not_device_quorum_and_council_removes_single_admin_bypass() -> R {
    let peers: Vec<_> = (0..5)
        .map(|_| Identity::generate().peer_id().to_string())
        .collect();
    let mut s = State::new([peers[0].clone()].into())?;
    let policy = Council {
        epoch: 0,
        schools: BTreeMap::from([
            ("jlu".into(), [peers[0].clone(), peers[1].clone()].into()),
            ("school2".into(), [peers[2].clone()].into()),
            ("school3".into(), [peers[3].clone()].into()),
        ]),
        quorum: 2,
        change_quorum: 3,
        cooldown_ms: 172_800_000,
    };
    act(
        &mut s,
        &peers[0],
        Action::InstallCouncil {
            council: policy.clone(),
        },
    )?;
    let grant = Action::GrantAdmin {
        device: peers[4].clone(),
    };
    assert!(s.apply(&peers[0], s.revision, 10, grant.clone()).is_err());
    act(
        &mut s,
        &peers[0],
        Action::Propose {
            id: "grant".into(),
            action: Box::new(grant),
            expires_ms: 600000,
        },
    )?;
    assert!(
        s.apply(
            &peers[1],
            s.revision,
            10,
            Action::ApproveProposal { id: "grant".into() }
        )
        .is_err()
    );
    assert!(
        s.apply(
            &peers[0],
            s.revision,
            10,
            Action::ExecuteProposal { id: "grant".into() }
        )
        .is_err()
    );
    act(
        &mut s,
        &peers[2],
        Action::ApproveProposal { id: "grant".into() },
    )?;
    act(
        &mut s,
        &peers[0],
        Action::ExecuteProposal { id: "grant".into() },
    )?;
    assert!(s.admins.contains(&peers[4]));
    assert!(
        s.apply(
            &peers[4],
            s.revision,
            10,
            Action::ExecuteProposal { id: "grant".into() }
        )
        .is_err()
    );
    act(
        &mut s,
        &peers[0],
        Action::Propose {
            id: "policy".into(),
            action: Box::new(Action::UpdateCouncil { council: policy }),
            expires_ms: 600_000_000,
        },
    )?;
    for voter in [&peers[2], &peers[3]] {
        act(
            &mut s,
            voter,
            Action::ApproveProposal {
                id: "policy".into(),
            },
        )?;
    }
    assert!(
        s.apply(
            &peers[0],
            s.revision,
            100,
            Action::ExecuteProposal {
                id: "policy".into()
            }
        )
        .is_err()
    );
    s.apply(
        &peers[0],
        s.revision,
        172_800_100,
        Action::ExecuteProposal {
            id: "policy".into(),
        },
    )?;
    assert_eq!(s.council.as_ref().map(|c| c.epoch), Some(2));
    Ok(())
}
#[test]
fn member_votes_and_feedback_do_not_grant_management_authority() -> R {
    let admin = Identity::generate().peer_id().to_string();
    let member = Identity::generate().peer_id().to_string();
    let mut s = State::new([admin.clone()].into())?;
    act(
        &mut s,
        &admin,
        Action::Enroll {
            member: "student".into(),
            club: "jlu".into(),
            device: member.clone(),
        },
    )?;
    act(
        &mut s,
        &admin,
        Action::CreateBallot {
            id: "map".into(),
            title: "Next match map".into(),
            options: vec!["A".into(), "B".into()],
            closes_ms: 1000,
        },
    )?;
    act(
        &mut s,
        &member,
        Action::MemberVote {
            id: "map".into(),
            option: 1,
        },
    )?;
    assert!(
        s.apply(
            &member,
            s.revision,
            100,
            Action::MemberVote {
                id: "map".into(),
                option: 0
            }
        )
        .is_err()
    );
    act(
        &mut s,
        &member,
        Action::SubmitFeedback {
            id: "request".into(),
            category: "league".into(),
            text: "Please schedule another round".into(),
        },
    )?;
    assert!(
        s.apply(
            &member,
            s.revision,
            100,
            Action::RespondFeedback {
                id: "request".into(),
                text: "approved".into()
            }
        )
        .is_err()
    );
    act(
        &mut s,
        &admin,
        Action::RespondFeedback {
            id: "request".into(),
            text: "Received".into(),
        },
    )?;
    assert_eq!(s.feedback["request"].response.as_deref(), Some("Received"));
    Ok(())
}
