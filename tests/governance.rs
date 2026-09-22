use std::collections::BTreeMap;
use union_core::{
    Identity,
    governance::*,
    journal::{Command, Journal, SignedCommand},
};
type R = Result<(), Box<dyn std::error::Error>>;

fn apply(state: &mut State, actor: &str, action: Action) -> R {
    state.apply(actor, state.revision, state.clock_ms + 1, action)?;
    Ok(())
}

fn setup(
    cross_club: bool,
    seats: usize,
) -> Result<(State, String, Vec<String>), Box<dyn std::error::Error>> {
    let admin = Identity::generate().peer_id().to_string();
    let players: Vec<_> = (0..4)
        .map(|_| Identity::generate().peer_id().to_string())
        .collect();
    let mut state = State::new([admin.clone()].into())?;
    for (i, device) in players.iter().enumerate() {
        apply(
            &mut state,
            &admin,
            Action::Enroll {
                member: i.to_string(),
                club: if i == 3 { "other" } else { "jlu" }.into(),
                device: device.clone(),
            },
        )?;
    }
    apply(
        &mut state,
        &admin,
        Action::CreateLeague {
            league: "cup".into(),
            rules: Rules {
                cross_club,
                seats,
                ..Rules::default()
            },
            host: admin.clone(),
            scorer: admin.clone(),
        },
    )?;
    apply(
        &mut state,
        &players[0],
        Action::CreateTeam {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    Ok((state, admin, players))
}

#[test]
fn invitation_consent_cross_club_and_single_team() -> R {
    let (mut state, _admin, players) = setup(false, 2)?;
    assert!(
        apply(
            &mut state,
            &players[1],
            Action::Accept {
                league: "cup".into(),
                team: "a".into()
            }
        )
        .is_err()
    );
    apply(
        &mut state,
        &players[0],
        Action::Invite {
            league: "cup".into(),
            team: "a".into(),
            member: "3".into(),
        },
    )?;
    let before = state.clone();
    assert!(
        apply(
            &mut state,
            &players[3],
            Action::Accept {
                league: "cup".into(),
                team: "a".into()
            }
        )
        .is_err()
    );
    assert_eq!(state, before);
    apply(
        &mut state,
        &players[0],
        Action::Invite {
            league: "cup".into(),
            team: "a".into(),
            member: "1".into(),
        },
    )?;
    apply(
        &mut state,
        &players[1],
        Action::Accept {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    assert!(
        apply(
            &mut state,
            &players[1],
            Action::CreateTeam {
                league: "cup".into(),
                team: "b".into()
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn undersized_team_plays_and_random_replacement_fences_late_recovery() -> R {
    let (mut state, admin, players) = setup(true, 1)?;
    for member in ["1", "2", "3"] {
        apply(
            &mut state,
            &players[0],
            Action::Invite {
                league: "cup".into(),
                team: "a".into(),
                member: member.into(),
            },
        )?;
        apply(
            &mut state,
            &players[member.parse::<usize>()?],
            Action::Accept {
                league: "cup".into(),
                team: "a".into(),
            },
        )?;
    }
    apply(
        &mut state,
        &players[0],
        Action::Register {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    for member in ["0", "1", "2", "3"] {
        apply(
            &mut state,
            &admin,
            Action::Presence {
                league: "cup".into(),
                member: member.into(),
                online: true,
                health: ConnectionHealth::default(),
            },
        )?;
    }
    apply(
        &mut state,
        &admin,
        Action::Start {
            league: "cup".into(),
            seed: [7; 32],
        },
    )?;
    let original = state.leagues["cup"].seats["a"][0].clone();
    assert_eq!(state.leagues["cup"].online.len(), 4);
    apply(
        &mut state,
        &admin,
        Action::Presence {
            league: "cup".into(),
            member: original.player.clone(),
            online: false,
            health: ConnectionHealth::default(),
        },
    )?;
    let deadline = state.leagues["cup"].seats["a"][0]
        .disconnected_until
        .ok_or("no deadline")?;
    state.apply(
        &admin,
        state.revision,
        deadline,
        Action::Tick {
            league: "cup".into(),
        },
    )?;
    let replacement = state.leagues["cup"].seats["a"][0].clone();
    assert_ne!(replacement.player, original.player);
    assert!(replacement.epoch > original.epoch);
    apply(
        &mut state,
        &admin,
        Action::Presence {
            league: "cup".into(),
            member: original.player.clone(),
            online: true,
            health: ConnectionHealth::default(),
        },
    )?;
    assert_eq!(state.leagues["cup"].route(&original.player), Route::Waiting);
    // Even zero players is legal at the start.
    let (mut empty, admin, players) = setup(false, 4)?;
    apply(
        &mut empty,
        &players[0],
        Action::Register {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    apply(
        &mut empty,
        &admin,
        Action::Start {
            league: "cup".into(),
            seed: [0; 32],
        },
    )?;
    assert_eq!(empty.leagues["cup"].phase, Phase::Playing);
    assert!(empty.leagues["cup"].seats["a"].is_empty());
    Ok(())
}

#[test]
fn infrastructure_outage_defers_replacement_and_score_is_idempotent() -> R {
    let (mut state, admin, players) = setup(false, 2)?;
    apply(
        &mut state,
        &players[0],
        Action::Register {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    apply(
        &mut state,
        &admin,
        Action::Presence {
            league: "cup".into(),
            member: "0".into(),
            online: true,
            health: ConnectionHealth::default(),
        },
    )?;
    apply(
        &mut state,
        &admin,
        Action::Start {
            league: "cup".into(),
            seed: [4; 32],
        },
    )?;
    apply(
        &mut state,
        &admin,
        Action::Presence {
            league: "cup".into(),
            member: "0".into(),
            online: false,
            health: ConnectionHealth::default(),
        },
    )?;
    apply(
        &mut state,
        &admin,
        Action::Infrastructure {
            league: "cup".into(),
            healthy: false,
        },
    )?;
    state.apply(
        &admin,
        state.revision,
        100_000,
        Action::Tick {
            league: "cup".into(),
        },
    )?;
    assert_eq!(state.leagues["cup"].seats["a"].len(), 1);
    let score = Action::Score {
        league: "cup".into(),
        event: "result-1".into(),
        players: [("0".into(), 10)].into(),
        teams: [("a".into(), 20)].into(),
    };
    assert!(apply(&mut state, &players[0], score.clone()).is_err());
    apply(&mut state, &admin, score.clone())?;
    apply(&mut state, &admin, score)?;
    assert_eq!(state.leagues["cup"].player_scores["0"], 10);
    assert_eq!(state.leagues["cup"].team_scores["a"], 20);
    assert!(
        apply(
            &mut state,
            &admin,
            Action::Score {
                league: "cup".into(),
                event: "result-1".into(),
                players: BTreeMap::new(),
                teams: BTreeMap::new()
            }
        )
        .is_err()
    );
    apply(
        &mut state,
        &admin,
        Action::Finish {
            league: "cup".into(),
        },
    )?;
    assert!(
        apply(
            &mut state,
            &admin,
            Action::Score {
                league: "cup".into(),
                event: "late".into(),
                players: BTreeMap::new(),
                teams: BTreeMap::new()
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn signed_journal_replays_locks_and_rejects_tampering() -> R {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let key = Identity::generate();
    let genesis = State::new([key.peer_id().to_string()].into())?;
    let mut journal = Journal::open(&path, genesis.clone())?;
    assert!(Journal::open(&path, genesis.clone()).is_err());
    let command = SignedCommand::sign(
        &key,
        Command {
            revision: 0,
            expires_ms: 100,
            action: Action::Enroll {
                member: "m".into(),
                club: "jlu".into(),
                device: Identity::generate().peer_id().to_string(),
            },
        },
    )?;
    journal.execute(command.clone(), 1)?;
    assert!(journal.execute(command, 2).is_err());
    let expected = journal.state().clone();
    drop(journal);
    let journal = Journal::open(&path, genesis.clone())?;
    assert_eq!(journal.state(), &expected);
    drop(journal);
    let mut data: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    data[0]["state_hash"] = "invalid".into();
    std::fs::write(&path, serde_json::to_vec(&data)?)?;
    assert!(Journal::open(&path, genesis).is_err());
    Ok(())
}

#[test]
fn administrator_recovery_requires_authority_and_preserves_last_admin() -> R {
    let (mut state, admin, players) = setup(false, 1)?;
    let recovery = Identity::generate().peer_id().to_string();
    assert!(
        apply(
            &mut state,
            &players[0],
            Action::GrantAdmin {
                device: recovery.clone()
            }
        )
        .is_err()
    );
    assert!(
        apply(
            &mut state,
            &admin,
            Action::RevokeAdmin {
                device: admin.clone()
            }
        )
        .is_err()
    );
    apply(
        &mut state,
        &admin,
        Action::GrantAdmin {
            device: recovery.clone(),
        },
    )?;
    apply(
        &mut state,
        &recovery,
        Action::RevokeAdmin {
            device: admin.clone(),
        },
    )?;
    assert!(
        apply(
            &mut state,
            &admin,
            Action::GrantAdmin {
                device: admin.clone()
            }
        )
        .is_err()
    );
    let replacement = Identity::generate().peer_id().to_string();
    apply(
        &mut state,
        &recovery,
        Action::RotateMemberDevice {
            member: "0".into(),
            device: replacement.clone(),
        },
    )?;
    assert!(
        apply(
            &mut state,
            &players[0],
            Action::Register {
                league: "cup".into(),
                team: "a".into()
            }
        )
        .is_err()
    );
    apply(
        &mut state,
        &replacement,
        Action::Register {
            league: "cup".into(),
            team: "a".into(),
        },
    )?;
    // League organizer is an explicit role; revoking global administration does
    // not silently transfer ownership of an existing league.
    apply(
        &mut state,
        &admin,
        Action::Start {
            league: "cup".into(),
            seed: [0; 32],
        },
    )?;
    assert!(
        apply(
            &mut state,
            &recovery,
            Action::RotateMemberDevice {
                member: "0".into(),
                device: players[0].clone()
            }
        )
        .is_err()
    );
    Ok(())
}
