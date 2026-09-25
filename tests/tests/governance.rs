#[path = "../support/mod.rs"]
mod support;
type State = support::Scenario<league::LeagueDomain>;
use identity::Identity;
use league::governance::{Action, ConnectionHealth, Phase, Route, Rules};
use std::collections::BTreeMap;
type R = Result<(), Box<dyn std::error::Error>>;

fn apply(state: &mut State, actor: &str, action: Action) -> R {
    state.apply(actor, state.revision, state.clock_ms + 1, action)?;
    Ok(())
}

fn setup(
    cross_club: bool,
    seats: usize,
) -> Result<(State, String, Vec<String>), Box<dyn std::error::Error>> {
    let keys: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
    let admin = keys[0].peer_id().to_string();
    let players: Vec<_> = keys[1..].iter().map(|k| k.peer_id().to_string()).collect();
    let mut state = State::new(
        &[
            (&keys[0], "admin", "jlu"),
            (&keys[1], "0", "jlu"),
            (&keys[2], "1", "jlu"),
            (&keys[3], "2", "jlu"),
            (&keys[4], "3", "other"),
        ],
        "admin",
    );
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::CreateLeague {
            league: "cup".into(),
            rules: Rules {
                cross_club,
                seats,
                ..Rules::default()
            },
            host: admin.clone(),
            scorer: admin.clone(),
        }),
    )?;
    apply(
        &mut state,
        &players[0],
        Action::Domain(league::LeagueAction::CreateTeam {
            league: "cup".into(),
            team: "a".into(),
        }),
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
            Action::Domain(league::LeagueAction::Accept {
                league: "cup".into(),
                team: "a".into()
            })
        )
        .is_err()
    );
    apply(
        &mut state,
        &players[0],
        Action::Domain(league::LeagueAction::Invite {
            league: "cup".into(),
            team: "a".into(),
            member: "3".into(),
        }),
    )?;
    let before = state.clone();
    assert!(
        apply(
            &mut state,
            &players[3],
            Action::Domain(league::LeagueAction::Accept {
                league: "cup".into(),
                team: "a".into()
            })
        )
        .is_err()
    );
    assert_eq!(state, before);
    apply(
        &mut state,
        &players[0],
        Action::Domain(league::LeagueAction::Invite {
            league: "cup".into(),
            team: "a".into(),
            member: "1".into(),
        }),
    )?;
    apply(
        &mut state,
        &players[1],
        Action::Domain(league::LeagueAction::Accept {
            league: "cup".into(),
            team: "a".into(),
        }),
    )?;
    assert!(
        apply(
            &mut state,
            &players[1],
            Action::Domain(league::LeagueAction::CreateTeam {
                league: "cup".into(),
                team: "b".into()
            })
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
            Action::Domain(league::LeagueAction::Invite {
                league: "cup".into(),
                team: "a".into(),
                member: member.into(),
            }),
        )?;
        apply(
            &mut state,
            &players[member.parse::<usize>()?],
            Action::Domain(league::LeagueAction::Accept {
                league: "cup".into(),
                team: "a".into(),
            }),
        )?;
    }
    apply(
        &mut state,
        &players[0],
        Action::Domain(league::LeagueAction::Register {
            league: "cup".into(),
            team: "a".into(),
        }),
    )?;
    for member in ["0", "1", "2", "3"] {
        apply(
            &mut state,
            &admin,
            Action::Domain(league::LeagueAction::Presence {
                league: "cup".into(),
                member: member.into(),
                online: true,
                health: ConnectionHealth::default(),
            }),
        )?;
    }
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Start {
            league: "cup".into(),
            seed: [7; 32],
        }),
    )?;
    let original = state.domain.leagues["cup"].seats["a"][0].clone();
    assert_eq!(state.domain.leagues["cup"].online.len(), 4);
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Presence {
            league: "cup".into(),
            member: original.player.clone(),
            online: false,
            health: ConnectionHealth::default(),
        }),
    )?;
    let deadline = state.domain.leagues["cup"].seats["a"][0]
        .disconnected_until
        .ok_or("no deadline")?;
    state.apply(
        &admin,
        state.revision,
        deadline,
        Action::Domain(league::LeagueAction::Tick {
            league: "cup".into(),
        }),
    )?;
    let replacement = state.domain.leagues["cup"].seats["a"][0].clone();
    assert_ne!(replacement.player, original.player);
    assert!(replacement.epoch > original.epoch);
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Presence {
            league: "cup".into(),
            member: original.player.clone(),
            online: true,
            health: ConnectionHealth::default(),
        }),
    )?;
    assert_eq!(
        state.domain.leagues["cup"].route(&original.player),
        Route::Waiting
    );
    // Even zero players is legal at the start.
    let (mut empty, admin, players) = setup(false, 4)?;
    apply(
        &mut empty,
        &players[0],
        Action::Domain(league::LeagueAction::Register {
            league: "cup".into(),
            team: "a".into(),
        }),
    )?;
    apply(
        &mut empty,
        &admin,
        Action::Domain(league::LeagueAction::Start {
            league: "cup".into(),
            seed: [0; 32],
        }),
    )?;
    assert_eq!(empty.domain.leagues["cup"].phase, Phase::Playing);
    assert!(empty.domain.leagues["cup"].seats["a"].is_empty());
    Ok(())
}

#[test]
fn infrastructure_outage_defers_replacement_and_score_is_idempotent() -> R {
    let (mut state, admin, players) = setup(false, 2)?;
    apply(
        &mut state,
        &players[0],
        Action::Domain(league::LeagueAction::Register {
            league: "cup".into(),
            team: "a".into(),
        }),
    )?;
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Presence {
            league: "cup".into(),
            member: "0".into(),
            online: true,
            health: ConnectionHealth::default(),
        }),
    )?;
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Start {
            league: "cup".into(),
            seed: [4; 32],
        }),
    )?;
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Presence {
            league: "cup".into(),
            member: "0".into(),
            online: false,
            health: ConnectionHealth::default(),
        }),
    )?;
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Infrastructure {
            league: "cup".into(),
            healthy: false,
        }),
    )?;
    state.apply(
        &admin,
        state.revision,
        100_000,
        Action::Domain(league::LeagueAction::Tick {
            league: "cup".into(),
        }),
    )?;
    assert_eq!(state.domain.leagues["cup"].seats["a"].len(), 1);
    let score = Action::Domain(league::LeagueAction::Score {
        league: "cup".into(),
        event: "result-1".into(),
        players: [("0".into(), 10)].into(),
        teams: [("a".into(), 20)].into(),
    });
    assert!(apply(&mut state, &players[0], score.clone()).is_err());
    apply(&mut state, &admin, score.clone())?;
    apply(&mut state, &admin, score)?;
    assert_eq!(state.domain.leagues["cup"].player_scores["0"], 10);
    assert_eq!(state.domain.leagues["cup"].team_scores["a"], 20);
    assert!(
        apply(
            &mut state,
            &admin,
            Action::Domain(league::LeagueAction::Score {
                league: "cup".into(),
                event: "result-1".into(),
                players: BTreeMap::new(),
                teams: BTreeMap::new()
            })
        )
        .is_err()
    );
    apply(
        &mut state,
        &admin,
        Action::Domain(league::LeagueAction::Finish {
            league: "cup".into(),
        }),
    )?;
    assert!(
        apply(
            &mut state,
            &admin,
            Action::Domain(league::LeagueAction::Score {
                league: "cup".into(),
                event: "late".into(),
                players: BTreeMap::new(),
                teams: BTreeMap::new()
            })
        )
        .is_err()
    );
    Ok(())
}
