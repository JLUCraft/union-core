#[path = "../support/mod.rs"]
mod support;
type State = support::Scenario<league::LeagueDomain>;
use identity::Identity;
use league::{
    governance::{Action, ConnectionHealth, Rules},
    season::Schedule,
};
use std::collections::BTreeMap;
type R = Result<(), Box<dyn std::error::Error>>;
fn apply(s: &mut State, a: &str, t: u64, action: Action) -> wire::Result<()> {
    s.apply(a, s.revision, t, action)
}
#[test]
fn registration_schedule_manual_pause_and_review_are_authorized_and_atomic() -> R {
    let root = Identity::generate();
    let phone = Identity::generate();
    let admin = root.peer_id().to_string();
    let member = phone.peer_id().to_string();
    let mut s = State::new(&[(&root, "admin", "jlu"), (&phone, "p", "jlu")], "admin");
    apply(
        &mut s,
        &admin,
        2,
        Action::Domain(league::LeagueAction::CreateLeague {
            league: "cup".into(),
            rules: Rules::default(),
            host: admin.clone(),
            scorer: admin.clone(),
        }),
    )?;
    apply(
        &mut s,
        &admin,
        3,
        Action::Domain(league::LeagueAction::CreateSeason {
            id: "autumn".into(),
            title: "秋季联赛".into(),
        }),
    )?;
    apply(
        &mut s,
        &admin,
        4,
        Action::Domain(league::LeagueAction::ScheduleLeague {
            season: "autumn".into(),
            league: "cup".into(),
            schedule: Schedule {
                opens_ms: 10,
                closes_ms: 20,
                starts_ms: 30,
            },
        }),
    )?;
    let create = Action::Domain(league::LeagueAction::CreateTeam {
        league: "cup".into(),
        team: "team".into(),
    });
    assert!(apply(&mut s, &member, 9, create.clone()).is_err());
    apply(&mut s, &member, 10, create)?;
    apply(
        &mut s,
        &member,
        11,
        Action::Domain(league::LeagueAction::Register {
            league: "cup".into(),
            team: "team".into(),
        }),
    )?;
    assert!(
        apply(
            &mut s,
            &member,
            20,
            Action::Domain(league::LeagueAction::Register {
                league: "cup".into(),
                team: "team".into()
            })
        )
        .is_err()
    );
    apply(
        &mut s,
        &admin,
        21,
        Action::Domain(league::LeagueAction::Presence {
            league: "cup".into(),
            member: "p".into(),
            online: true,
            health: ConnectionHealth::default(),
        }),
    )?;
    let start = Action::Domain(league::LeagueAction::Start {
        league: "cup".into(),
        seed: [0; 32],
    });
    assert!(apply(&mut s, &admin, 29, start.clone()).is_err());
    apply(&mut s, &admin, 30, start)?;
    apply(
        &mut s,
        &admin,
        31,
        Action::Domain(league::LeagueAction::PauseLeague {
            league: "cup".into(),
            paused: true,
        }),
    )?;
    apply(
        &mut s,
        &admin,
        32,
        Action::Domain(league::LeagueAction::Infrastructure {
            league: "cup".into(),
            healthy: false,
        }),
    )?;
    apply(
        &mut s,
        &admin,
        33,
        Action::Domain(league::LeagueAction::Infrastructure {
            league: "cup".into(),
            healthy: true,
        }),
    )?;
    assert_eq!(s.domain.leagues["cup"].paused_since, Some(31));
    apply(
        &mut s,
        &admin,
        34,
        Action::Domain(league::LeagueAction::PauseLeague {
            league: "cup".into(),
            paused: false,
        }),
    )?;
    assert_eq!(s.domain.leagues["cup"].paused_since, None);
    apply(
        &mut s,
        &admin,
        35,
        Action::Domain(league::LeagueAction::Score {
            league: "cup".into(),
            event: "result".into(),
            players: BTreeMap::from([("p".into(), 3)]),
            teams: BTreeMap::from([("team".into(), 5)]),
        }),
    )?;
    apply(
        &mut s,
        &admin,
        36,
        Action::Domain(league::LeagueAction::Finish {
            league: "cup".into(),
        }),
    )?;
    apply(
        &mut s,
        &member,
        37,
        Action::Domain(league::LeagueAction::DisputeResult {
            id: "review".into(),
            league: "cup".into(),
            reason: "记分重复".into(),
        }),
    )?;
    let correction = Action::Domain(league::LeagueAction::ResolveDispute {
        id: "review".into(),
        response: "已核对原始计分事件".into(),
        players: BTreeMap::from([("p".into(), -1)]),
        teams: BTreeMap::from([("team".into(), -2)]),
    });
    assert!(apply(&mut s, &member, 38, correction.clone()).is_err());
    apply(&mut s, &admin, 39, correction.clone())?;
    assert!(apply(&mut s, &admin, 40, correction).is_err());
    let ranks = s.domain.season_rankings("autumn")?;
    assert_eq!(ranks.players, vec![("p".into(), 2)]);
    assert_eq!(ranks.teams, vec![("team".into(), 3)]);
    Ok(())
}
