use llm_gateway::{Ledger, Quotas, Reservation, Result};
fn charge(ledger: &mut Ledger, member: &str, club: &str, tokens: u64, now: u64) -> Result<usize> {
    ledger.reserve(
        Reservation {
            member,
            club,
            model: "local",
            purpose: "assistant.ask",
            tokens,
        },
        Quotas {
            member: Some(80),
            club: Some(100),
        },
        now,
    )
}
#[test]
fn shared_budget_survives_restart_and_settlement_preserves_original_institution() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("ledger");
    let mut ledger = Ledger::open(&path)?;
    let first = charge(&mut ledger, "alice", "a", 70, 1000)?;
    assert!(charge(&mut ledger, "bob", "a", 40, 1001).is_err());
    charge(&mut ledger, "bob", "b", 40, 1001)?;
    ledger.settle(first, 30, 1002)?;
    drop(ledger);
    let mut ledger = Ledger::open(&path)?;
    charge(&mut ledger, "carol", "a", 70, 1003)?;
    assert!(charge(&mut ledger, "alice", "a", 1, 1004).is_err());
    // Even when changing institution, the member's own rolling budget is retained.
    assert!(charge(&mut ledger, "alice", "b", 51, 1004).is_err());
    charge(&mut ledger, "alice", "b", 50, 1004)?;
    assert!(charge(&mut ledger, "dave", "b", 11, 1005).is_err());
    charge(&mut ledger, "carol", "a", 80, 86_401_004)?;
    Ok(())
}
#[test]
fn ledger_requires_explicit_member_institution_attribution() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("ledger");
    let previous = protocol::digest(b"jlucraft/llm/usage/1");
    let invalid = serde_json::json!([{"previous":previous,"time_ms":1000,"event":{"type":"reserve","member":"alice","model":"local","purpose":"assistant.ask","tokens":70}}]);
    std::fs::write(&path, serde_json::to_vec(&invalid)?)?;
    assert!(Ledger::open(path).is_err());
    Ok(())
}
