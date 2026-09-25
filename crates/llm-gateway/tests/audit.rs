use llm_gateway::{Ledger, Result};
#[test]
fn running_ledger_exports_a_prefix_that_remains_verifiable_after_settlement() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let mut ledger = Ledger::open(&path)?;
    let first = ledger.reserve(
        llm_gateway::Reservation {
            member: "alice",
            club: "jlu",
            model: "local",
            purpose: "events.draft",
            tokens: 100,
        },
        llm_gateway::Quotas {
            member: Some(1000),
            club: None,
        },
        1000,
    )?;
    ledger.settle(first, 30, 1001)?;
    let second = ledger.reserve(
        llm_gateway::Reservation {
            member: "bob",
            club: "jlu",
            model: "local",
            purpose: "events.summary",
            tokens: 80,
        },
        llm_gateway::Quotas {
            member: Some(1000),
            club: None,
        },
        1002,
    )?;
    let summary = Ledger::audit(&path, None)?;
    assert_eq!(summary.entries, 3);
    assert_eq!(summary.totals.requests, 2);
    assert_eq!(summary.totals.settled_tokens, 30);
    assert_eq!(summary.totals.reserved_tokens, 80);
    assert_eq!(summary.totals.unsettled_requests, 1);
    assert_eq!(summary.purposes["events.draft"].settled_tokens, 30);
    assert_eq!(summary.purposes["events.summary"].reserved_tokens, 80);
    let pin = summary.digest()?;
    // No second writer is opened; audit reads the atomic snapshot while the gateway owns its lock.
    summary.verify(&path, &pin)?;
    ledger.settle(second, 20, 1003)?;
    summary.verify(&path, &pin)?;
    let settled = Ledger::audit(&path, None)?;
    assert_eq!(settled.totals.settled_tokens, 50);
    assert_eq!(settled.totals.reserved_tokens, 0);
    assert_ne!(settled.digest()?, pin);
    assert!(summary.verify(&path, &"0".repeat(64)).is_err());
    let mut forged = summary.clone();
    forged.totals.settled_tokens = 0;
    assert!(forged.verify(&path, &pin).is_err());
    let original = std::fs::read(&path)?;
    let mut entries: serde_json::Value = serde_json::from_slice(&original)?;
    entries
        .as_array_mut()
        .ok_or(llm_gateway::Error::Invalid("test entries"))?
        .truncate(2);
    std::fs::write(&path, serde_json::to_vec(&entries)?)?;
    assert!(summary.verify(&path, &pin).is_err());
    std::fs::write(&path, b"[]")?;
    assert!(summary.verify(&path, &pin).is_err());
    Ok(())
}
