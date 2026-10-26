#[path = "../support/mod.rs"]
mod support;
use authority::events;
use client::application::Action;
use identity::Identity;
type Journal = authority::journal::Journal<client::application::Application>;
use node::{Node, NodeConfig};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
#[tokio::test]
async fn events_invalidate_snapshots_and_reject_outsiders() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = Identity::generate();
    let identities = support::Identities::new(&[(&identity, "admin", "jlu")], "admin");
    let view = identities.log.view(Duration::from_secs(60))?;
    let dir = tempfile::tempdir()?;
    let journal = Arc::new(Mutex::new(Journal::open(
        dir.path().join("journal"),
        identities.genesis(),
    )?));
    let host = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
    let client = Node::start(identity.clone(), NodeConfig::default()).await?;
    client.dial(host.addresses()[0].clone()).await?;
    let log = Arc::new(Mutex::new(identities.log));
    let task = tokio::spawn(events::serve_authority(
        host.clone(),
        authority::authority::Authority::Local {
            journal: journal.clone(),
            log: log.clone(),
            view,
        },
        events::PROTOCOL,
    ));
    tokio::task::yield_now().await;
    let mut stream = events::subscribe(&client, host.peer_id(), 0, events::PROTOCOL).await?;
    let first = events::next(&mut stream).await?;
    assert_eq!(first.revision, 0);
    assert!(first.resync);
    let current = log.lock().await;
    let mut j = journal.lock().await;
    let command = authority::journal::SignedCommand::sign(
        &identity,
        authority::journal::TrustedCommand {
            genesis: j.genesis_hash().into(),
            previous: j.head()?,
            identity: current.state().checkpoint().clone(),
            command: authority::journal::Command {
                revision: 0,
                expires_ms: 1000,
                action: Action::AnchorDigest {
                    id: "a".into(),
                    digest: "a".repeat(64),
                },
            },
        },
    )?;
    j.execute(command, current.history_since(None)?, current.state(), 10)?;
    drop(j);
    drop(current);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let event = events::next(&mut stream).await?;
            if event.revision == 1 {
                return Ok::<_, protocol::Error>(());
            }
        }
    })
    .await??;
    let outsider = Node::start(Identity::generate(), NodeConfig::default()).await?;
    outsider.dial(host.addresses()[0].clone()).await?;
    let mut denied = events::subscribe(&outsider, host.peer_id(), 0, events::PROTOCOL).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), events::next(&mut denied))
            .await?
            .is_err()
    );
    task.abort();
    client.shutdown().await?;
    outsider.shutdown().await?;
    Ok(())
}
