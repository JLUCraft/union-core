use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use union_core::{
    Identity, Node, NodeConfig, events,
    governance::{Action, State},
    journal::{Command, Journal, SignedCommand},
};
#[tokio::test]
async fn events_invalidate_snapshots_and_reject_outsiders() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = Identity::generate();
    let admin = identity.peer_id().to_string();
    let dir = tempfile::tempdir()?;
    let journal = Arc::new(Mutex::new(Journal::open(
        dir.path().join("journal"),
        State::new([admin.clone()].into())?,
    )?));
    let host = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
    let client = Node::start(identity.clone(), NodeConfig::default()).await?;
    client.dial(host.addresses()[0].clone()).await?;
    let task = tokio::spawn(events::serve(host.clone(), journal.clone()));
    tokio::task::yield_now().await;
    let mut stream = events::subscribe(&client, host.peer_id(), 0).await?;
    let first = events::next(&mut stream).await?;
    assert_eq!(first.revision, 0);
    assert!(first.resync);
    let command = SignedCommand::sign(
        &identity,
        Command {
            revision: 0,
            expires_ms: 1000,
            action: Action::Enroll {
                member: "member".into(),
                club: "jlu".into(),
                device: Identity::generate().peer_id().to_string(),
            },
        },
    )?;
    journal.lock().await.execute(command, 10)?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let event = events::next(&mut stream).await?;
            if event.revision == 1 {
                return Ok::<_, union_core::Error>(());
            }
        }
    })
    .await??;
    let outsider = Node::start(Identity::generate(), NodeConfig::default()).await?;
    outsider.dial(host.addresses()[0].clone()).await?;
    let mut denied = events::subscribe(&outsider, host.peer_id(), 0).await?;
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
