use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use union_core::{
    Identity, Node, NodeConfig,
    governance::{Action, State},
    journal::{self, Command, Journal, Request, SignedCommand},
};

#[tokio::test]
async fn governance_binds_signed_actor_to_authenticated_stream_and_rejects_replay()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let admin = Identity::generate();
        let outsider = Identity::generate();
        let directory = tempfile::tempdir()?;
        let journal = Arc::new(Mutex::new(Journal::open(
            directory.path().join("journal"),
            State::new([admin.peer_id().to_string()].into())?,
        )?));
        let server = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
        let task = {
            let node = server.clone();
            let journal = journal.clone();
            tokio::spawn(async move { journal::serve(&node, journal).await })
        };
        // Protocol registration runs on the spawned server task before dialing.
        tokio::task::yield_now().await;
        let client = Node::start(admin.clone(), NodeConfig::default()).await?;
        let stranger = Node::start(outsider, NodeConfig::default()).await?;
        client.dial(server.addresses()[0].clone()).await?;
        stranger.dial(server.addresses()[0].clone()).await?;
        assert!(
            journal::request(&stranger, server.peer_id(), Request::Snapshot)
                .await?
                .state
                .is_none()
        );
        let command = SignedCommand::sign(
            &admin,
            Command {
                revision: 0,
                expires_ms: journal::now_ms()? + 10_000,
                action: Action::Enroll {
                    member: "student".into(),
                    club: "jlu".into(),
                    device: client.peer_id().to_string(),
                },
            },
        )?;
        assert!(
            journal::request(
                &stranger,
                server.peer_id(),
                Request::Execute {
                    command: command.clone()
                }
            )
            .await?
            .error
            .is_some()
        );
        assert_eq!(
            journal::request(
                &client,
                server.peer_id(),
                Request::Execute {
                    command: command.clone()
                }
            )
            .await?
            .state
            .ok_or("missing state")?
            .revision,
            1
        );
        assert!(
            journal::request(&client, server.peer_id(), Request::Execute { command })
                .await?
                .error
                .is_some()
        );
        task.abort();
        let _ = task.await;
        client.shutdown().await?;
        stranger.shutdown().await?;
        let node = Arc::try_unwrap(server).map_err(|_| "server retained")?;
        node.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
