#[path = "../support/mod.rs"]
mod support;
use authority::journal::TrustedCommand;
use identity::Identity;
use league::{
    governance::Action,
    journal::{self, Command, Journal, Request, SignedCommand},
};
use node::{Node, NodeConfig};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[tokio::test]
async fn governance_binds_signed_actor_to_authenticated_stream_and_rejects_replay()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let admin = Identity::generate();
        let outsider = Identity::generate();
        let directory = tempfile::tempdir()?;
        let identities = support::Identities::new(&[(&admin, "admin", "jlu")], "admin");
        let view = identities.log.view(Duration::from_secs(60))?;
        let journal = Arc::new(Mutex::new(Journal::open(
            directory.path().join("journal"),
            identities.genesis(),
        )?));
        let genesis_hash = journal.lock().await.genesis_hash().to_owned();
        let server = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
        let task = {
            let node = server.clone();
            let journal = journal.clone();
            tokio::spawn(async move { journal::serve(&node, journal, view).await })
        };
        // Protocol registration runs on the spawned server task before dialing.
        tokio::task::yield_now().await;
        let client = Node::start(admin.clone(), NodeConfig::default()).await?;
        let stranger = Node::start(outsider, NodeConfig::default()).await?;
        client.dial(server.addresses()[0].clone()).await?;
        stranger.dial(server.addresses()[0].clone()).await?;
        assert!(
            journal::request(
                &stranger,
                server.peer_id(),
                &genesis_hash,
                Request::Snapshot
            )
            .await?
            .state
            .is_none()
        );
        let command = SignedCommand::sign(
            &admin,
            TrustedCommand {
                genesis: genesis_hash.clone(),
                previous: journal.lock().await.head()?,
                identity: identities.log.state().checkpoint().clone(),
                command: Command {
                    revision: 0,
                    expires_ms: journal::now_ms()? + 10_000,
                    action: Action::AnchorDigest {
                        id: "anchor".into(),
                        digest: "a".repeat(64),
                    },
                },
            },
        )?;
        let history = identities.log.history_since(None)?;
        let wrong = journal::request(
            &client,
            server.peer_id(),
            &"0".repeat(64),
            Request::Execute {
                history: history.clone(),
                command: command.clone(),
            },
        )
        .await?;
        assert!(wrong.error.is_some());
        assert_eq!(
            journal.lock().await.state().revision,
            0,
            "wrong deployment must not execute a command"
        );
        assert!(
            journal::request(
                &stranger,
                server.peer_id(),
                &genesis_hash,
                Request::Execute {
                    history: history.clone(),
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
                &genesis_hash,
                Request::Execute {
                    history: history.clone(),
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
            journal::request(
                &client,
                server.peer_id(),
                &genesis_hash,
                Request::Execute {
                    history: history.clone(),
                    command
                }
            )
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
