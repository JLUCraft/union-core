#[path = "../support/mod.rs"]
mod support;
use authority::journal::{self, JsonFrame, Request};
use futures::StreamExt;
use identity::Identity;
type Journal = authority::journal::Journal<client::application::Application>;
use node::{Node, NodeConfig};
use state::governance::Member;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::timeout};
#[tokio::test]
async fn snapshot_exceeds_single_frame_and_rejects_out_of_order_chunks()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let admin = Identity::generate();
        let identities = support::Identities::new(&[(&admin, "admin", "jlu")], "admin");
        let view = identities.log.view(Duration::from_secs(60))?;
        let mut state: client::application::Snapshot = identities.genesis();
        for i in 0..900 {
            state.members.insert(
                format!("member-{i}"),
                Member {
                    club: "jlu".into(),
                    additional_devices: Default::default(),
                    roles: Default::default(),
                    device: Identity::generate().peer_id().to_string(),
                },
            );
        }
        assert!(serde_json::to_vec(&state)?.len() > protocol::MAX_FRAME);
        let journal = Arc::new(Mutex::new(Journal::open(
            dir.path().join("journal"),
            state.clone(),
        )?));
        let genesis_hash = journal.lock().await.genesis_hash().to_owned();
        let host = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
        let server = host.clone();
        let serving =
            tokio::spawn(
                async move { journal::serve(&server, journal, view, journal::PROTOCOL).await },
            );
        let client = Node::start(admin, NodeConfig::default()).await?;
        client.dial(host.addresses()[0].clone()).await?;
        let response = journal::request::<client::application::Application>(
            &client,
            host.peer_id(),
            &genesis_hash,
            Request::Snapshot,
            journal::PROTOCOL,
        )
        .await?;
        assert_eq!(response.state, Some(state));
        response.verify(&genesis_hash)?;
        assert!(response.proof.as_ref().unwrap().observed_ms > 0);
        assert!(response.verify(&"0".repeat(64)).is_err());
        let mut tampered = response.clone();
        tampered.state.as_mut().ok_or("missing state")?.revision += 1;
        assert!(tampered.verify(&genesis_hash).is_err());
        let mut missing = response.clone();
        missing.proof = None;
        assert!(missing.verify(&genesis_hash).is_err());
        let rogue = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let mut incoming = rogue.accept_protocol(journal::PROTOCOL)?;
        client.dial(rogue.addresses()[0].clone()).await?;
        let attack = tokio::spawn(async move {
            let (_, mut stream) = incoming.next().await.ok_or(protocol::Error::Stopped)?;
            let _: JsonFrame = protocol::read_frame(&mut stream).await?;
            protocol::write_frame(
                &mut stream,
                &JsonFrame {
                    json: b"{}".to_vec(),
                    sequence: 1,
                    last: true,
                },
            )
            .await
        });
        assert!(
            journal::request::<client::application::Application>(
                &client,
                rogue.peer_id(),
                &genesis_hash,
                Request::Snapshot,
                journal::PROTOCOL
            )
            .await
            .is_err()
        );
        attack.await??;
        serving.abort();
        client.shutdown().await?;
        rogue.shutdown().await?;
        drop(host);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}
