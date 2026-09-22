use futures::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::timeout};
use union_core::{
    Identity, Node, NodeConfig,
    governance::{Member, State},
    journal::{self, Journal, JsonFrame, Request},
    protocol,
};
#[tokio::test]
async fn snapshot_exceeds_single_frame_and_rejects_out_of_order_chunks()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let admin = Identity::generate();
        let mut state = State::new([admin.peer_id().to_string()].into())?;
        for i in 0..900 {
            state.members.insert(
                format!("member-{i}"),
                Member {
                    club: "jlu".into(),
                    additional_devices: Default::default(),
                    device: Identity::generate().peer_id().to_string(),
                },
            );
        }
        assert!(serde_json::to_vec(&state)?.len() > protocol::MAX_FRAME);
        let journal = Arc::new(Mutex::new(Journal::open(
            dir.path().join("journal"),
            state.clone(),
        )?));
        let host = Arc::new(Node::start(Identity::generate(), NodeConfig::default()).await?);
        let server = host.clone();
        let serving = tokio::spawn(async move { journal::serve(&server, journal).await });
        let client = Node::start(admin, NodeConfig::default()).await?;
        client.dial(host.addresses()[0].clone()).await?;
        assert_eq!(
            journal::request(&client, host.peer_id(), Request::Snapshot)
                .await?
                .state,
            Some(state)
        );
        let rogue = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let mut incoming = rogue.accept_protocol(journal::PROTOCOL)?;
        client.dial(rogue.addresses()[0].clone()).await?;
        let attack = tokio::spawn(async move {
            let (_, mut stream) = incoming.next().await.ok_or(union_core::Error::Stopped)?;
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
            journal::request(&client, rogue.peer_id(), Request::Snapshot)
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
