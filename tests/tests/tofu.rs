#[path = "../support/mod.rs"]
mod support;
use identity::{Identity, trust::TrustState};
use journal::{journal::Journal, trust::TrustLog};
use node::{Node, NodeConfig};
use state::{EmptyDomain, State};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use wire::protocol::{
    TrustBusinessBinding, TrustCheckpoint, TrustFounder, TrustGenesis, TrustRequest, digest,
};

#[tokio::test]
async fn identity_genesis_discovery_round_trips_and_bypasses_the_stale_view_gate() {
    let roots: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
    let genesis = TrustGenesis {
        federation: "test-federation".into(),
        quorum: 2,
        founders: roots
            .iter()
            .enumerate()
            .map(|(i, key)| TrustFounder {
                member: format!("founder-{i}"),
                club: format!("club-{i}"),
                public_key: key.public_key().encode_protobuf(),
            })
            .collect(),
    };
    let pin = TrustState::genesis_digest(&genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log = TrustLog::open(&dir.path().join("identity.jsonl"), &genesis, &pin).unwrap();
    let checkpoint: TrustCheckpoint = log.state().checkpoint().clone();
    // A read-only replica that never reached the authenticated head serves discovery but not reads.
    let view = log.view(Duration::from_secs(60)).unwrap();
    assert!(view.state().is_err());
    let log = Arc::new(Mutex::new(log));
    let server = Arc::new(
        Node::start(Identity::generate(), NodeConfig::default())
            .await
            .unwrap(),
    );
    let task = tokio::spawn({
        let server = server.clone();
        let log = log.clone();
        async move { authority::trust::serve_with_view(&server, log, false, view).await }
    });
    tokio::task::yield_now().await;
    let client = Node::start(Identity::generate(), NodeConfig::default())
        .await
        .unwrap();
    let peer = server.peer_id().to_string();
    let address = format!("{}/p2p/{}", server.addresses()[0], peer);
    let (found, found_pin) = client::trust::fetch_identity_genesis(&client, &address, &peer)
        .await
        .unwrap();
    assert_eq!(found, genesis);
    assert_eq!(found_pin, pin);
    // Reads still pass through the freshness gate and stay rejected on a stale view.
    let read =
        authority::trust::request(&client, server.peer_id(), TrustRequest::Read { checkpoint })
            .await
            .unwrap();
    assert!(read.error.is_some());
    assert!(read.genesis.is_none());
    // The multiaddr must name the dialed peer as its final /p2p/ segment.
    let wrong_peer = Identity::generate().peer_id().to_string();
    let wrong_address = format!("{}/p2p/{}", server.addresses()[0], wrong_peer);
    assert!(
        client::trust::fetch_identity_genesis(&client, &wrong_address, &peer)
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
    client.shutdown().await.unwrap();
    Arc::try_unwrap(server)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test]
async fn business_genesis_discovery_round_trips_and_rejects_binding_mismatch() {
    let admin = Identity::generate();
    let identities = support::Identities::new(&[(&admin, "admin", "jlu")], "admin");
    let expected = identities.genesis::<EmptyDomain>();
    let expected_pin = digest(&serde_json::to_vec(&expected).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let business = Arc::new(Mutex::new(
        Journal::open(dir.path().join("journal"), expected.clone()).unwrap(),
    ));
    let server = Arc::new(Node::start(admin, NodeConfig::default()).await.unwrap());
    let task = tokio::spawn({
        let server = server.clone();
        let business = business.clone();
        let view = identities.log.view(Duration::from_secs(60)).unwrap();
        async move { authority::journal::serve(&server, business, view).await }
    });
    tokio::task::yield_now().await;
    let client = Node::start(Identity::generate(), NodeConfig::default())
        .await
        .unwrap();
    let peer = server.peer_id().to_string();
    let address = format!("{}/p2p/{}", server.addresses()[0], peer);
    let (found, pin) = client::trust::fetch_business_genesis::<EmptyDomain>(
        &client,
        &address,
        &peer,
        &identities.binding.genesis,
    )
    .await
    .unwrap();
    assert_eq!(found, expected);
    assert_eq!(pin, expected_pin);
    // A business pin that does not match the confirmed identity genesis is rejected.
    assert!(
        client::trust::fetch_business_genesis::<EmptyDomain>(
            &client,
            &address,
            &peer,
            &"0".repeat(64),
        )
        .await
        .is_err()
    );
    task.abort();
    let _ = task.await;
    // A binding whose audience names a different peer than the serving node is rejected,
    // even when the identity pin matches.
    let bad_binding = TrustBusinessBinding {
        audience: Identity::generate().peer_id().to_string(),
        ..identities.binding.clone()
    };
    let bad = Arc::new(Mutex::new(
        Journal::open(
            dir.path().join("journal-mismatched"),
            State::<EmptyDomain>::new(bad_binding).unwrap(),
        )
        .unwrap(),
    ));
    let server = Arc::new(
        Node::start(Identity::generate(), NodeConfig::default())
            .await
            .unwrap(),
    );
    let task = tokio::spawn({
        let server = server.clone();
        let bad = bad.clone();
        let view = identities.log.view(Duration::from_secs(60)).unwrap();
        async move { authority::journal::serve(&server, bad, view).await }
    });
    tokio::task::yield_now().await;
    let address = format!("{}/p2p/{}", server.addresses()[0], server.peer_id());
    assert!(
        client::trust::fetch_business_genesis::<EmptyDomain>(
            &client,
            &address,
            &server.peer_id().to_string(),
            &identities.binding.genesis,
        )
        .await
        .is_err()
    );
    task.abort();
    let _ = task.await;
    client.shutdown().await.unwrap();
    Arc::try_unwrap(server)
        .ok()
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}
