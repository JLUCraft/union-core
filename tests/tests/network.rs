use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt};
use identity::Identity;
use node::{AccessPolicy, Error, Multiaddr, Node, NodeConfig, RelayConfig, Service, ServiceId};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn config(address: &str) -> Result<NodeConfig, Box<dyn std::error::Error + Send + Sync>> {
    Ok(NodeConfig {
        listen: vec![address.parse()?],
        hole_punching: false,
        ..NodeConfig::default()
    })
}

fn service(id: ServiceId, access: AccessPolicy) -> Service {
    Service {
        metadata: Vec::new(),
        id,
        name: "test service".into(),
        protocol: "test/echo".into(),
        access,
    }
}

async fn transfer(client: &Node, server: &mut Node) -> TestResult {
    let id = ServiceId::new();
    server.publish(service(id, AccessPolicy::Public)).await?;
    let records = client.list_services(server.peer_id()).await?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id.to_string());
    let mut incoming = server.take_incoming()?;
    let expected_peer = client.peer_id();
    let echo = tokio::spawn(async move {
        let mut session = incoming.recv().await.ok_or("missing session")?;
        assert_eq!(session.peer, expected_peer);
        assert_eq!(session.service, id);
        let mut bytes = Vec::new();
        session.stream.read_to_end(&mut bytes).await?;
        session.stream.write_all(&bytes).await?;
        session.stream.close().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut stream = client.open_service(server.peer_id(), id).await?;
    // Larger than the upstream relay's default 128 KiB circuit quota.
    let payload: Vec<u8> = (0..300_000).map(|n| (n % 251) as u8).collect();
    stream.write_all(&payload).await?;
    stream.close().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    assert_eq!(response, payload);
    echo.await??;
    server.withdraw(id).await;
    assert!(client.list_services(server.peer_id()).await?.is_empty());
    assert!(matches!(
        client.open_service(server.peer_id(), id).await,
        Err(Error::NotFound)
    ));
    Ok(())
}

#[tokio::test]
async fn default_nodes_publish_dialable_interface_addresses() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut server = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let address = server.addresses().into_iter().find(|address| {
            address.iter().any(|part| {
                matches!(part, node::AddressProtocol::Ip4(ip) if !ip.is_loopback() && !ip.is_unspecified())
            })
        });
        let Some(address) = address else {
            server.shutdown().await?;
            return Err("default node has no interface address for remote peers".into());
        };
        let client = Node::start(Identity::generate(), NodeConfig::default()).await?;
        client.dial(address).await?;
        transfer(&client, &mut server).await?;
        client.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn short_lived_terminals_release_their_peer_connections() -> TestResult {
    const TERMINAL_RESTARTS: usize = 8;
    timeout(Duration::from_secs(30), async {
        let host = Node::start(
            Identity::generate(),
            NodeConfig {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse()?],
                ..NodeConfig::default()
            },
        )
        .await?;
        let identity = Identity::generate();
        for index in 0..TERMINAL_RESTARTS {
            let identity = identity.clone();
            let address = host.addresses()[0].clone();
            let peer = host.peer_id();
            tokio::task::spawn_blocking(move || -> node::Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|error| Error::Network(error.to_string()))?;
                runtime.block_on(async move {
                    let client = Node::start(identity, NodeConfig::default()).await?;
                    client.dial(address).await?;
                    client.list_services(peer).await?;
                    client.shutdown().await
                })
            })
            .await?
            .map_err(|error| format!("terminal restart {index}: {error}"))?;
        }
        host.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn direct_quic_directory_stream_and_half_close() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut server = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let client = Node::start(Identity::generate(), NodeConfig::default()).await?;
        client.dial(server.addresses()[0].clone()).await?;
        transfer(&client, &mut server).await?;
        client.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn direct_tcp_noise_directory_and_stream() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut server = Node::start(Identity::generate(), config("/ip4/127.0.0.1/tcp/0")?).await?;
        let client = Node::start(Identity::generate(), config("/ip4/127.0.0.1/tcp/0")?).await?;
        client.dial(server.addresses()[0].clone()).await?;
        transfer(&client, &mut server).await?;
        client.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn relay_only_route_preserves_end_to_end_identity_and_stream() -> TestResult {
    timeout(Duration::from_secs(40), async {
        let relay = Node::start(
            Identity::generate(),
            NodeConfig {
                relay: Some(RelayConfig::default()),
                ..config("/ip4/127.0.0.1/tcp/0")?
            },
        )
        .await?;
        let relay_address = relay.addresses()[0].clone();
        let mut external = relay_address.clone();
        external.pop();
        relay.add_external_address(external).await?;
        let embedded_service = ServiceId::new();
        relay
            .publish(service(embedded_service, AccessPolicy::Public))
            .await?;
        let mut server = Node::start(Identity::generate(), config("/ip4/127.0.0.1/tcp/0")?).await?;
        let circuit: Multiaddr = format!("{relay_address}/p2p-circuit").parse()?;
        server.listen_on(circuit.clone()).await?;
        let circuit: Multiaddr = format!("{circuit}/p2p/{}", server.peer_id()).parse()?;
        let mut addresses = server.watch_addresses();
        loop {
            if addresses.borrow().contains(&circuit) {
                break;
            }
            addresses.changed().await?;
        }
        let client = Node::start(Identity::generate(), config("/ip4/127.0.0.1/tcp/0")?).await?;
        // Never dial the game's direct address; DCUtR is disabled on both ends.
        client.dial(circuit.clone()).await?;
        // A relay may simultaneously host a service; no exclusive role assignment.
        assert_eq!(
            client.list_services(relay.peer_id()).await?[0].id,
            embedded_service.to_string()
        );
        transfer(&client, &mut server).await?;
        client.shutdown().await?;
        relay.shutdown().await?;
        // A lost reservation must disappear instead of advertising a stale route.
        while addresses.borrow().contains(&circuit) {
            addresses.changed().await?;
        }
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn wrong_target_identity_and_default_deny_fail_closed() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let server = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let client = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let mut wrong = server.addresses()[0].clone();
        wrong.pop();
        wrong.push(node::AddressProtocol::P2p(Identity::generate().peer_id()));
        assert!(client.dial(wrong).await.is_err());
        client.dial(server.addresses()[0].clone()).await?;
        let id = ServiceId::new();
        server.publish(service(id, AccessPolicy::default())).await?;
        assert!(matches!(
            client.open_service(server.peer_id(), id).await,
            Err(Error::Denied)
        ));
        client.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}
