use identity::Identity;
use node::{AccessPolicy, Node, NodeConfig, Service, ServiceId};
use std::time::Duration;
use tokio::time::{sleep, timeout};
#[tokio::test]
async fn service_discovery_through_seed_then_authenticated_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = Node::start(
        Identity::generate(),
        NodeConfig {
            discovery_server: true,
            ..Default::default()
        },
    )
    .await?;
    let host = Node::start(
        Identity::generate(),
        NodeConfig {
            discovery_server: true,
            bootstrap: seed.addresses(),
            ..Default::default()
        },
    )
    .await?;
    let client = Node::start(
        Identity::generate(),
        NodeConfig {
            bootstrap: seed.addresses(),
            ..Default::default()
        },
    )
    .await?;
    host.dial(seed.addresses()[0].clone()).await?;
    client.dial(seed.addresses()[0].clone()).await?;
    let id = ServiceId::new();
    let service = Service {
        metadata: serde_json::to_vec(&protocol::RoomMetadata {
            school: "other-school".into(),
            version: "26.3".into(),
            players_max: 12,
        })?,
        id,
        name: "Discovered game".into(),
        protocol: protocol::ROOM_PROTOCOL.into(),
        access: AccessPolicy::Deny,
    };
    timeout(Duration::from_secs(20), async {
        loop {
            host.publish(service.clone()).await?;
            if client.discover(id).await?.contains(&host.peer_id()) {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, protocol::Error>(())
    })
    .await??;
    assert!(
        client
            .discover_protocol(protocol::ROOM_PROTOCOL)
            .await?
            .contains(&host.peer_id())
    );
    let rooms = client::rooms::discover(&client, &seed.addresses()).await?;
    assert!(
        rooms
            .rooms
            .iter()
            .any(|r| r.peer == host.peer_id().to_string() && r.metadata.school == "other-school")
    );
    let found = client.list_services(host.peer_id()).await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, id.to_string());
    assert!(client.open_service(host.peer_id(), id).await.is_err());
    host.withdraw(id).await;
    assert!(client.list_services(host.peer_id()).await?.is_empty());
    client.shutdown().await?;
    host.shutdown().await?;
    seed.shutdown().await?;
    Ok(())
}
