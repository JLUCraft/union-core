use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt};
use node::{AccessPolicy, Identity, Node, NodeConfig, Service, ServiceId};
use std::time::Duration;
use terminal_runtime::{LocalProxy, TargetArgs};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

#[tokio::test]
async fn owned_proxy_transfers_half_close_and_closes_listener_on_drop() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut host = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let player = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let expected = player.peer_id();
        let service = ServiceId::new();
        host.publish(Service {
            metadata: Vec::new(),
            id: service,
            name: "game".into(),
            protocol: "test/echo".into(),
            access: AccessPolicy::Peers([expected].into()),
        })
        .await?;
        let proxy = LocalProxy::start(
            player,
            TargetArgs {
                peer: host.peer_id(),
                address: host.addresses(),
            },
            service,
            "127.0.0.1:0".parse()?,
        )
        .await?;
        let address = proxy.address();
        assert!(proxy.is_running());
        let mut incoming = host.take_incoming()?;
        let echo = tokio::spawn(async move {
            let mut session = incoming
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("no session"))?;
            assert_eq!(session.peer, expected);
            let mut bytes = Vec::new();
            session.stream.read_to_end(&mut bytes).await?;
            session.stream.write_all(&bytes).await?;
            session.stream.close().await?;
            Ok::<_, anyhow::Error>(())
        });
        let mut local = TcpStream::connect(address).await?;
        local.write_all(b"owned-proxy").await?;
        local.shutdown().await?;
        let mut result = Vec::new();
        local.read_to_end(&mut result).await?;
        assert_eq!(result, b"owned-proxy");
        echo.await??;
        drop(local);
        drop(proxy);
        // Abort is scheduled; yield until the OS listener has actually closed.
        timeout(Duration::from_secs(2), async {
            loop {
                if TcpStream::connect(address).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        host.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn bootstrap_connection_can_also_reserve_a_relay() -> Result<()> {
    let relay = Node::start(
        Identity::generate(),
        NodeConfig {
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse()?],
            relay: Some(node::RelayConfig::default()),
            ..Default::default()
        },
    )
    .await?;
    let address = relay.addresses()[0].clone();
    let mut external = address.clone();
    external.pop();
    relay.add_external_address(external).await?;
    let host = Node::start(
        Identity::generate(),
        NodeConfig {
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse()?],
            bootstrap: vec![address.clone()],
            ..Default::default()
        },
    )
    .await?;
    let result = terminal_runtime::reserve_relays(&host, &[address]).await;
    if result.is_ok() {
        assert!(
            host.addresses()
                .iter()
                .any(|a| a.to_string().contains("/p2p-circuit/"))
        );
    }
    host.shutdown().await?;
    relay.shutdown().await?;
    result
}
