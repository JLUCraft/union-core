use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use union_core::{
    AccessPolicy, Error, Grant, Identity, Multiaddr, Node, NodeConfig, RelayConfig, Service,
    ServiceId, SignedGrant,
};

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
    let mut stream = client.open_service(server.peer_id(), id, None).await?;
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
        client.open_service(server.peer_id(), id, None).await,
        Err(Error::NotFound)
    ));
    Ok(())
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
async fn admission_denies_missing_grants_and_limits_active_sessions() -> TestResult {
    timeout(Duration::from_secs(30), async {
        let issuer = Identity::generate();
        let mut server = Node::start(
            Identity::generate(),
            NodeConfig {
                max_sessions: 1,
                ..NodeConfig::default()
            },
        )
        .await?;
        let client = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let id = ServiceId::new();
        server
            .publish(service(
                id,
                AccessPolicy::Grants {
                    issuers: [issuer.peer_id()].into(),
                    revoked: Default::default(),
                },
            ))
            .await?;
        client.dial(server.addresses()[0].clone()).await?;
        assert!(matches!(
            client.open_service(server.peer_id(), id, None).await,
            Err(Error::Denied)
        ));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let ticket = SignedGrant::issue(
            &issuer,
            Grant {
                subject: client.peer_id(),
                audience: server.peer_id(),
                service: id,
                not_before: now,
                expires_at: now + 60,
            },
        )?;
        let mut incoming = server.take_incoming()?;
        let first = client
            .open_service(server.peer_id(), id, Some(ticket.clone()))
            .await?;
        let accepted = incoming.recv().await.ok_or("missing authorized session")?;
        assert!(matches!(
            client
                .open_service(server.peer_id(), id, Some(ticket.clone()))
                .await,
            Err(Error::Capacity)
        ));
        drop(accepted);
        drop(first);
        server
            .publish(service(
                id,
                AccessPolicy::Grants {
                    issuers: [issuer.peer_id()].into(),
                    revoked: [ticket.id()?].into(),
                },
            ))
            .await?;
        assert!(matches!(
            client
                .open_service(server.peer_id(), id, Some(ticket))
                .await,
            Err(Error::Denied)
        ));
        client.shutdown().await?;
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
        wrong.push(union_core::AddressProtocol::P2p(
            Identity::generate().peer_id(),
        ));
        assert!(client.dial(wrong).await.is_err());
        client.dial(server.addresses()[0].clone()).await?;
        let id = ServiceId::new();
        server.publish(service(id, AccessPolicy::default())).await?;
        assert!(matches!(
            client.open_service(server.peer_id(), id, None).await,
            Err(Error::Denied)
        ));
        client.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn school_credential_admission_binds_device_and_exposes_verified_profile() -> TestResult {
    use union_core::federation::*;
    timeout(Duration::from_secs(20), async {
        let root = Identity::generate();
        let issuer = Identity::generate();
        let holder = Identity::generate();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let delegation = delegate(
            &root,
            StudentDelegation {
                id: "d".into(),
                school: "jlu".into(),
                issuer: issuer.peer_id().to_string(),
                not_before: now - 1,
                expires_at: now + 3600,
                max_credential_seconds: 3600,
                evidence: vec![Evidence::InstitutionalEmail],
            },
        )?;
        let credential = issue(
            &issuer,
            delegation,
            StudentClaims {
                id: "c".into(),
                school: "jlu".into(),
                subject: "student".into(),
                game_profile: "game-uuid".into(),
                holder: holder.peer_id().to_string(),
                evidence: Evidence::InstitutionalEmail,
                verified_at: now,
                issued_at: now,
                expires_at: now + 300,
            },
        )?;
        let proof = StudentPresentation {
            credential,
            profile: "game-uuid".into(),
        };
        let trust = TrustPolicy {
            local_school: "jlu".into(),
            province_schools: Default::default(),
            mua_schools: Default::default(),
            school_roots: [("jlu".into(), [root.peer_id().to_string()].into())].into(),
            revoked: Default::default(),
            max_verification_age_seconds: 3600,
        };
        let id = ServiceId::new();
        let mut server = Node::start(Identity::generate(), NodeConfig::default()).await?;
        let client = Node::start(holder, NodeConfig::default()).await?;
        let stranger = Node::start(Identity::generate(), NodeConfig::default()).await?;
        server
            .publish(service(
                id,
                AccessPolicy::Students {
                    trust: Box::new(trust.clone()),
                    minimum: Circle::Local,
                    current_enrollment: false,
                },
            ))
            .await?;
        client.dial(server.addresses()[0].clone()).await?;
        stranger.dial(server.addresses()[0].clone()).await?;
        assert!(
            client
                .open_service(server.peer_id(), id, None)
                .await
                .is_err()
        );
        assert!(
            stranger
                .open_student_service(server.peer_id(), id, &proof)
                .await
                .is_err()
        );
        let stream = client
            .open_student_service(server.peer_id(), id, &proof)
            .await?;
        let mut incoming = server.take_incoming()?;
        let session = incoming.recv().await.ok_or("missing student session")?;
        assert_eq!(
            session
                .student
                .ok_or("missing verified claims")?
                .game_profile,
            "game-uuid"
        );
        drop(session.stream);
        drop(stream);
        server.withdraw(id).await;
        server
            .publish(service(
                id,
                AccessPolicy::Students {
                    trust: Box::new(trust),
                    minimum: Circle::Local,
                    current_enrollment: true,
                },
            ))
            .await?;
        assert!(
            client
                .open_student_service(server.peer_id(), id, &proof)
                .await
                .is_err()
        );
        client.shutdown().await?;
        stranger.shutdown().await?;
        server.shutdown().await?;
        TestResult::Ok(())
    })
    .await?
}
