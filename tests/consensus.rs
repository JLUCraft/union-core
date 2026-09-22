#![cfg(feature = "consensus")]
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};
use union_core::{
    Identity, Node, NodeConfig,
    consensus::{Cluster, Peer, Store},
    governance::{Action, State},
    journal::{Command, SignedCommand, now_ms},
};
type R = Result<(), Box<dyn std::error::Error>>;
async fn leader(
    clusters: &[Arc<Cluster>],
    excluded: Option<u64>,
) -> Result<Arc<Cluster>, Box<dyn std::error::Error>> {
    Ok(timeout(Duration::from_secs(20), async {
        loop {
            for cluster in clusters {
                if Some(cluster.id) != excluded
                    && cluster.raft.metrics().borrow().state == openraft::ServerState::Leader
                {
                    return cluster.clone();
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_commit_elect_after_leader_loss_and_restore_durable_state() -> R {
    let admin = Identity::generate();
    let genesis = State::new([admin.peer_id().to_string()].into())?;
    let dir = tempfile::tempdir()?;
    let mut nodes = Vec::new();
    for _ in 0..3 {
        nodes.push(Arc::new(
            Node::start(Identity::generate(), NodeConfig::default()).await?,
        ));
    }
    let peers: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            (
                (i + 1) as u64,
                Peer {
                    peer: node.peer_id().to_string(),
                    addresses: node
                        .addresses()
                        .into_iter()
                        .map(|a| a.to_string())
                        .collect(),
                },
            )
        })
        .collect();
    let mut clusters = Vec::new();
    let mut tasks = Vec::new();
    for (i, node) in nodes.into_iter().enumerate() {
        let c = Cluster::start(
            (i + 1) as u64,
            node,
            &dir.path().join(format!("raft-{i}")),
            genesis.clone(),
            peers.clone(),
        )
        .await?;
        tasks.push(tokio::spawn(c.clone().serve()));
        clusters.push(c);
    }
    tokio::task::yield_now().await;
    clusters[0].initialize().await?;
    let first = leader(&clusters, None).await?;
    let command = SignedCommand::sign(
        &admin,
        Command {
            revision: 0,
            expires_ms: now_ms()? + 60000,
            action: Action::Enroll {
                member: "first".into(),
                club: "jlu".into(),
                device: Identity::generate().peer_id().to_string(),
            },
        },
    )?;
    assert!(
        first
            .execute(admin.peer_id(), command)
            .await?
            .error
            .is_none()
    );
    timeout(Duration::from_secs(5), async {
        loop {
            let mut done = true;
            for c in &clusters {
                done &= c.store.state().await.revision == 1;
            }
            if done {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let failed = first.id;
    first.shutdown().await?;
    tasks[(failed - 1) as usize].abort();
    let second = leader(&clusters, Some(failed)).await?;
    let command = SignedCommand::sign(
        &admin,
        Command {
            revision: 1,
            expires_ms: now_ms()? + 60000,
            action: Action::Enroll {
                member: "second".into(),
                club: "other".into(),
                device: Identity::generate().peer_id().to_string(),
            },
        },
    )?;
    assert!(
        second
            .execute(admin.peer_id(), command)
            .await?
            .error
            .is_none()
    );
    assert_eq!(second.snapshot(admin.peer_id()).await?.revision, 2);
    let restored_index = (second.id - 1) as usize;
    second.raft.trigger().snapshot().await?;
    for c in &clusters {
        let _ = c.shutdown().await;
    }
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    drop(first);
    drop(second);
    drop(clusters);
    let store = Store::open(
        &dir.path().join(format!("raft-{restored_index}")),
        Cluster::genesis(genesis, &peers)?,
    )?;
    assert_eq!(store.state().await.revision, 2);
    assert!(store.state().await.members.contains_key("second"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approved_membership_catches_up_learners_and_followers_forward_signed_commands() -> R {
    let admin = Identity::generate();
    let genesis = State::new([admin.peer_id().to_string()].into())?;
    let dir = tempfile::tempdir()?;
    let mut nodes = Vec::new();
    for _ in 0..3 {
        nodes.push(Arc::new(
            Node::start(Identity::generate(), NodeConfig::default()).await?,
        ));
    }
    let peers: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                (i + 1) as u64,
                Peer {
                    peer: n.peer_id().to_string(),
                    addresses: n.addresses().iter().map(ToString::to_string).collect(),
                },
            )
        })
        .collect();
    let initial = BTreeMap::from([(1, peers[&1].clone())]);
    let mut clusters = Vec::new();
    let mut tasks = Vec::new();
    for (i, node) in nodes.into_iter().enumerate() {
        let c = Cluster::start(
            (i + 1) as u64,
            node,
            &dir.path().join(format!("node-{i}")),
            genesis.clone(),
            initial.clone(),
        )
        .await?;
        tasks.push(tokio::spawn(c.clone().serve()));
        clusters.push(c);
    }
    clusters[0].initialize().await?;
    leader(&clusters, None).await?;
    let command = SignedCommand::sign(
        &admin,
        Command {
            revision: 0,
            expires_ms: now_ms()? + 60000,
            action: Action::SetConsensusMembers {
                members: peers.clone(),
            },
        },
    )?;
    assert!(
        clusters[0]
            .execute(admin.peer_id(), command)
            .await?
            .error
            .is_none()
    );
    timeout(Duration::from_secs(20), async {
        loop {
            if clusters.iter().all(|c| {
                c.raft
                    .metrics()
                    .borrow()
                    .membership_config
                    .membership()
                    .voter_ids()
                    .count()
                    == 3
            }) {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    assert_eq!(clusters[2].snapshot(admin.peer_id()).await?.revision, 1);
    let command = SignedCommand::sign(
        &admin,
        Command {
            revision: 1,
            expires_ms: now_ms()? + 60000,
            action: Action::Enroll {
                member: "via-follower".into(),
                club: "jlu".into(),
                device: Identity::generate().peer_id().to_string(),
            },
        },
    )?;
    assert!(
        clusters[2]
            .execute(admin.peer_id(), command.clone())
            .await?
            .error
            .is_none()
    );
    assert!(
        clusters[1].execute(admin.peer_id(), command).await.is_err(),
        "replay must not be accepted"
    );
    let outsider = Identity::generate();
    assert!(clusters[2].snapshot(outsider.peer_id()).await.is_err());
    let command = SignedCommand::sign(
        &outsider,
        Command {
            revision: 2,
            expires_ms: now_ms()? + 60000,
            action: Action::SetConsensusMembers { members: initial },
        },
    )?;
    assert!(
        clusters[2]
            .execute(outsider.peer_id(), command)
            .await
            .is_err()
    );
    assert_eq!(clusters[0].snapshot(admin.peer_id()).await?.revision, 2);
    for c in &clusters {
        c.shutdown().await?;
    }
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    Ok(())
}
