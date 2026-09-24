//! Terminal assembly helpers. No application-specific policy lives in union-core.
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use union_core::{
    AccessPolicy, Identity, Multiaddr, Node, NodeConfig, PeerId, RelayConfig, ServiceId,
    SignedGrant,
};

#[derive(Clone, Debug, Args)]
pub struct NodeArgs {
    /// Persistent device key. Create it with union-manager keygen first.
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    pub listen: Vec<Multiaddr>,
    /// Operator-confirmed publicly reachable listen addresses (without local PeerId).
    #[arg(long)]
    pub external: Vec<Multiaddr>,
    /// Offer relay capacity from this process, independently of game permissions.
    #[arg(long)]
    pub relay: bool,
    #[arg(long, default_value_t = 128)]
    pub relay_circuits: usize,
    #[arg(long, default_value_t = 268435456)]
    pub relay_bytes: u64,
    #[arg(long, default_value_t = 3600)]
    pub relay_seconds: u64,
    /// Relay address ending in /p2p/RELAY; may be repeated for redundancy.
    #[arg(long)]
    pub reserve: Vec<Multiaddr>,
    /// Redundant federation discovery seeds. Failure never terminates an existing session.
    #[arg(long)]
    pub bootstrap: Vec<Multiaddr>,
    #[arg(long)]
    pub discovery_server: bool,
    #[arg(long)]
    pub lan_discovery: bool,
}

impl NodeArgs {
    pub async fn start(&self, standalone_relay: bool) -> Result<Node> {
        let node = Node::start(
            Identity::load(&self.key)?,
            NodeConfig {
                listen: self.listen.clone(),
                bootstrap: self.bootstrap.clone(),
                discovery_server: self.discovery_server || standalone_relay,
                lan_discovery: self.lan_discovery,
                external_addresses: self.external.clone(),
                relay: (self.relay || standalone_relay).then_some(RelayConfig {
                    max_circuits: self.relay_circuits,
                    max_circuit_bytes: self.relay_bytes,
                    max_circuit_duration: Duration::from_secs(self.relay_seconds),
                    ..RelayConfig::default()
                }),
                ..NodeConfig::default()
            },
        )
        .await?;
        for relay in &self.reserve {
            if !matches!(
                relay.iter().last(),
                Some(union_core::AddressProtocol::P2p(_))
            ) {
                bail!("--reserve must end in /p2p/RELAY");
            }
            let circuit: Multiaddr = format!("{relay}/p2p-circuit").parse()?;
            node.listen_on(circuit.clone()).await?;
            let expected = format!("{circuit}/p2p/{}", node.peer_id());
            let mut addresses = node.watch_addresses();
            timeout(Duration::from_secs(20), async {
                loop {
                    if addresses.borrow().iter().any(|a| a.to_string() == expected) {
                        break;
                    }
                    addresses
                        .changed()
                        .await
                        .context("node stopped while reserving relay")?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("relay reservation timed out")??;
        }
        tracing::info!(peer = %node.peer_id(), addresses = ?node.addresses(), "node ready");
        Ok(node)
    }
}

#[derive(Clone, Debug, Args)]
pub struct TargetArgs {
    /// Expected host device identity; verified even through a relay.
    #[arg(long)]
    pub peer: PeerId,
    /// Candidate addresses ending in /p2p/PEER, tried in order.
    #[arg(long, required = true)]
    pub address: Vec<Multiaddr>,
}

impl TargetArgs {
    pub async fn connect(&self, node: &Node) -> Result<()> {
        let suffix = format!("/p2p/{}", self.peer);
        if self
            .address
            .iter()
            .any(|a| !a.to_string().ends_with(&suffix))
        {
            bail!("every candidate address must end with the expected --peer");
        }
        let mut errors = Vec::new();
        for address in &self.address {
            match node.dial(address.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) => errors.push(format!("{address}: {error}")),
            }
        }
        bail!("all connection candidates failed: {}", errors.join("; "))
    }
}

#[derive(Clone, Debug, Args)]
pub struct AccessArgs {
    /// Explicitly allow any authenticated union node. Does not disable MC login.
    #[arg(long = "public", conflicts_with_all = ["allow_peer", "issuer"])]
    pub public: bool,
    #[arg(long, conflicts_with = "issuer")]
    pub allow_peer: Vec<PeerId>,
    /// Trusted grant issuers; hosting a service never makes its node a club issuer.
    #[arg(long)]
    pub issuer: Vec<PeerId>,
    #[arg(long, requires = "issuer")]
    pub revoked: Vec<String>,
}

impl AccessArgs {
    pub fn policy(&self) -> AccessPolicy {
        if self.public {
            AccessPolicy::Public
        } else if !self.allow_peer.is_empty() {
            AccessPolicy::Peers(self.allow_peer.iter().copied().collect())
        } else if !self.issuer.is_empty() {
            AccessPolicy::Grants {
                issuers: self.issuer.iter().copied().collect(),
                revoked: self.revoked.iter().cloned().collect::<HashSet<_>>(),
            }
        } else {
            AccessPolicy::Deny
        }
    }
}

pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
}

pub fn load_grant(path: Option<&Path>) -> Result<Option<SignedGrant>> {
    path.map(|path| {
        let size = std::fs::metadata(path)?.len();
        anyhow::ensure!(
            size <= union_core::protocol::MAX_FRAME as u64,
            "grant file too large"
        );
        Ok(SignedGrant::decode(&std::fs::read(path)?)?)
    })
    .transpose()
}

/// Bridge authorized incoming sessions to one configured backend; clients cannot
/// choose arbitrary TCP destinations. Minecraft authentication remains end-to-end.
pub async fn serve_backend(mut node: Node, backend: SocketAddr) -> Result<()> {
    let mut incoming = node.take_incoming()?;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => { signal?; break; }
            session = incoming.recv() => {
                let Some(mut session) = session else { break; };
                tasks.spawn(async move {
                    let result = async {
                        let mut backend = timeout(Duration::from_secs(10), TcpStream::connect(backend)).await??;
                        backend.set_nodelay(true)?;
                        let mut stream = (&mut session.stream).compat();
                        tokio::io::copy_bidirectional(&mut stream, &mut backend).await?;
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    if let Err(error) = result { tracing::warn!(peer = %session.peer, %error, "backend session ended"); }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { tracing::error!(%error, "backend task failed"); }
            }
        }
    }
    tasks.shutdown().await;
    node.shutdown().await?;
    Ok(())
}

/// Owned local proxy. Dropping it closes the listener, sessions and network node.
/// Suitable for desktop app state; never installs process-wide signal handlers.
pub struct LocalProxy {
    student: Arc<tokio::sync::RwLock<Option<union_core::federation::StudentPresentation>>>,
    address: SocketAddr,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl LocalProxy {
    pub fn proof_store(
        &self,
    ) -> Arc<tokio::sync::RwLock<Option<union_core::federation::StudentPresentation>>> {
        self.student.clone()
    }
    pub fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.task.abort_handle()
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }
    pub async fn start(
        node: Node,
        target: TargetArgs,
        service: ServiceId,
        grant: Option<SignedGrant>,
        student: Option<union_core::federation::StudentPresentation>,
        bind: SocketAddr,
    ) -> Result<Self> {
        anyhow::ensure!(
            bind.ip().is_loopback(),
            "player proxy must bind to loopback"
        );
        anyhow::ensure!(
            grant.is_none() || student.is_none(),
            "choose one admission proof"
        );
        target.connect(&node).await?;
        // Check service existence without creating an empty game session.
        anyhow::ensure!(
            node.list_services(target.peer)
                .await?
                .iter()
                .any(|s| s.id == service.to_string()),
            "game service not found"
        );
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let student = Arc::new(tokio::sync::RwLock::new(student));
        let proofs = student.clone();
        let task = tokio::spawn(async move {
            let node = Arc::new(node);
            let limit = Arc::new(tokio::sync::Semaphore::new(64));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut local, _) = accepted?;
                        let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                        let (node, target, grant, student) = (node.clone(), target.clone(), grant.clone(), proofs.read().await.clone());
                        tasks.spawn(async move {
                            let _permit = permit;
                            let result = async {
                                local.set_nodelay(true)?;
                                target.connect(&node).await?;
                                let stream = match student {
                                    Some(proof) => node.open_student_service(target.peer, service, &proof).await?,
                                    None => node.open_service(target.peer, service, grant).await?,
                                };
                                tokio::io::copy_bidirectional(&mut local, &mut stream.compat()).await?;
                                Ok::<_, anyhow::Error>(())
                            }.await;
                            if let Err(error) = result { tracing::warn!(%error, "player session ended"); }
                        });
                    }
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                        if let Err(error) = result { tracing::error!(%error, "proxy task failed"); }
                    }
                }
            }
        });
        Ok(Self {
            address,
            task,
            student,
        })
    }
}
impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// CLI wrapper; application integrations own LocalProxy directly.
pub async fn run_proxy(
    node: Node,
    target: TargetArgs,
    service: ServiceId,
    grant: Option<SignedGrant>,
    bind: SocketAddr,
) -> Result<()> {
    let proxy = LocalProxy::start(node, target, service, grant, None, bind).await?;
    tracing::info!(address = %proxy.address(), "local game proxy ready");
    tokio::signal::ctrl_c().await?;
    drop(proxy);
    Ok(())
}
