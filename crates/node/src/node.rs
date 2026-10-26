use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle};
use libp2p::{
    Multiaddr, PeerId, Stream, StreamProtocol, Swarm, SwarmBuilder, autonat, dcutr, identify, kad,
    mdns, noise, ping, relay, tcp, yamux,
};
use tokio::{
    sync::{OwnedSemaphorePermit, RwLock, Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::{AccessPolicy, Error, Identity, Result, Service, ServiceId, protocol::*};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_CAPACITY: usize = 64;

/// Bounds apply equally to standalone and embedded relay hosts.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub max_reservations: usize,
    pub max_circuits: usize,
    pub max_circuit_bytes: u64,
    pub max_circuit_duration: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_reservations: 128,
            max_circuits: 128,
            max_circuit_bytes: 256 * 1024 * 1024,
            max_circuit_duration: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub listen: Vec<Multiaddr>,
    /// Addresses known by the operator to be reachable. No reachability is inferred.
    pub external_addresses: Vec<Multiaddr>,
    pub relay: Option<RelayConfig>,
    pub hole_punching: bool,
    pub max_sessions: usize,
    /// Stable nodes may serve DHT queries; consumer nodes remain clients.
    pub discovery_server: bool,
    pub lan_discovery: bool,
    pub bootstrap: Vec<Multiaddr>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: vec![
                Multiaddr::empty()
                    .with(libp2p::multiaddr::Protocol::Ip4(
                        std::net::Ipv4Addr::UNSPECIFIED,
                    ))
                    .with(libp2p::multiaddr::Protocol::Udp(0))
                    .with(libp2p::multiaddr::Protocol::QuicV1),
            ],
            external_addresses: Vec::new(),
            relay: None,
            hole_punching: true,
            max_sessions: 128,
            discovery_server: false,
            lan_discovery: false,
            bootstrap: Vec::new(),
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    // Reject excess connections before protocol handlers record them.
    limits: libp2p::connection_limits::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    autonat: autonat::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    streams: libp2p_stream::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
}

type Catalog = Arc<RwLock<HashMap<ServiceId, Service>>>;

enum Command {
    Dial(Multiaddr, oneshot::Sender<Result<()>>),
    Listen(Multiaddr, oneshot::Sender<Result<()>>),
    External(Multiaddr),
    Provide(ServiceId, oneshot::Sender<Result<()>>),
    Withdraw(ServiceId),
    Discover(kad::RecordKey, oneshot::Sender<Result<Vec<PeerId>>>),
    Peers(oneshot::Sender<Vec<PeerId>>),
    PeerAddresses(PeerId, oneshot::Sender<Vec<Multiaddr>>),
    DialPeer(PeerId, oneshot::Sender<Result<()>>),
    Shutdown(oneshot::Sender<Result<()>>),
}

/// An authorized byte stream. The permit keeps admission bounded until dropped.
pub struct IncomingSession {
    pub peer: PeerId,
    pub service: ServiceId,
    pub stream: SessionStream,
    pub claims: Option<Vec<u8>>,
    pub(crate) _permit: OwnedSemaphorePermit,
}

/// Running node. Dropping it stops the swarm and cancels its protocol tasks.
pub struct Node {
    peer: PeerId,
    commands: mpsc::Sender<Command>,
    control: libp2p_stream::Control,
    catalog: Catalog,
    policy_changes: watch::Sender<()>,
    addresses: watch::Receiver<Vec<Multiaddr>>,
    incoming: Option<mpsc::Receiver<IncomingSession>>,
    task: JoinHandle<()>,
}

impl Node {
    /// Application protocols must authenticate/authorize every operation themselves.
    pub fn accept_protocol(
        &self,
        protocol: &'static str,
    ) -> Result<libp2p_stream::IncomingStreams> {
        self.control
            .clone()
            .accept(StreamProtocol::new(protocol))
            .map_err(network)
    }

    pub async fn open_protocol(&self, peer: PeerId, protocol: &'static str) -> Result<Stream> {
        timeout(
            REQUEST_TIMEOUT,
            self.control
                .clone()
                .open_stream(peer, StreamProtocol::new(protocol)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(network)
    }
    pub async fn start(identity: Identity, config: NodeConfig) -> Result<Self> {
        if config.listen.is_empty() || config.max_sessions == 0 || config.max_sessions > 4096 {
            return Err(Error::Protocol(
                "listen address required; max_sessions must be 1..=4096".into(),
            ));
        }
        if let Some(relay) = &config.relay
            && (relay.max_reservations == 0
                || relay.max_circuits == 0
                || relay.max_circuit_bytes == 0
                || relay.max_circuit_duration.is_zero())
        {
            return Err(Error::Protocol("relay limits must be positive".into()));
        }
        let peer = identity.peer_id();
        let relay_config = config.relay.clone();
        if config.bootstrap.len() > 16 {
            return Err(Error::Capacity);
        }
        for address in &config.bootstrap {
            if !matches!(
                address.iter().last(),
                Some(libp2p::multiaddr::Protocol::P2p(_))
            ) {
                return Err(Error::Protocol(
                    "bootstrap address must end in PeerId".into(),
                ));
            }
        }
        let mut kad_config = kad::Config::new(StreamProtocol::new("/jlucraft/union/kad/1"));
        kad_config.set_query_timeout(Duration::from_secs(10));
        kad_config.set_provider_record_ttl(Some(Duration::from_secs(600)));
        kad_config.set_provider_publication_interval(Some(Duration::from_secs(120)));
        let mut kad =
            kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), kad_config);
        kad.set_mode(Some(if config.discovery_server {
            kad::Mode::Server
        } else {
            kad::Mode::Client
        }));
        let mdns = if config.lan_discovery {
            Some(mdns::tokio::Behaviour::new(mdns::Config::default(), peer).map_err(network)?)
        } else {
            None
        };
        let mut swarm = SwarmBuilder::with_existing_identity(identity.into_keypair())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(network)?
            .with_quic()
            .with_dns()
            .map_err(network)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(network)?
            .with_behaviour(|key, relay_client| Behaviour {
                kad,
                mdns: mdns.into(),
                autonat: autonat::Behaviour::new(peer, autonat::Config::default()),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/jlucraft/union/1".into(),
                    key.public(),
                )),
                ping: ping::Behaviour::default(),
                streams: libp2p_stream::Behaviour::new(),
                relay_client,
                relay_server: relay_config
                    .map(|limits| {
                        relay::Behaviour::new(
                            peer,
                            relay::Config {
                                max_reservations: limits.max_reservations,
                                max_circuits: limits.max_circuits,
                                max_circuit_bytes: limits.max_circuit_bytes,
                                max_circuit_duration: limits.max_circuit_duration,
                                ..Default::default()
                            },
                        )
                    })
                    .into(),
                dcutr: config
                    .hole_punching
                    .then(|| dcutr::Behaviour::new(peer))
                    .into(),
                limits: libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(64))
                        .with_max_pending_outgoing(Some(64))
                        .with_max_established(Some(512))
                        .with_max_established_per_peer(Some(4)),
                ),
            })
            .map_err(network)?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        for address in config.listen {
            swarm.listen_on(address).map_err(network)?;
        }
        for address in config.external_addresses {
            swarm.add_external_address(address);
        }
        let mut control = swarm.behaviour().streams.new_control();
        let directories = control
            .accept(StreamProtocol::new(DIRECTORY_PROTOCOL))
            .map_err(network)?;
        let sessions = control
            .accept(StreamProtocol::new(SESSION_PROTOCOL))
            .map_err(network)?;
        let (commands, rx) = mpsc::channel(COMMAND_CAPACITY);
        let (addresses_tx, addresses) = watch::channel(Vec::new());
        let (incoming_tx, incoming) = mpsc::channel(config.max_sessions);
        let catalog = Arc::new(RwLock::new(HashMap::new()));
        let (policy_changes, changes) = watch::channel(());
        let task = tokio::spawn(run(
            swarm,
            rx,
            addresses_tx,
            directories,
            sessions,
            catalog.clone(),
            incoming_tx,
            config.max_sessions,
            config.bootstrap,
            changes,
        ));
        let mut node = Self {
            peer,
            commands,
            control,
            catalog,
            policy_changes,
            addresses,
            incoming: Some(incoming),
            task,
        };
        timeout(REQUEST_TIMEOUT, async {
            while node.addresses.borrow().is_empty() {
                node.addresses.changed().await.map_err(|_| Error::Stopped)?;
            }
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(node)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// Addresses include the local PeerId, and are not assertions of public reachability.
    pub fn addresses(&self) -> Vec<Multiaddr> {
        self.addresses.borrow().clone()
    }

    pub fn watch_addresses(&self) -> watch::Receiver<Vec<Multiaddr>> {
        self.addresses.clone()
    }

    pub fn take_incoming(&mut self) -> Result<mpsc::Receiver<IncomingSession>> {
        self.incoming
            .take()
            .ok_or_else(|| Error::Protocol("incoming receiver already taken".into()))
    }

    pub async fn publish(&self, service: Service) -> Result<()> {
        service.validate()?;
        let mut catalog = self.catalog.write().await;
        if !catalog.contains_key(&service.id) && catalog.len() >= MAX_SERVICES {
            return Err(Error::Capacity);
        }
        let id = service.id;
        catalog.insert(id, service);
        self.policy_changes.send_replace(());
        drop(catalog);
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Provide(id, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)?
    }

    /// Removes discovery and closes authorized sessions on their pending or next I/O.
    pub async fn withdraw(&self, service: ServiceId) {
        self.catalog.write().await.remove(&service);
        self.policy_changes.send_replace(());
        let _ = self.commands.send(Command::Withdraw(service)).await;
    }

    /// DHT provider claims are hints. Confirm the authenticated host directory and
    /// service authorization before using a returned peer; discovery grants no authority.
    pub async fn discover(&self, service: ServiceId) -> Result<Vec<PeerId>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Discover(provider_key(service), tx))
            .await
            .map_err(|_| Error::Stopped)?;
        timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Stopped)?
    }

    /// LAN peers announced over mDNS. Hints only; authorization is checked on use.
    pub async fn peers(&self) -> Result<Vec<PeerId>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Peers(tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)
    }

    /// Every address the peer announced on the local network, reachable-looking
    /// candidates first. Hints only; authorization is checked on use.
    pub async fn peer_addresses(&self, peer: PeerId) -> Result<Vec<Multiaddr>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::PeerAddresses(peer, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)
    }

    /// Dial a peer announced by discovery, reusing the addresses mDNS or identify supplied.
    pub async fn dial_peer(&self, peer: PeerId) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::DialPeer(peer, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Stopped)?
    }

    /// Discover protocol providers as untrusted hints, then query each host directory.
    pub async fn discover_protocol(&self, protocol: &str) -> Result<Vec<PeerId>> {
        if protocol::validate_identifier(protocol).is_err() || !protocol.is_ascii() {
            return Err(Error::Protocol("invalid discovery protocol".into()));
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Discover(protocol_key(protocol), tx))
            .await
            .map_err(|_| Error::Stopped)?;
        timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Stopped)?
    }

    pub async fn dial(&self, address: Multiaddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Dial(address, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Stopped)?
    }

    /// To reserve a relay: listen on /.../p2p/RELAY/p2p-circuit, then wait for
    /// the circuit address in watch_addresses before publishing it to clients.
    pub async fn listen_on(&self, address: Multiaddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Listen(address, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)?
    }

    pub async fn add_external_address(&self, address: Multiaddr) -> Result<()> {
        self.commands
            .send(Command::External(address))
            .await
            .map_err(|_| Error::Stopped)
    }

    /// Authenticated per-host directory. Results are claims of this connected host,
    /// not globally certified ownership or a decentralized consensus snapshot.
    pub async fn list_services(&self, peer: PeerId) -> Result<Vec<ServiceRecord>> {
        Ok(self.directory(peer).await?.services)
    }

    pub async fn directory(&self, peer: PeerId) -> Result<DirectoryResponse> {
        timeout(REQUEST_TIMEOUT, async {
            let mut stream = self
                .control
                .clone()
                .open_stream(peer, StreamProtocol::new(DIRECTORY_PROTOCOL))
                .await
                .map_err(network)?;
            write_frame(&mut stream, &DirectoryRequest {}).await?;
            let response: DirectoryResponse = read_frame(&mut stream).await?;
            if response.services.len() > MAX_SERVICES || response.addresses.len() > MAX_DIRECTORY_ADDRESSES {
                return Err(Error::Capacity);
            }
            for address in &response.addresses {
                let parsed: Multiaddr = address.parse().map_err(network)?;
                if address.len() > MAX_DIRECTORY_ADDRESS_BYTES || !matches!(parsed.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(id)) if id == peer) {
                    return Err(Error::Protocol("invalid directory address".into()));
                }
            }
            let mut ids = std::collections::HashSet::new();
            for record in &response.services {
                let id = record.id.parse()?;
                Service {
                    metadata: record.metadata.clone(),
                    id,
                    name: record.name.clone(),
                    protocol: record.protocol.clone(),
                    access: AccessPolicy::Deny,
                }
                .validate()?;
                if !ids.insert(id) {
                    return Err(Error::Protocol("duplicate service id".into()));
                }
            }
            Ok(response)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn open_service(&self, peer: PeerId, service: ServiceId) -> Result<Stream> {
        timeout(REQUEST_TIMEOUT, async {
            let mut stream = self
                .control
                .clone()
                .open_stream(peer, StreamProtocol::new(SESSION_PROTOCOL))
                .await
                .map_err(network)?;
            write_frame(
                &mut stream,
                &OpenRequest {
                    service_id: service.to_string(),
                },
            )
            .await?;
            let response: OpenResponse = read_frame(&mut stream).await?;
            match Status::try_from(response.status) {
                Ok(Status::Accepted) => Ok(stream),
                Ok(Status::Denied) => Err(Error::Denied),
                Ok(Status::AuthorityUnavailable) => Err(Error::AuthorityUnavailable),
                Ok(Status::NotFound) => Err(Error::NotFound),
                Ok(Status::Busy) => Err(Error::Capacity),
                _ => Err(Error::Protocol("unknown session status".into())),
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Shutdown(tx))
            .await
            .map_err(|_| Error::Stopped)?;
        let result = rx.await.map_err(|_| Error::Stopped)?;
        (&mut self.task).await.map_err(network)?;
        result
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn network(error: impl std::fmt::Display) -> Error {
    Error::Network(error.to_string())
}

fn reachable_hint(address: &Multiaddr) -> bool {
    let text = address.to_string();
    !text.starts_with("/ip4/127.")
        && !text.starts_with("/ip6/::1")
        && !text.starts_with("/ip4/169.254.")
        && !text.starts_with("/ip6/fe80")
}

fn qualified_address(address: Multiaddr, local: PeerId) -> Multiaddr {
    // Relay transports already include the destination PeerId in listen events.
    if matches!(address.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(peer)) if peer == local)
    {
        address
    } else {
        address.with(libp2p::multiaddr::Protocol::P2p(local))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    mut swarm: Swarm<Behaviour>,
    mut commands: mpsc::Receiver<Command>,
    addresses: watch::Sender<Vec<Multiaddr>>,
    mut directories: libp2p_stream::IncomingStreams,
    mut sessions: libp2p_stream::IncomingStreams,
    catalog: Catalog,
    incoming: mpsc::Sender<IncomingSession>,
    max_sessions: usize,
    bootstrap: Vec<Multiaddr>,
    policy_changes: watch::Receiver<()>,
) {
    let local = *swarm.local_peer_id();
    let permits = Arc::new(Semaphore::new(max_sessions));
    let handlers = Arc::new(Semaphore::new(max_sessions));
    let mut tasks = JoinSet::new();
    let mut pending: HashMap<PeerId, Vec<oneshot::Sender<Result<()>>>> = HashMap::new();
    type DiscoveryQuery = (oneshot::Sender<Result<Vec<PeerId>>>, HashSet<PeerId>);
    let mut queries: HashMap<kad::QueryId, DiscoveryQuery> = HashMap::new();
    let mut advertised: HashMap<ServiceId, String> = HashMap::new();
    let mut lan_peers: std::collections::BTreeMap<PeerId, Vec<Multiaddr>> =
        std::collections::BTreeMap::new();
    let mut maintenance = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _=maintenance.tick()=>{
                queries.retain(|_,(sender,_)|!sender.is_closed());
                for address in &bootstrap {
                    if let Some(libp2p::multiaddr::Protocol::P2p(peer))=address.iter().last() {
                        swarm.behaviour_mut().kad.add_address(&peer,address.clone());
                        if !swarm.is_connected(&peer){let _=swarm.dial(address.clone());}
                    }
                }
                if !bootstrap.is_empty(){let _=swarm.behaviour_mut().kad.bootstrap();}
            },
            command = commands.recv() => match command {
                Some(Command::Dial(address, response)) => {
                    pending.retain(|_, senders| { senders.retain(|s| !s.is_closed()); !senders.is_empty() });
                    let Some(libp2p::multiaddr::Protocol::P2p(peer)) = address.iter().last() else {
                        let _ = response.send(Err(Error::Protocol("dial address must end with /p2p/PEER".into())));
                        continue;
                    };
                    swarm.behaviour_mut().kad.add_address(&peer,address.clone());
                    if swarm.is_connected(&peer) { let _ = response.send(Ok(())); continue; }
                    if pending.values().map(Vec::len).sum::<usize>() >= COMMAND_CAPACITY {
                        let _ = response.send(Err(Error::Capacity)); continue;
                    }
                    if let Some(waiting) = pending.get_mut(&peer) { waiting.push(response); continue; }
                    match swarm.dial(address) {
                        Ok(()) => { pending.insert(peer, vec![response]); },
                        Err(error) => { let _ = response.send(Err(network(error))); },
                    }
                }
                Some(Command::Provide(service,response))=>{
                    let protocol = catalog.read().await.get(&service).map(|s| s.protocol.clone());
                    let result = if let Some(protocol) = protocol {
                        if let Some(old) = advertised.insert(service, protocol.clone())
                            && old != protocol && !advertised.values().any(|p| p == &old) {
                            swarm.behaviour_mut().kad.stop_providing(&protocol_key(&old));
                        }
                        swarm.behaviour_mut().kad.start_providing(provider_key(service))
                            .and_then(|_| swarm.behaviour_mut().kad.start_providing(protocol_key(&protocol)))
                            .map(|_| ()).map_err(network)
                    } else { Err(Error::NotFound) };
                    let _=response.send(result);
                }
                Some(Command::Withdraw(service))=>{
                    swarm.behaviour_mut().kad.stop_providing(&provider_key(service));
                    if let Some(protocol) = advertised.remove(&service)
                        && !advertised.values().any(|p| p == &protocol) {
                        swarm.behaviour_mut().kad.stop_providing(&protocol_key(&protocol));
                    }
                }
                Some(Command::Discover(service,response))=>{
                    queries.retain(|_,(sender,_)|!sender.is_closed());
                    if queries.len()>=COMMAND_CAPACITY{let _=response.send(Err(Error::Capacity));continue;}
                    let query=swarm.behaviour_mut().kad.get_providers(service);
                    queries.insert(query,(response,HashSet::new()));
                }
                Some(Command::Peers(response)) => { let _ = response.send(lan_peers.keys().copied().collect()); }
                Some(Command::PeerAddresses(peer, response)) => { let mut all = lan_peers.get(&peer).cloned().unwrap_or_default(); all.sort_by_key(|a| !reachable_hint(a)); let _ = response.send(all); }
                Some(Command::DialPeer(peer, response)) => {
                    if swarm.is_connected(&peer) { let _ = response.send(Ok(())); continue; }
                    match swarm.dial(libp2p::swarm::dial_opts::DialOpts::peer_id(peer).build()) {
                        Ok(()) => { pending.entry(peer).or_default().push(response); }
                        Err(error) => { let _ = response.send(Err(network(error))); }
                    }
                }
                Some(Command::Listen(address, response)) => { let _ = response.send(swarm.listen_on(address).map(|_| ()).map_err(network)); }
                Some(Command::External(address)) => { swarm.add_external_address(address); }
                Some(Command::Shutdown(response)) => {
                    tasks.abort_all();
                    let result = timeout(REQUEST_TIMEOUT, async {
                        while tasks.join_next().await.is_some() {}
                        while swarm.network_info().connection_counters().num_established() > 0 {
                            let peers: Vec<_> = swarm.connected_peers().copied().collect();
                            for peer in peers { let _ = swarm.disconnect_peer_id(peer); }
                            if swarm.next().await.is_none() { return Err(Error::Stopped); }
                        }
                        Ok(())
                    }).await.unwrap_or(Err(Error::Timeout));
                    drop(swarm);
                    let _ = response.send(result);
                    return;
                }
                None => return,
            },
            Some((peer, mut stream)) = directories.next() => {
                let Ok(permit) = handlers.clone().try_acquire_owned() else { continue; };
                let catalog = catalog.clone();
                let mut host_addresses: Vec<String> = addresses.borrow().iter().map(ToString::to_string)
                    .filter(|a| a.len() <= MAX_DIRECTORY_ADDRESS_BYTES).collect();
                host_addresses.sort_by_key(|a| !a.contains("/p2p-circuit/"));
                host_addresses.truncate(MAX_DIRECTORY_ADDRESSES);
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(REQUEST_TIMEOUT, async {
                        let _: DirectoryRequest = read_frame(&mut stream).await?;
                        let mut services: Vec<_> = catalog.read().await.values().map(Service::record).collect();
                        services.sort_by(|a, b| a.id.cmp(&b.id));
                        write_frame(&mut stream, &DirectoryResponse { services, addresses: host_addresses }).await
                    }).await;
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!(%peer, "directory exchange failed"); }
                });
            }
            Some((peer, stream)) = sessions.next() => {
                let Ok(permit) = handlers.clone().try_acquire_owned() else { continue; };
                let (catalog, incoming, permits) = (catalog.clone(), incoming.clone(), permits.clone());
                let changes = policy_changes.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(REQUEST_TIMEOUT, accept_session(peer, local, stream, catalog, incoming, permits, changes)).await;
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!(%peer, "session negotiation failed"); }
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { tracing::error!(%error, "protocol task failed"); }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let address = qualified_address(address, local);
                    addresses.send_modify(|all| { if !all.contains(&address) { all.push(address.clone()); } });
                    tracing::info!(%address, "listening");
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    let address = qualified_address(address, local);
                    addresses.send_modify(|all| all.retain(|a| a != &address));
                }
                SwarmEvent::ListenerClosed { addresses: expired, reason, .. } => {
                    let expired: Vec<_> = expired.into_iter().map(|a| qualified_address(a, local)).collect();
                    addresses.send_modify(|all| all.retain(|a| !expired.contains(a)));
                    if let Err(error) = reason { tracing::warn!(%error, "listener closed"); }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if let Some(waiting) = pending.remove(&peer_id) {
                        for response in waiting { let _ = response.send(Ok(())); }
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), error, .. } => {
                    if let Some(waiting) = pending.remove(&peer) {
                        for response in waiting { let _ = response.send(Err(network(&error))); }
                    }
                    tracing::debug!(%peer, %error, "connection failed");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    // Addresses are authenticated claims, not proof of reachability.
                    for address in info.listen_addrs.into_iter().take(16) {
                        swarm.add_peer_address(peer_id, address.clone());
                        if info.protocols.iter().any(|p|p.as_ref()=="/jlucraft/union/kad/1") {swarm.behaviour_mut().kad.add_address(&peer_id,address);}
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers)))=>{
                    for (peer,address) in peers.into_iter().take(64){swarm.behaviour_mut().kad.add_address(&peer,address.clone());swarm.add_peer_address(peer,address.clone());lan_peers.entry(peer).or_default().push(address);}
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers)))=>{
                    for (peer,address) in peers{swarm.behaviour_mut().kad.remove_address(&peer,&address);if let Some(all)=lan_peers.get_mut(&peer){all.retain(|a|a!=&address);if all.is_empty(){lan_peers.remove(&peer);}}}
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed{id,result:kad::QueryResult::GetProviders(result),step,..}))=>{
                    if let Some((_,peers))=queries.get_mut(&id) && let Ok(kad::GetProvidersOk::FoundProviders{providers,..})=&result {
                        peers.extend(providers.iter().copied().take(128usize.saturating_sub(peers.len())));
                    }
                    if step.last && let Some((sender,peers))=queries.remove(&id){
                        let result=if result.is_err()&&peers.is_empty(){Err(Error::Timeout)}else{Ok(peers.into_iter().collect())};
                        let _=sender.send(result);
                    }
                }
                SwarmEvent::ListenerError { error, .. } => tracing::warn!(%error, "listener failed"),
                SwarmEvent::Behaviour(event) => tracing::trace!(?event, "network event"),
                _ => {}
            }
        }
    }
}

async fn accept_session(
    peer: PeerId,
    local: PeerId,
    mut stream: Stream,
    catalog: Catalog,
    incoming: mpsc::Sender<IncomingSession>,
    permits: Arc<Semaphore>,
    changes: watch::Receiver<()>,
) -> Result<()> {
    let request: OpenRequest = read_frame(&mut stream).await?;
    let id: ServiceId = request.service_id.parse()?;
    let services = catalog.read().await;
    let Some(service) = services.get(&id) else {
        return write_frame(
            &mut stream,
            &OpenResponse {
                status: Status::NotFound as i32,
            },
        )
        .await;
    };
    let authorization: Result<Option<Vec<u8>>> = match &service.access {
        AccessPolicy::Trust { view, requirement } => view
            .authorize(
                &peer.to_string(),
                &local.to_string(),
                &id.to_string(),
                requirement,
            )
            .and_then(|member| {
                let state = view.state()?;
                let claims = crate::protocol::TrustAdmission {
                    clubs: state.clubs(&member),
                    game_profile: state.profile(&member).map(str::to_owned),
                    member,
                };
                Ok(Some(serde_json::to_vec(&claims).map_err(network)?))
            }),
        access => access.authorize(peer, local, id).map(|()| None),
    };
    let claims = match authorization {
        Ok(claims) => claims,
        Err(error) => {
            return write_frame(
                &mut stream,
                &OpenResponse {
                    status: if matches!(error, Error::AuthorityUnavailable) {
                        Status::AuthorityUnavailable
                    } else {
                        Status::Denied
                    } as i32,
                },
            )
            .await;
        }
    };
    let guard = if let AccessPolicy::Trust { .. } = &service.access {
        Some(trust_guard(
            peer,
            local,
            id,
            catalog.clone(),
            changes,
            claims
                .as_ref()
                .and_then(|proof| {
                    serde_json::from_slice::<crate::protocol::TrustAdmission>(proof).ok()
                })
                .and_then(|claims| claims.game_profile),
        ))
    } else {
        None
    };
    drop(services);
    let Ok(permit) = permits.try_acquire_owned() else {
        return write_frame(
            &mut stream,
            &OpenResponse {
                status: Status::Busy as i32,
            },
        )
        .await;
    };
    let Ok(slot) = incoming.try_reserve() else {
        return write_frame(
            &mut stream,
            &OpenResponse {
                status: Status::Busy as i32,
            },
        )
        .await;
    };
    write_frame(
        &mut stream,
        &OpenResponse {
            status: Status::Accepted as i32,
        },
    )
    .await?;
    slot.send(IncomingSession {
        peer,
        service: id,
        stream: SessionStream {
            inner: Some(stream),
            guard,
        },
        claims,
        _permit: permit,
    });
    Ok(())
}

fn protocol_key(protocol: &str) -> kad::RecordKey {
    kad::RecordKey::new(&format!("jlucraft/protocol/{protocol}"))
}

fn provider_key(service: ServiceId) -> kad::RecordKey {
    kad::RecordKey::new(&format!("jlucraft/service/{service}"))
}

/// A session stream whose authorization remains subject to live governance and policy.
/// The raw stream is private so applications cannot bypass the guard.
pub struct SessionStream {
    inner: Option<Stream>,
    guard: Option<AuthorizationGuard>,
}

fn trust_guard(
    peer: PeerId,
    local: PeerId,
    id: ServiceId,
    catalog: Catalog,
    mut changes: watch::Receiver<()>,
    expected_profile: Option<String>,
) -> AuthorizationGuard {
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let permit = allowed.clone();
    let future = Box::pin(async move {
        loop {
            permit.store(false, std::sync::atomic::Ordering::Relaxed);
            let mut view = {
                let services = catalog.read().await;
                let Some(service) = services.get(&id) else {
                    return;
                };
                let AccessPolicy::Trust { view, requirement } = &service.access else {
                    return;
                };
                let mut view = view.clone();
                view.mark_seen();
                let Ok(state) = view.state() else {
                    return;
                };
                let Some(member) = state.member_for_device(&peer.to_string()) else {
                    return;
                };
                if state.profile(member) != expected_profile.as_deref() {
                    return;
                }
                if view
                    .authorize(
                        &peer.to_string(),
                        &local.to_string(),
                        &id.to_string(),
                        requirement,
                    )
                    .is_err()
                {
                    return;
                }
                view
            };
            permit.store(true, std::sync::atomic::Ordering::Relaxed);
            tokio::select! {
                _ = tokio::time::sleep(view.remaining()) => {},
                changed = view.changed() => { if changed.is_err() { return; } },
                changed = changes.changed() => { if changed.is_err() { return; } },
            }
        }
    });
    AuthorizationGuard { future, allowed }
}

struct AuthorizationGuard {
    future: futures::future::BoxFuture<'static, ()>,
    allowed: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionStream {
    fn checked(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&mut Stream>> {
        if self
            .guard
            .as_mut()
            .is_some_and(|guard| guard.future.as_mut().poll(cx).is_ready())
        {
            self.inner.take();
            self.guard.take();
        }
        if self
            .guard
            .as_ref()
            .is_some_and(|guard| !guard.allowed.load(std::sync::atomic::Ordering::Relaxed))
        {
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(self.inner.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "session authorization revoked",
            )
        }))
    }
}
impl futures::AsyncRead for SessionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(std::task::ready!(self.checked(cx))?).poll_read(cx, buf)
    }
}
impl futures::AsyncWrite for SessionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(std::task::ready!(self.checked(cx))?).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(std::task::ready!(self.checked(cx))?).poll_flush(cx)
    }
    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(std::task::ready!(self.checked(cx))?).poll_close(cx)
    }
}
