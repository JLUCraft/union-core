use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
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

use crate::{AccessPolicy, Error, Identity, Result, Service, ServiceId, SignedGrant, protocol::*};

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
                        std::net::Ipv4Addr::LOCALHOST,
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
    kad: kad::Behaviour<kad::store::MemoryStore>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    autonat: autonat::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    streams: libp2p_stream::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    limits: libp2p::connection_limits::Behaviour,
}

type Catalog = Arc<RwLock<HashMap<ServiceId, Service>>>;

enum Command {
    Dial(Multiaddr, oneshot::Sender<Result<()>>),
    Listen(Multiaddr, oneshot::Sender<Result<()>>),
    External(Multiaddr),
    Provide(ServiceId, oneshot::Sender<Result<()>>),
    Withdraw(ServiceId),
    Discover(ServiceId, oneshot::Sender<Result<Vec<PeerId>>>),
    Shutdown(oneshot::Sender<()>),
}

/// An authorized byte stream. The permit keeps admission bounded until dropped.
pub struct IncomingSession {
    pub peer: PeerId,
    pub service: ServiceId,
    pub stream: Stream,
    pub student: Option<crate::federation::StudentClaims>,
    pub(crate) _permit: OwnedSemaphorePermit,
}

/// Running node. Dropping it stops the swarm and cancels its protocol tasks.
pub struct Node {
    peer: PeerId,
    commands: mpsc::Sender<Command>,
    control: libp2p_stream::Control,
    catalog: Catalog,
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
        let mut swarm = SwarmBuilder::with_existing_identity(identity.0)
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
        ));
        let mut node = Self {
            peer,
            commands,
            control,
            catalog,
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
        drop(catalog);
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Provide(id, tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)?
    }

    /// Removes discovery and blocks new sessions; existing streams are not revoked.
    pub async fn withdraw(&self, service: ServiceId) {
        self.catalog.write().await.remove(&service);
        let _ = self.commands.send(Command::Withdraw(service)).await;
    }

    /// DHT provider claims are hints. Confirm the authenticated host directory and
    /// service grant before using a returned peer; discovery grants no authority.
    pub async fn discover(&self, service: ServiceId) -> Result<Vec<PeerId>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Discover(service, tx))
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
        timeout(REQUEST_TIMEOUT, async {
            let mut stream = self
                .control
                .clone()
                .open_stream(peer, StreamProtocol::new(DIRECTORY_PROTOCOL))
                .await
                .map_err(network)?;
            write_frame(&mut stream, &DirectoryRequest {}).await?;
            let response: DirectoryResponse = read_frame(&mut stream).await?;
            if response.services.len() > MAX_SERVICES {
                return Err(Error::Capacity);
            }
            let mut ids = std::collections::HashSet::new();
            for record in &response.services {
                let id = record.id.parse()?;
                Service {
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
            Ok(response.services)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn open_service(
        &self,
        peer: PeerId,
        service: ServiceId,
        grant: Option<SignedGrant>,
    ) -> Result<Stream> {
        self.open_admitted_service(peer, service, grant, Vec::new())
            .await
    }

    pub async fn open_student_service(
        &self,
        peer: PeerId,
        service: ServiceId,
        presentation: &crate::federation::StudentPresentation,
    ) -> Result<Stream> {
        let bytes = serde_json::to_vec(presentation).map_err(|e| Error::Protocol(e.to_string()))?;
        self.open_admitted_service(peer, service, None, bytes).await
    }

    async fn open_admitted_service(
        &self,
        peer: PeerId,
        service: ServiceId,
        grant: Option<SignedGrant>,
        student: Vec<u8>,
    ) -> Result<Stream> {
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
                    grant: grant.map(|g| g.0),
                    student,
                },
            )
            .await?;
            let response: OpenResponse = read_frame(&mut stream).await?;
            match Status::try_from(response.status) {
                Ok(Status::Accepted) => Ok(stream),
                Ok(Status::Denied) => Err(Error::Denied),
                Ok(Status::NotFound) => Err(Error::NotFound),
                Ok(Status::Busy) => Err(Error::Capacity),
                _ => Err(Error::Protocol("unknown session status".into())),
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn shutdown(self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Shutdown(tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn network(error: impl std::fmt::Display + std::fmt::Debug) -> Error {
    Error::Network(format!("{error} ({error:?})"))
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
) {
    let local = *swarm.local_peer_id();
    let permits = Arc::new(Semaphore::new(max_sessions));
    let handlers = Arc::new(Semaphore::new(max_sessions));
    let mut tasks = JoinSet::new();
    let mut pending: HashMap<PeerId, Vec<oneshot::Sender<Result<()>>>> = HashMap::new();
    type DiscoveryQuery = (oneshot::Sender<Result<Vec<PeerId>>>, HashSet<PeerId>);
    let mut queries: HashMap<kad::QueryId, DiscoveryQuery> = HashMap::new();
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
                    let key=provider_key(service);
                    let result=swarm.behaviour_mut().kad.start_providing(key).map(|_|()).map_err(network);
                    let _=response.send(result);
                }
                Some(Command::Withdraw(service))=>{swarm.behaviour_mut().kad.stop_providing(&provider_key(service));}
                Some(Command::Discover(service,response))=>{
                    queries.retain(|_,(sender,_)|!sender.is_closed());
                    if queries.len()>=COMMAND_CAPACITY{let _=response.send(Err(Error::Capacity));continue;}
                    let query=swarm.behaviour_mut().kad.get_providers(provider_key(service));
                    queries.insert(query,(response,HashSet::new()));
                }
                Some(Command::Listen(address, response)) => { let _ = response.send(swarm.listen_on(address).map(|_| ()).map_err(network)); }
                Some(Command::External(address)) => { swarm.add_external_address(address); }
                Some(Command::Shutdown(response)) => {
                    tasks.abort_all();
                    drop(swarm);
                    let _ = response.send(());
                    return;
                }
                None => return,
            },
            Some((peer, mut stream)) = directories.next() => {
                let Ok(permit) = handlers.clone().try_acquire_owned() else { continue; };
                let catalog = catalog.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(REQUEST_TIMEOUT, async {
                        let _: DirectoryRequest = read_frame(&mut stream).await?;
                        let mut services: Vec<_> = catalog.read().await.values().map(Service::record).collect();
                        services.sort_by(|a, b| a.id.cmp(&b.id));
                        write_frame(&mut stream, &DirectoryResponse { services }).await
                    }).await;
                    if !matches!(result, Ok(Ok(()))) { tracing::debug!(%peer, "directory exchange failed"); }
                });
            }
            Some((peer, stream)) = sessions.next() => {
                let Ok(permit) = handlers.clone().try_acquire_owned() else { continue; };
                let (catalog, incoming, permits) = (catalog.clone(), incoming.clone(), permits.clone());
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(REQUEST_TIMEOUT, accept_session(peer, local, stream, catalog, incoming, permits)).await;
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
                    for (peer,address) in peers.into_iter().take(64){swarm.behaviour_mut().kad.add_address(&peer,address.clone());swarm.add_peer_address(peer,address);}
                }
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers)))=>{
                    for (peer,address) in peers{swarm.behaviour_mut().kad.remove_address(&peer,&address);}
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
) -> Result<()> {
    let request: OpenRequest = read_frame(&mut stream).await?;
    let id: ServiceId = request.service_id.parse()?;
    let catalog = catalog.read().await;
    let Some(service) = catalog.get(&id) else {
        return write_frame(
            &mut stream,
            &OpenResponse {
                status: Status::NotFound as i32,
            },
        )
        .await;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(network)?
        .as_secs();
    let authorization: Result<Option<crate::federation::StudentClaims>> = match &service.access {
        AccessPolicy::Students {
            trust,
            minimum,
            current_enrollment,
        } => (|| {
            let proof: crate::federation::StudentPresentation =
                serde_json::from_slice(&request.student).map_err(|_| Error::Denied)?;
            let (circle, claims) = if *current_enrollment {
                trust.verify_current_student(&proof.credential, peer, &proof.profile, now)?
            } else {
                trust.verify(&proof.credential, peer, &proof.profile, now)?
            };
            if circle < *minimum {
                return Err(Error::Denied);
            }
            Ok(Some(claims))
        })(),
        access => access
            .authorize(
                peer,
                local,
                id,
                request.grant.map(SignedGrant).as_ref(),
                now,
            )
            .map(|()| None),
    };
    let student = match authorization {
        Ok(student) => student,
        Err(_) => {
            return write_frame(
                &mut stream,
                &OpenResponse {
                    status: Status::Denied as i32,
                },
            )
            .await;
        }
    };
    // Authorization is fixed at admission. Later revocation prevents new sessions.
    drop(catalog);
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
        stream,
        student,
        _permit: permit,
    });
    Ok(())
}

fn provider_key(service: ServiceId) -> kad::RecordKey {
    kad::RecordKey::new(&format!("jlucraft/service/{service}"))
}
