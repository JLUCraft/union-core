use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use terminal_runtime::{NodeArgs, TargetArgs, init_logging, load_grant, run_proxy};
use union_core::{Grant, Identity, PeerId, ServiceId, SignedGrant};

#[derive(Parser)]
#[command(version, about = "Federation management terminal foundation")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a holder-bound student credential using local school trust roots.
    VerifyStudent {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        holder: PeerId,
        #[arg(long)]
        profile: String,
    },
    /// Sign an explicitly scoped school delegation for a skin-station issuer.
    DelegateStudents {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        claims: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Signed governance request. Omit --action for a snapshot; action is a JSON file.
    Governance {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        revision: Option<u64>,
        #[arg(long)]
        action: Option<PathBuf>,
    },
    /// Create a device/issuer key without overwriting an existing identity.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public PeerId for an existing key.
    Identity {
        #[arg(long)]
        key: PathBuf,
    },
    /// Allocate a stable service identifier.
    NewServiceId,
    /// Find a service via federation discovery seeds; providers are untrusted hints.
    Discover {
        #[command(flatten)]
        node: NodeArgs,
        #[arg(long)]
        service: ServiceId,
    },
    /// Watch invalidations; reconnecting consumers must pull a new snapshot.
    Watch {
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value_t = 0)]
        after_revision: u64,
    },
    /// Query a known host's authenticated service directory.
    List {
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Issue a holder-bound service grant using a key explicitly trusted by the host.
    IssueGrant {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        subject: PeerId,
        #[arg(long)]
        audience: PeerId,
        #[arg(long)]
        service: ServiceId,
        #[arg(long, default_value_t = 3600)]
        valid_seconds: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// List installed Minecraft instances discovered by the minecraftd library.
    LocalInstances,
    /// Expose a local TCP endpoint for an existing Minecraft client through the federation proxy.
    Proxy {
        #[command(flatten)]
        node: Box<NodeArgs>,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        service: ServiceId,
        #[arg(long)]
        ticket: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:25566")]
        bind: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    match Args::parse().command {
        Command::VerifyStudent {
            policy,
            credential,
            holder,
            profile,
        } => {
            let policy: union_core::federation::TrustPolicy =
                serde_json::from_slice(&std::fs::read(policy)?)?;
            let credential = serde_json::from_slice(&std::fs::read(credential)?)?;
            let result = policy.verify(
                &credential,
                holder,
                &profile,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::DelegateStudents { key, claims, out } => {
            let claims = serde_json::from_slice(&std::fs::read(claims)?)?;
            let signed = union_core::federation::delegate(&Identity::load(key)?, claims)?;
            let mut file = OpenOptions::new().write(true).create_new(true).open(out)?;
            file.write_all(&serde_json::to_vec_pretty(&signed)?)?;
            file.sync_all()?;
        }
        Command::Governance {
            key,
            address,
            peer,
            revision,
            action,
        } => {
            let action = action
                .map(|path| -> Result<_> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
                .transpose()?;
            let reply = union_core::client::execute(
                Identity::load(key)?,
                union_core::client::Input {
                    address,
                    peer,
                    revision,
                    action,
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&reply)?);
            anyhow::ensure!(reply.error.is_none(), "governance request rejected");
        }
        Command::Keygen { out } => {
            let identity = Identity::generate();
            identity.save_new(out)?;
            println!("{}", identity.peer_id());
        }
        Command::Identity { key } => println!("{}", Identity::load(key)?.peer_id()),
        Command::Discover { node, service } => {
            let node = node.start(false).await?;
            for peer in node.discover(service).await? {
                println!("{peer}");
            }
            node.shutdown().await?;
        }
        Command::Watch {
            node,
            target,
            after_revision,
        } => {
            let node = node.start(false).await?;
            target.connect(&node).await?;
            let mut events =
                union_core::events::subscribe(&node, target.peer, after_revision).await?;
            loop {
                tokio::select! {result=union_core::events::next(&mut events)=>println!("{}",serde_json::to_string(&result?)?),_=tokio::signal::ctrl_c()=>break}
            }
            node.shutdown().await?;
        }
        Command::NewServiceId => println!("{}", ServiceId::new()),
        Command::List { node, target } => {
            let node = node.start(false).await?;
            target.connect(&node).await?;
            for service in node.list_services(target.peer).await? {
                println!("{}\t{}\t{}", service.id, service.protocol, service.name);
            }
            node.shutdown().await?;
        }
        Command::IssueGrant {
            key,
            subject,
            audience,
            service,
            valid_seconds,
            out,
        } => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let grant = SignedGrant::issue(
                &Identity::load(key)?,
                Grant {
                    subject,
                    audience,
                    service,
                    not_before: now,
                    expires_at: now.checked_add(valid_seconds).context("expiry overflow")?,
                },
            )?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(out)?;
            file.write_all(&grant.encode())?;
            file.sync_all()?;
            println!("{}", grant.id()?);
        }
        Command::LocalInstances => {
            for instance in minecraftd::discovery::discover() {
                println!(
                    "{}\t{}\t{}",
                    instance.id,
                    instance.kind.as_str(),
                    instance.path.display()
                );
            }
        }
        Command::Proxy {
            node,
            target,
            service,
            ticket,
            bind,
        } => {
            let grant = load_grant(ticket.as_deref())?;
            run_proxy(node.start(false).await?, target, service, grant, bind).await?;
        }
    }
    Ok(())
}
