//! LeagueDomain-bound journal client bindings.
use crate::LeagueDomain;

pub use authority::journal::{
    Exchange, JsonFrame, MAX_SNAPSHOT, PROTOCOL, Request, SignedCommand, SnapshotProof, now_ms,
};
/// League-bound signed command.
pub type Command = authority::journal::Command<LeagueDomain>;
/// League-bound durable governance journal.
pub type Journal = authority::journal::Journal<LeagueDomain>;
/// League-bound snapshot or rejection reply.
pub type Response = authority::journal::Response<LeagueDomain>;

/// Request one bounded governance exchange from a peer's journal service.
pub async fn request(
    node: &authority::Node,
    peer: crate::PeerId,
    genesis: &str,
    request: Request,
) -> crate::Result<Response> {
    authority::journal::request(node, peer, genesis, request).await
}

/// Serve the governance journal protocol until the node stops.
pub async fn serve(
    node: &authority::Node,
    journal: std::sync::Arc<authority::tokio::sync::Mutex<Journal>>,
    identity: authority::trust::TrustView,
) -> crate::Result<()> {
    authority::journal::serve(node, journal, identity).await
}
