//! Signed block upload followed by a single compare-and-swap directory commit.
use crate::application::Application;
use crate::{Error, Identity, Node, PeerId, Result};
use authority::journal;
use protocol::{Cid, FileNode, IpldBlock};
pub type Snapshot = state::State<Application>;
pub async fn snapshot(node: &Node, peer: PeerId, genesis: &str) -> Result<Snapshot> {
    journal::request::<Application>(
        node,
        peer,
        genesis,
        journal::Request::Snapshot,
        crate::journal::PROTOCOL,
    )
    .await?
    .state
    .ok_or(Error::Denied)
}
pub struct Upload<'a> {
    pub branch: &'a str,
    pub path: &'a str,
    pub message: &'a str,
    pub bytes: &'a [u8],
}
pub async fn upload(
    node: &Node,
    peer: PeerId,
    genesis: &str,
    identity: &Identity,
    upload: Upload<'_>,
    trust: &crate::trust::TrustLog,
) -> Result<Cid> {
    let state = snapshot(node, peer, genesis).await?;
    let store = &state.domain.inner.files;
    let expected = store.branches.get(upload.branch).map(|h| h.commit.clone());
    let mut files = if let Some(head) = &expected {
        let FileNode::Commit { files, .. } = store.commit(head)? else {
            return Err(Error::Denied);
        };
        files
    } else {
        Default::default()
    };
    let parent = files.get(upload.path).map(|link| link.cid.clone());
    let (file, mut blocks) = store.version(parent, upload.bytes)?;
    files.insert(upload.path.into(), file.link());
    let commit = IpldBlock::node(&FileNode::Commit {
        parent: expected.clone().map(|c| c.link()),
        files,
        message: upload.message.into(),
    })?;
    let head = commit.cid.clone();
    blocks.push(commit);
    // Validate everything locally before the first remote write; the server repeats validation.
    let mut preview = store.clone();
    for block in &blocks {
        preview.put(block.clone())?;
    }
    let device = identity.peer_id().to_string();
    let core = state.identity_core(trust.state())?;
    let member = core
        .members
        .values()
        .find(|m| m.owns(&device))
        .ok_or(Error::Denied)?;
    preview.advance(
        upload.branch.into(),
        expected.clone(),
        head.clone(),
        &member.club,
        &device,
        state.revision,
    )?;
    for block in blocks {
        apply_with_identity(
            node,
            peer,
            genesis,
            identity,
            events::EventAction::PutBlock { block },
            trust,
        )
        .await?;
    }
    apply_with_identity(
        node,
        peer,
        genesis,
        identity,
        events::EventAction::CommitFiles {
            branch: upload.branch.into(),
            expected,
            commit: head,
        },
        trust,
    )
    .await?;
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
async fn apply_with_identity(
    node: &Node,
    peer: PeerId,
    genesis: &str,
    identity: &Identity,
    action: events::EventAction,
    trust: &crate::trust::TrustLog,
) -> Result<Snapshot> {
    crate::trust::execute::<Application>(
        node,
        peer,
        genesis,
        identity,
        trust,
        state::governance::Action::Domain(flows::FlowAction::Inner(action)),
        crate::journal::PROTOCOL,
    )
    .await?
    .state
    .ok_or(Error::Denied)
}

pub async fn push(
    node: &Node,
    peer: PeerId,
    request: &protocol::ApplicationPushRequest,
) -> Result<protocol::ApplicationPushResponse> {
    let service = node
        .list_services(peer)
        .await?
        .into_iter()
        .find(|r| r.protocol == protocol::APPLICATION_PUSH_PROTOCOL)
        .ok_or(Error::NotFound)?
        .id
        .parse()
        .map_err(|_| Error::Denied)?;
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut stream = node.open_service(peer, service).await?;
        protocol::write_frame(
            &mut stream,
            &protocol::JsonFrame {
                json: serde_json::to_vec(request).map_err(|e| Error::Protocol(e.to_string()))?,
                sequence: 0,
                last: true,
            },
        )
        .await?;
        let frame: protocol::JsonFrame = protocol::read_frame(&mut stream).await?;
        if frame.sequence != 0 || !frame.last {
            return Err(Error::Denied);
        }
        serde_json::from_slice(&frame.json).map_err(|e| Error::Protocol(e.to_string()))
    })
    .await
    .map_err(|_| Error::Protocol("push registration timed out".into()))?
}

/// Read only the content-addressed store from a presented snapshot. UI number conversion in
/// unrelated fields cannot alter a block's CID or prevent reading already verified file bytes.
pub fn cached_file(snapshot: &serde_json::Value, cid: &str) -> Result<Vec<u8>> {
    let files: events::files::FileStore =
        serde_json::from_value(snapshot.get("files").cloned().ok_or(Error::Denied)?)
            .map_err(Error::protocol)?;
    files.read(&cid.parse()?)
}
