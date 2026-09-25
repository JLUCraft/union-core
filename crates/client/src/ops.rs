//! Shared federated-server operations client. One request frame, one response frame.
use crate::{
    Error, Node, PeerId, Result, ServiceId,
    protocol::{JsonFrame, OpsRequest, OpsResponse, read_frame, write_frame},
};

/// Execute one operation on a node whose connection/address is prepared by the caller.
/// Application failures (`ok: false`) are returned intact; transport, envelope and
/// JSON failures use the shared client error. The owned stream is dropped on every exit.
pub async fn execute(
    node: &Node,
    peer: PeerId,
    service: ServiceId,
    request: &OpsRequest,
) -> Result<OpsResponse> {
    let mut stream = node.open_service(peer, service).await?;
    write_frame(
        &mut stream,
        &JsonFrame {
            json: serde_json::to_vec(request).map_err(protocol)?,
            last: true,
            sequence: 0,
        },
    )
    .await?;
    let frame: JsonFrame = read_frame(&mut stream).await?;
    if frame.sequence != 0 || !frame.last {
        return Err(Error::Protocol("invalid ops envelope".into()));
    }
    let response = serde_json::from_slice::<OpsResponse>(&frame.json).map_err(protocol);
    drop(stream);
    response
}

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}
