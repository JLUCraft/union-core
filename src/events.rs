//! Reliable state is pulled separately; this stream only invalidates cached views.
use crate::{
    Error, Node, PeerId, Result,
    journal::{Journal, JsonFrame},
    protocol::{read_frame, write_frame},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};
pub const PROTOCOL: &str = "/jlucraft/union/events/1";
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub revision: u64,
    pub state_hash: String,
    pub resync: bool,
}
#[derive(Serialize, Deserialize)]
pub struct Subscribe {
    pub after_revision: u64,
}
pub async fn subscribe(node: &Node, peer: PeerId, after_revision: u64) -> Result<crate::Stream> {
    let mut stream = node.open_protocol(peer, PROTOCOL).await?;
    write_frame(
        &mut stream,
        &JsonFrame {
            json: serde_json::to_vec(&Subscribe { after_revision })
                .map_err(|e| Error::Protocol(e.to_string()))?,
            sequence: 0,
            last: true,
        },
    )
    .await?;
    Ok(stream)
}
pub async fn next(stream: &mut crate::Stream) -> Result<Event> {
    let frame: JsonFrame = read_frame(stream).await?;
    if frame.sequence != 0 || !frame.last {
        return Err(Error::Protocol("invalid event frame".into()));
    }
    serde_json::from_slice(&frame.json).map_err(|e| Error::Protocol(e.to_string()))
}
pub async fn serve(node: Arc<Node>, journal: Arc<Mutex<Journal>>) -> Result<()> {
    serve_authority(node, journal.into()).await
}
pub async fn serve_authority(
    node: Arc<Node>,
    authority: crate::authority::Authority,
) -> Result<()> {
    let mut incoming = node.accept_protocol(PROTOCOL)?;
    let capacity = Arc::new(Semaphore::new(128));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
         Some((peer,mut stream))=incoming.next()=>{
          let Ok(permit)=capacity.clone().try_acquire_owned()else{continue;};let authority=authority.clone();
          tasks.spawn(async move{
           let _permit=permit;
           let result:Result<()>=async{
            let frame:JsonFrame=timeout(Duration::from_secs(5),read_frame(&mut stream)).await.map_err(|_|Error::Timeout)??;
            if frame.sequence!=0||!frame.last{return Err(Error::Denied);}
            let subscription:Subscribe=serde_json::from_slice(&frame.json).map_err(|_|Error::Denied)?;
            let mut updates=authority.watch().await;
            authority.state(peer).await?;
            let mut last=subscription.after_revision;let mut first=true;let mut heartbeat=tokio::time::interval(Duration::from_secs(30));
            loop{
             let mut event=updates.borrow_and_update().clone();event.resync=first||event.revision>last.saturating_add(1)||event.revision<last;
             let json=serde_json::to_vec(&event).map_err(|e|Error::Protocol(e.to_string()))?;
             timeout(Duration::from_secs(10),write_frame(&mut stream,&JsonFrame{json,sequence:0,last:true})).await.map_err(|_|Error::Timeout)??;
             last=event.revision;first=false;
             tokio::select!{changed=updates.changed()=>{changed.map_err(|_|Error::Stopped)?;},_=heartbeat.tick()=>{}}
             authority.state(peer).await?;
            }
           }.await;
           if let Err(error)=result{tracing::debug!(%peer,%error,"event subscription ended");}
          });
         }
         Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(error)=result{tracing::error!(%error,"event handler failed");}}
         else=>return Ok(())
        }
    }
}
