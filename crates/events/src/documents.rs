//! Host-owned document storage. Read permission covers one configured collection.
use node::{Node, PeerId, ServiceId};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use wire::{
    Error, Result,
    protocol::{DocumentChunk, DocumentRequest, digest, read_frame, write_frame},
};
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 32 * 1024;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
use wire::protocol::validate_digest;
fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Denied);
    }
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
/// Local operator action, never an arbitrary remote filesystem write.
pub fn store(directory: &Path, source: &Path) -> Result<String> {
    let bytes = bounded_read(source)?;
    let hash = digest(&bytes);
    std::fs::create_dir_all(directory)?;
    let path = directory.join(&hash);
    // Link a fully synced temporary inode into place: interrupted writes never
    // reserve the content address with an incomplete document.
    let mut temporary = None;
    const TEMP_ATTEMPTS: usize = 32;
    for attempt in 0..TEMP_ATTEMPTS {
        let candidate = directory.join(format!(".{hash}.{}.{}.tmp", std::process::id(), attempt));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                temporary = Some((Temporary(candidate), file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let (temporary, mut file) = temporary.ok_or(Error::Capacity)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    match std::fs::hard_link(&temporary.0, &path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if load(directory, &hash)? != bytes {
                return Err(Error::Denied);
            }
        }
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(hash)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn load(directory: &Path, hash: &str) -> Result<Vec<u8>> {
    validate_digest(hash)?;
    let path = directory.join(hash);
    if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(Error::Denied);
    }
    let bytes = bounded_read(&path)?;
    if digest(&bytes) != hash {
        return Err(Error::Denied);
    }
    Ok(bytes)
}
/// Serve only the configured document service; its caller must publish an authorization policy.
pub async fn serve(
    mut incoming: tokio::sync::mpsc::Receiver<node::IncomingSession>,
    service: ServiceId,
    directory: PathBuf,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            session=incoming.recv()=>{
                let Some(mut session)=session else {break;};
                if session.service!=service {continue;}
                let directory=directory.clone();
                tasks.spawn(async move {
                    let _=tokio::time::timeout(EXCHANGE_TIMEOUT,async {
                        let request:DocumentRequest=read_frame(&mut session.stream).await?;
                        let data=tokio::task::spawn_blocking(move || load(&directory,&request.hash)).await.map_err(|e|Error::Network(e.to_string()))??;
                        if data.is_empty() {write_frame(&mut session.stream,&DocumentChunk{data:Vec::new(),sequence:0,last:true}).await?;}
                        let count=data.len().div_ceil(CHUNK_BYTES);
                        for (sequence,chunk) in data.chunks(CHUNK_BYTES).enumerate() {
                            write_frame(&mut session.stream,&DocumentChunk{data:chunk.to_vec(),sequence:sequence as u32,last:sequence+1==count}).await?;
                        }
                        Ok::<_,Error>(())
                    }).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty()=>{},
        }
    }
    tasks.shutdown().await;
    Ok(())
}
pub async fn fetch(node: &Node, peer: PeerId, service: ServiceId, hash: &str) -> Result<Vec<u8>> {
    validate_digest(hash)?;
    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let mut stream = node.open_service(peer, service).await?;
        write_frame(&mut stream, &DocumentRequest { hash: hash.into() }).await?;
        let mut data = Vec::new();
        for sequence in 0..=MAX_DOCUMENT_BYTES / CHUNK_BYTES {
            let chunk: DocumentChunk = read_frame(&mut stream).await?;
            if chunk.sequence as usize != sequence
                || data.len().saturating_add(chunk.data.len()) > MAX_DOCUMENT_BYTES
                || (!chunk.last && chunk.data.is_empty())
            {
                return Err(Error::Denied);
            }
            data.extend(chunk.data);
            if chunk.last {
                if digest(&data) != hash {
                    return Err(Error::Denied);
                }
                return Ok(data);
            }
        }
        Err(Error::Capacity)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_addressing_is_bounded_and_detects_corruption() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("source");
        std::fs::write(&source, b"planning document")?;
        let collection = dir.path().join("collection");
        let hash = store(&collection, &source)?;
        assert_eq!(store(&collection, &source)?, hash);
        assert_eq!(load(&collection, &hash)?, b"planning document");
        assert!(load(&collection, "../source").is_err());
        std::fs::write(collection.join(&hash), b"tampered")?;
        assert!(load(&collection, &hash).is_err());
        assert!(store(&collection, &source).is_err());
        let file = std::fs::File::create(&source)?;
        file.set_len(MAX_DOCUMENT_BYTES as u64 + 1)?;
        assert!(matches!(store(&collection, &source), Err(Error::Capacity)));
        Ok(())
    }
}
