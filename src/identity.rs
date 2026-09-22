use std::{fs, io::Write, path::Path};

use libp2p::{PeerId, identity::Keypair};

use crate::{Error, Result};

/// Device identity. Never implements Debug or serializes private material implicitly.
#[derive(Clone)]
pub struct Identity(pub(crate) Keypair);

impl Identity {
    pub fn generate() -> Self {
        Self(Keypair::generate_ed25519())
    }

    pub fn peer_id(&self) -> PeerId {
        self.0.public().to_peer_id()
    }

    /// Explicit secret export for OS-backed encrypted storage. The caller must
    /// protect and erase this buffer; never log or send it over the network.
    pub fn export_secret(&self) -> Result<Vec<u8>> {
        self.0
            .to_protobuf_encoding()
            .map_err(|e| Error::Identity(e.to_string()))
    }

    /// Import a bounded secret from an unlocked OS credential store.
    pub fn import_secret(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(Error::Identity("invalid key size".into()));
        }
        Keypair::from_protobuf_encoding(bytes)
            .map(Self)
            .map_err(|e| Error::Identity(e.to_string()))
    }

    /// Load an existing identity. Corrupt keys are never silently regenerated.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(Error::Identity("expected a small regular key file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Identity(
                    "key file must be private (chmod 600)".into(),
                ));
            }
        }
        Keypair::from_protobuf_encoding(&fs::read(path)?)
            .map(Self)
            .map_err(|e| Error::Identity(e.to_string()))
    }

    /// Atomically creates a new key; never overwrites an existing file.
    /// On Windows, place this file in a directory protected by the user's ACL.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(
            &self
                .0
                .to_protobuf_encoding()
                .map_err(|e| Error::Identity(e.to_string()))?,
        )?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)
            .map_err(|e| Error::Io(e.error))?;
        Ok(())
    }
}
