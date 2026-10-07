//! A bounded CIDv1/raw/DAG-JSON profile, using standard multibase and SHA2-256.
use crate::{Cid, Error, FileNode, IpldBlock, IpldLink, Result};
use sha2::{Digest, Sha256};
pub const BLOCK_BYTES: usize = 4096;
const RAW: &[u8] = &[1, 0x55, 0x12, 32];
const DAG_JSON: &[u8] = &[1, 0xa9, 2, 0x12, 32];
impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::str::FromStr for Cid {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.len() > 64 {
            return Err(Error::Denied);
        }
        let (base, bytes) = multibase::decode(s).map_err(|_| Error::Denied)?;
        if base != multibase::Base::Base32Lower
            || ![RAW, DAG_JSON]
                .iter()
                .any(|p| bytes.starts_with(p) && bytes.len() == p.len() + 32)
            || multibase::encode(base, &bytes) != s
        {
            return Err(Error::Denied);
        }
        Ok(Self(s.into()))
    }
}
impl Cid {
    pub fn of(bytes: &[u8], dag: bool) -> Self {
        let mut cid = if dag { DAG_JSON } else { RAW }.to_vec();
        cid.extend(Sha256::digest(bytes));
        Self(multibase::encode(multibase::Base::Base32Lower, cid))
    }
    pub fn is_raw(&self) -> bool {
        multibase::decode(&self.0).is_ok_and(|(_, b)| b.starts_with(RAW))
    }
    pub fn link(&self) -> IpldLink {
        IpldLink { cid: self.clone() }
    }
}
impl IpldBlock {
    pub fn raw(bytes: &[u8]) -> Result<Self> {
        Self::encode(bytes, false)
    }
    pub fn node(node: &FileNode) -> Result<Self> {
        // Remain canonical even when another crate enables serde_json/preserve_order.
        let mut value = serde_json::to_value(node).map_err(Error::protocol)?;
        value.sort_all_objects();
        Self::encode(&serde_json::to_vec(&value).map_err(Error::protocol)?, true)
    }
    fn encode(bytes: &[u8], dag: bool) -> Result<Self> {
        if bytes.len() > BLOCK_BYTES {
            return Err(Error::Capacity);
        }
        let encoded = multibase::encode(multibase::Base::Base64, bytes);
        Ok(Self {
            cid: Cid::of(bytes, dag),
            data: encoded[1..].into(),
        })
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.data.len() > BLOCK_BYTES.div_ceil(3) * 4 {
            return Err(Error::Capacity);
        }
        let (_, bytes) = multibase::decode(format!("m{}", self.data)).map_err(|_| Error::Denied)?;
        if bytes.len() > BLOCK_BYTES
            || Cid::of(&bytes, !self.cid.is_raw()) != self.cid
            || multibase::encode(multibase::Base::Base64, &bytes)[1..] != self.data
        {
            return Err(Error::Denied);
        }
        if !self.cid.is_raw() {
            let node: FileNode = serde_json::from_slice(&bytes).map_err(Error::protocol)?;
            if Self::node(&node)?.cid != self.cid {
                return Err(Error::Denied);
            }
        }
        Ok(bytes)
    }
    pub fn decode(&self) -> Result<FileNode> {
        if self.cid.is_raw() {
            return Err(Error::Denied);
        }
        serde_json::from_slice(&self.bytes()?).map_err(Error::protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_json_uses_canonical_key_order() -> Result<()> {
        let block = IpldBlock::node(&FileNode::Commit {
            parent: None,
            files: Default::default(),
            message: "initial".into(),
        })?;
        let expected = br#"{"files":{},"message":"initial","parent":null,"type":"commit"}"#;
        assert_eq!(block.bytes()?, expected);
        assert_eq!(block.cid, Cid::of(expected, true));
        Ok(())
    }
}
