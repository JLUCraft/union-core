//! Replicated immutable blocks and compare-and-swap directory heads.
use protocol::{
    Cid, Error, FileLayout, FileNode, IpldBlock, IpldLink, Result, digest, ipld::BLOCK_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STORE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMMIT_PATHS: usize = 24;
const FANOUT: usize = MAX_COMMIT_PATHS;
const MAX_DIFF_DEPTH: u32 = 16;
const MAX_TREE_DEPTH: usize = 4;
const MAX_BRANCHES: usize = 256;
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStore {
    pub blocks: BTreeMap<Cid, String>,
    pub branches: BTreeMap<String, Head>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub commit: Cid,
    pub club: String,
    pub author: String,
    pub revision: u64,
}
impl FileStore {
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.branches.is_empty()
    }
    pub fn block(&self, cid: &Cid) -> Result<IpldBlock> {
        let data = self.blocks.get(cid).ok_or(Error::NotFound)?.clone();
        let block = IpldBlock {
            cid: cid.clone(),
            data,
        };
        block.bytes()?;
        Ok(block)
    }
    pub fn put(&mut self, block: IpldBlock) -> Result<()> {
        block.bytes()?;
        if let Some(old) = self.blocks.get(&block.cid) {
            return if old == &block.data {
                Ok(())
            } else {
                Err(Error::Denied)
            };
        }
        if self.blocks.len() >= MAX_STORE_BYTES / 32
            || self
                .blocks
                .iter()
                .map(|(k, v)| k.to_string().len() + v.len())
                .sum::<usize>()
                + block.data.len()
                + block.cid.to_string().len()
                > MAX_STORE_BYTES
        {
            return Err(Error::Capacity);
        }
        if !block.cid.is_raw() {
            self.validate(&block.decode()?)?;
        }
        self.blocks.insert(block.cid, block.data);
        Ok(())
    }
    fn validate(&self, node: &FileNode) -> Result<()> {
        match node {
            FileNode::Chunks { children } => {
                if children.is_empty() || children.len() > FANOUT {
                    return Err(Error::Denied);
                }
                let mut bytes = Vec::new();
                for child in children {
                    self.tree(&child.cid, 1, &mut bytes)?;
                }
            }
            FileNode::File {
                parent,
                size,
                checksum,
                depth,
                layout,
            } => {
                if *size > MAX_FILE_BYTES as u64 || *depth > MAX_DIFF_DEPTH {
                    return Err(Error::Capacity);
                }
                if let Some(parent) = parent {
                    self.file_node(&parent.cid)?;
                }
                let bytes = self.materialize(node, 0)?;
                if bytes.len() as u64 != *size || digest(&bytes) != *checksum {
                    return Err(Error::Denied);
                }
                match layout {
                    FileLayout::Full { .. } if *depth != 0 => return Err(Error::Denied),
                    FileLayout::Diff { .. } => {
                        let base = self.file_node(&parent.as_ref().ok_or(Error::Denied)?.cid)?;
                        if !matches!(base, FileNode::File { depth: d, .. } if d.checked_add(1) == Some(*depth))
                        {
                            return Err(Error::Denied);
                        }
                    }
                    _ => {}
                }
            }
            FileNode::Commit {
                parent,
                files,
                message,
            } => {
                if files.len() > MAX_COMMIT_PATHS || message.len() > 1024 {
                    return Err(Error::Capacity);
                }
                if let Some(parent) = parent {
                    self.commit(&parent.cid)?;
                }
                for (path, file) in files {
                    if path.is_empty()
                        || path.len() > 256
                        || path.contains('\\')
                        || path.chars().any(char::is_control)
                        || path
                            .split('/')
                            .any(|p| p.is_empty() || p == "." || p == "..")
                    {
                        return Err(Error::Denied);
                    }
                    self.file_node(&file.cid)?;
                }
            }
        }
        Ok(())
    }
    pub fn commit(&self, cid: &Cid) -> Result<FileNode> {
        let node = self.block(cid)?.decode()?;
        if !matches!(node, FileNode::Commit { .. }) {
            return Err(Error::Denied);
        }
        Ok(node)
    }
    fn file_node(&self, cid: &Cid) -> Result<FileNode> {
        let node = self.block(cid)?.decode()?;
        if !matches!(node, FileNode::File { .. }) {
            return Err(Error::Denied);
        }
        Ok(node)
    }
    fn tree(&self, cid: &Cid, depth: usize, out: &mut Vec<u8>) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(Error::Capacity);
        }
        let block = self.block(cid)?;
        if cid.is_raw() {
            let bytes = block.bytes()?;
            if out.len() + bytes.len() > MAX_FILE_BYTES {
                return Err(Error::Capacity);
            }
            out.extend(bytes);
        } else if let FileNode::Chunks { children } = block.decode()? {
            for child in children {
                self.tree(&child.cid, depth + 1, out)?;
            }
        } else {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn materialize(&self, node: &FileNode, depth: u32) -> Result<Vec<u8>> {
        if depth > MAX_DIFF_DEPTH {
            return Err(Error::Capacity);
        }
        let FileNode::File {
            parent,
            layout,
            size,
            checksum,
            ..
        } = node
        else {
            return Err(Error::Denied);
        };
        let bytes = match layout {
            FileLayout::Full { tree } => {
                let mut out = Vec::new();
                self.tree(&tree.cid, 0, &mut out)?;
                out
            }
            FileLayout::Diff {
                offset,
                remove,
                insert,
            } => {
                let parent = self.file_node(&parent.as_ref().ok_or(Error::Denied)?.cid)?;
                let base = self.materialize(&parent, depth + 1)?;
                let start = usize::try_from(*offset).map_err(|_| Error::Capacity)?;
                let end = offset
                    .checked_add(*remove)
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or(Error::Capacity)?;
                if end > base.len() || start > end {
                    return Err(Error::Denied);
                }
                let mut replacement = Vec::new();
                self.tree(&insert.cid, 0, &mut replacement)?;
                if base.len() - (end - start) + replacement.len() > MAX_FILE_BYTES {
                    return Err(Error::Capacity);
                }
                let mut out = base[..start].to_vec();
                out.extend(replacement);
                out.extend_from_slice(&base[end..]);
                out
            }
        };
        if bytes.len() as u64 != *size || digest(&bytes) != *checksum {
            return Err(Error::Denied);
        }
        Ok(bytes)
    }
    pub fn read(&self, cid: &Cid) -> Result<Vec<u8>> {
        self.materialize(&self.file_node(cid)?, 0)
    }
    pub fn advance(
        &mut self,
        branch: String,
        expected: Option<Cid>,
        commit: Cid,
        club: &str,
        author: &str,
        revision: u64,
    ) -> Result<()> {
        state::governance::identifier(&branch)?;
        let old = self.branches.get(&branch);
        if old.map(|h| &h.commit) != expected.as_ref() || old.is_some_and(|h| h.club != club) {
            return Err(Error::Denied);
        }
        if old.is_none() && self.branches.len() >= MAX_BRANCHES {
            return Err(Error::Capacity);
        }
        let FileNode::Commit { parent, .. } = self.commit(&commit)? else {
            return Err(Error::Denied);
        };
        if parent.map(|l| l.cid) != expected {
            return Err(Error::Denied);
        }
        self.branches.insert(
            branch,
            Head {
                commit,
                club: club.into(),
                author: author.into(),
                revision,
            },
        );
        Ok(())
    }
    /// Build blocks in dependency order. Does not change the caller's store or publish a head.
    pub fn version(&self, parent: Option<Cid>, bytes: &[u8]) -> Result<(Cid, Vec<IpldBlock>)> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::Capacity);
        }
        let mut blocks = Vec::new();
        let mut depth = 0;
        let layout = if let Some(base) = &parent {
            let previous = self.read(base)?;
            let FileNode::File {
                depth: old_depth, ..
            } = self.file_node(base)?
            else {
                return Err(Error::Denied);
            };
            if previous == bytes {
                return Ok((base.clone(), blocks));
            }
            let prefix = previous
                .iter()
                .zip(bytes)
                .take_while(|(a, b)| a == b)
                .count();
            let suffix = previous[prefix..]
                .iter()
                .rev()
                .zip(bytes[prefix..].iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let insert = &bytes[prefix..bytes.len() - suffix];
            if old_depth < MAX_DIFF_DEPTH && insert.len() < bytes.len() {
                depth = old_depth + 1;
                FileLayout::Diff {
                    offset: prefix as u64,
                    remove: (previous.len() - prefix - suffix) as u64,
                    insert: build_tree(insert, &mut blocks)?,
                }
            } else {
                FileLayout::Full {
                    tree: build_tree(bytes, &mut blocks)?,
                }
            }
        } else {
            FileLayout::Full {
                tree: build_tree(bytes, &mut blocks)?,
            }
        };
        let block = IpldBlock::node(&FileNode::File {
            parent: parent.map(|c| c.link()),
            size: bytes.len() as u64,
            checksum: digest(bytes),
            depth,
            layout,
        })?;
        let cid = block.cid.clone();
        blocks.push(block);
        blocks.retain(|b| !self.blocks.contains_key(&b.cid));
        Ok((cid, blocks))
    }
}
fn build_tree(bytes: &[u8], blocks: &mut Vec<IpldBlock>) -> Result<IpldLink> {
    let mut links = Vec::new();
    for chunk in bytes
        .chunks(BLOCK_BYTES)
        .chain(bytes.is_empty().then_some(&[][..]))
    {
        let block = IpldBlock::raw(chunk)?;
        links.push(block.cid.link());
        blocks.push(block);
    }
    while links.len() > 1 {
        let mut parents = Vec::new();
        for children in links.chunks(FANOUT) {
            let block = IpldBlock::node(&FileNode::Chunks {
                children: children.to_vec(),
            })?;
            parents.push(block.cid.link());
            blocks.push(block);
        }
        links = parents;
    }
    links.pop().ok_or(Error::Denied)
}
