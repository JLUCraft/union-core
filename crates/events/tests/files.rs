use events::files::FileStore;
use protocol::{Cid, FileLayout, FileNode, IpldBlock, Result};
#[test]
fn standard_cid_diff_checkpoint_history_and_corruption() -> Result<()> {
    assert_eq!(
        Cid::of(b"", false).to_string(),
        "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
    );
    let mut store = FileStore::default();
    let mut bytes = vec![b'a'; 100_000];
    let (first, blocks) = store.version(None, &bytes)?;
    for block in blocks {
        store.put(block)?;
    }
    let mut parent = first.clone();
    let mut history = vec![(first.clone(), bytes.clone())];
    for i in 0..20 {
        bytes[100 + i] = b'b';
        let (cid, blocks) = store.version(Some(parent.clone()), &bytes)?;
        if i < 16 {
            assert!(blocks.iter().map(|b| b.data.len()).sum::<usize>() < 1000);
        }
        for block in blocks {
            store.put(block)?;
        }
        assert_eq!(store.read(&cid)?, bytes);
        history.push((cid.clone(), bytes.clone()));
        parent = cid;
    }
    for (cid, bytes) in history {
        assert_eq!(store.read(&cid)?, bytes);
    }
    let bad = IpldBlock::node(&FileNode::File {
        parent: Some(parent.link()),
        size: 0,
        checksum: protocol::digest(b""),
        depth: 1,
        layout: FileLayout::Diff {
            offset: u64::MAX,
            remove: 1,
            insert: first.link(),
        },
    })?;
    assert!(store.put(bad).is_err());
    let raw = IpldBlock::raw(b"tamper")?;
    let cid = raw.cid.clone();
    store.put(raw)?;
    store.blocks.insert(cid.clone(), "b29wcw".into());
    assert!(store.block(&cid).is_err());
    assert!("../../file".parse::<Cid>().is_err());
    assert!(
        serde_json::from_str::<FileNode>(r#"{"type":"chunks","children":[],"extra":1}"#).is_err()
    );
    let (empty, blocks) = store.version(None, b"")?;
    for block in blocks {
        store.put(block)?;
    }
    assert!(store.read(&empty)?.is_empty());

    Ok(())
}
#[test]
fn directory_heads_compare_and_swap_and_preserve_history() -> Result<()> {
    let mut store = FileStore::default();
    let (file, blocks) = store.version(None, b"plan")?;
    for block in blocks {
        store.put(block)?;
    }
    let commit = IpldBlock::node(&FileNode::Commit {
        parent: None,
        files: [("plan.txt".into(), file.link())].into(),
        message: "initial".into(),
    })?;
    let cid = commit.cid.clone();
    store.put(commit)?;
    store.advance("main".into(), None, cid.clone(), "a", "alice", 1)?;
    assert!(
        store
            .advance("main".into(), None, cid.clone(), "a", "alice", 2)
            .is_err()
    );
    let next = IpldBlock::node(&FileNode::Commit {
        parent: Some(cid.link()),
        files: Default::default(),
        message: "delete".into(),
    })?;
    let next_id = next.cid.clone();
    store.put(next)?;
    assert!(
        store
            .advance(
                "main".into(),
                Some(cid.clone()),
                next_id.clone(),
                "b",
                "bob",
                2
            )
            .is_err()
    );
    store.advance("main".into(), Some(cid), next_id, "a", "alice", 2)?;
    assert_eq!(store.read(&file)?, b"plan");
    Ok(())
}
