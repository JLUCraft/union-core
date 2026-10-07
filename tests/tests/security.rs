use futures::io::Cursor;
use identity::Identity;
use node::Error;
use protocol::{self, DirectoryRequest};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn identity_survives_restart_and_never_overwrites() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("node.key");
    let identity = Identity::generate();
    identity.save_new(&path)?;
    assert_eq!(Identity::load(&path)?.peer_id(), identity.peer_id());
    assert!(Identity::generate().save_new(&path).is_err());
    assert_eq!(Identity::load(&path)?.peer_id(), identity.peer_id());
    std::fs::write(&path, b"corrupt")?;
    assert!(Identity::load(&path).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn refuses_world_readable_or_symlink_keys() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("node.key");
    Identity::generate().save_new(&path)?;
    let link = directory.path().join("link.key");
    symlink(&path, &link)?;
    assert!(Identity::load(link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(Identity::load(path).is_err());
    Ok(())
}

#[tokio::test]
async fn bounded_framing_rejects_oversized_and_truncated_input() -> TestResult {
    let mut bytes = Cursor::new(((protocol::MAX_FRAME + 1) as u32).to_be_bytes().to_vec());
    assert!(matches!(
        protocol::read_frame::<DirectoryRequest>(&mut bytes).await,
        Err(Error::Protocol(_))
    ));
    let mut bytes = Cursor::new(vec![0, 0, 0, 4, 1]);
    assert!(
        protocol::read_frame::<DirectoryRequest>(&mut bytes)
            .await
            .is_err()
    );
    let mut bytes = Cursor::new(Vec::new());
    protocol::write_frame(&mut bytes, &DirectoryRequest {}).await?;
    // Golden frame fixture: empty protobuf request with a four-byte length prefix.
    assert_eq!(bytes.get_ref(), &[0, 0, 0, 0]);
    bytes.set_position(0);
    let _: DirectoryRequest = protocol::read_frame(&mut bytes).await?;
    Ok(())
}
