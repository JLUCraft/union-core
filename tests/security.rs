use futures::io::Cursor;
use prost::Message;
use std::collections::HashSet;
use union_core::{
    AccessPolicy, Error, Grant, Identity, ServiceId, SignedGrant,
    protocol::{self, DirectoryRequest, GrantEnvelope},
};

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

#[test]
fn grants_bind_issuer_holder_host_service_time_and_revocation() -> TestResult {
    let issuer = Identity::generate();
    let subject = Identity::generate().peer_id();
    let audience = Identity::generate().peer_id();
    let service = ServiceId::new();
    let policy = AccessPolicy::Grants {
        issuers: [issuer.peer_id()].into(),
        revoked: HashSet::new(),
    };
    let signed = SignedGrant::issue(
        &issuer,
        Grant {
            subject,
            audience,
            service,
            not_before: 100,
            expires_at: 200,
        },
    )?;
    let signed = SignedGrant::decode(&signed.encode())?;
    policy.authorize(subject, audience, service, Some(&signed), 100)?;
    assert!(
        policy
            .authorize(subject, audience, service, Some(&signed), 99)
            .is_err()
    );
    assert!(
        policy
            .authorize(subject, audience, service, Some(&signed), 200)
            .is_err()
    );
    assert!(
        policy
            .authorize(issuer.peer_id(), audience, service, Some(&signed), 150)
            .is_err()
    );
    assert!(
        policy
            .authorize(subject, issuer.peer_id(), service, Some(&signed), 150)
            .is_err()
    );
    assert!(
        policy
            .authorize(subject, audience, ServiceId::new(), Some(&signed), 150)
            .is_err()
    );
    assert!(
        policy
            .authorize(subject, audience, service, None, 150)
            .is_err()
    );
    let foreign = AccessPolicy::Grants {
        issuers: [Identity::generate().peer_id()].into(),
        revoked: HashSet::new(),
    };
    assert!(
        foreign
            .authorize(subject, audience, service, Some(&signed), 150)
            .is_err()
    );
    let revoked = AccessPolicy::Grants {
        issuers: [issuer.peer_id()].into(),
        revoked: [signed.id()?].into(),
    };
    assert!(
        revoked
            .authorize(subject, audience, service, Some(&signed), 150)
            .is_err()
    );
    let mut envelope = GrantEnvelope::decode(signed.encode().as_slice())?;
    envelope.claims.push(0);
    let tampered = SignedGrant::decode(&envelope.encode_to_vec())?;
    assert!(
        policy
            .authorize(subject, audience, service, Some(&tampered), 150)
            .is_err()
    );
    // Owning the host does not make its key a trusted federation issuer.
    let hosting_key = Identity::generate();
    let forged_authority = SignedGrant::issue(
        &hosting_key,
        Grant {
            subject,
            audience,
            service,
            not_before: 100,
            expires_at: 200,
        },
    )?;
    assert!(
        policy
            .authorize(subject, audience, service, Some(&forged_authority), 150)
            .is_err()
    );
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
    // Golden wire fixture: empty protobuf request with a four-byte length prefix.
    assert_eq!(bytes.get_ref(), &[0, 0, 0, 0]);
    bytes.set_position(0);
    let _: DirectoryRequest = protocol::read_frame(&mut bytes).await?;
    Ok(())
}
