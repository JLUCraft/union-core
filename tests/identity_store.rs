use union_core::Identity;
#[test]
fn os_vault_secret_roundtrip_preserves_peer_and_rejects_invalid_material() {
    let identity = Identity::generate();
    let mut bytes = identity.export_secret().expect("export");
    assert_eq!(
        Identity::import_secret(&bytes).expect("import").peer_id(),
        identity.peer_id()
    );
    assert!(Identity::import_secret(&[]).is_err());
    assert!(Identity::import_secret(&vec![0; 4097]).is_err());
    bytes.fill(0);
    assert!(Identity::import_secret(&bytes).is_err());
}
