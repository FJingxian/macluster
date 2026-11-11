use macluster_core::storage_uri::{StorageProtocol, StorageUri};

#[test]
fn nfs_uri_is_normalized_without_a_trailing_slash() {
    let uri = StorageUri::parse("nfs://default-001/Volumes/external-disk/").unwrap();

    assert_eq!(uri.protocol, StorageProtocol::Nfs);
    assert_eq!(uri.server.as_str(), "default-001");
    assert_eq!(uri.source, "/Volumes/external-disk");
    assert_eq!(uri.canonical, "nfs://default-001/Volumes/external-disk");
}

#[test]
fn smb_uri_preserves_share_and_subpath() {
    let uri = StorageUri::parse("smb://nas-01/data/project").unwrap();

    assert_eq!(uri.protocol, StorageProtocol::Smb);
    assert_eq!(uri.server.as_str(), "nas-01");
    assert_eq!(uri.source, "/data/project");
    assert_eq!(uri.canonical, "smb://nas-01/data/project");
}

#[test]
fn percent_encoded_paths_decode_to_one_canonical_identity() {
    let encoded = StorageUri::parse("nfs://default-001/Users/Shared/My%20Data").unwrap();
    let plain = StorageUri::parse("nfs://default-001/Users/Shared/My Data").unwrap();

    assert_eq!(encoded.source, "/Users/Shared/My Data");
    assert_eq!(encoded.canonical, plain.canonical);
}

#[test]
fn uri_rejects_noncanonical_or_ambiguous_inputs() {
    for value in [
        "nfs://default-001",
        "nfs://default-001/",
        "nfs://default-001/a/../b",
        "nfs://default-001/a?query=1",
        "nfs://default-001/a#fragment",
        "ssh://default-001/a",
        "nfs:///a",
        "/Volumes/external-disk",
    ] {
        assert!(
            StorageUri::parse(value).is_err(),
            "{value} must be rejected"
        );
    }
}
