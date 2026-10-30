use macluster_core::config::{ClusterConfig, ConfigError};

const VALID: &str = r#"
[cluster]
name = "macluster"
default_queue = "mini01"
shared_root = "/Users/Shared/macluster"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "mini01-a"
protocol_version = 1

[queues.mini01]
nodes = ["mini01-a"]
scheduler = "fifo"

[nodes.mini01-a]
host = "192.168.2.1"
transport = "ssh"
"#;

#[test]
fn documented_config_resolves_queue_members_and_storage_role() {
    let config = ClusterConfig::parse(VALID).unwrap();

    assert_eq!(config.name, "macluster");
    assert_eq!(config.default_queue.as_str(), "mini01");
    assert_eq!(config.nodes["mini01-a"].host, "192.168.2.1");
    assert_eq!(
        config.nodes["mini01-a"].remote_binary,
        "/usr/local/bin/macluster"
    );
    assert_eq!(config.queues["mini01"].nodes, ["mini01-a"]);
    assert_eq!(config.storage_server.as_str(), "mini01-a");
    assert_eq!(config.protocol_version, 1);
}

#[test]
fn legacy_config_uses_shared_root_as_storage_source_and_keeps_legacy_digest() {
    let config = ClusterConfig::parse(VALID).unwrap();

    assert_eq!(config.login_node, None);
    assert_eq!(
        config.primary_source_root(),
        std::path::Path::new("/Users/Shared/macluster")
    );
    assert_eq!(
        config.execution_digest().unwrap(),
        "10171ec146a3c39899e47515c97f034b55a54379c732d473c159802f6a95776a"
    );
}

#[test]
fn explicit_primary_source_and_local_login_are_parsed_and_digest_visible() {
    let legacy = ClusterConfig::parse(&extended_config()).unwrap();
    let explicit = extended_config().replace(
        "name = \"macluster\"",
        "name = \"macluster\"\nlogin_node = \"login\"\nstorage_source_root = \"/Volumes/Storage/macluster\"",
    );

    let config = ClusterConfig::parse(&explicit).unwrap();

    assert_eq!(config.login_node.as_ref().unwrap().as_str(), "login");
    assert_eq!(
        config.primary_source_root(),
        std::path::Path::new("/Volumes/Storage/macluster")
    );
    assert_ne!(
        config.execution_digest().unwrap(),
        legacy.execution_digest().unwrap()
    );
}

#[test]
fn login_node_must_be_registered_and_local() {
    let missing = VALID.replace(
        "name = \"macluster\"",
        "name = \"macluster\"\nlogin_node = \"missing\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&missing),
        Err(ConfigError::UnknownNode(node)) if node == "missing"
    ));

    let remote_login = VALID.replace(
        "name = \"macluster\"",
        "name = \"macluster\"\nlogin_node = \"mini01-a\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&remote_login),
        Err(ConfigError::LoginNodeMustBeLocal)
    ));
}

#[test]
fn empty_queue_is_valid_but_missing_default_queue_is_rejected() {
    let empty_queue = VALID.replace("nodes = [\"mini01-a\"]", "nodes = []");
    assert!(ClusterConfig::parse(&empty_queue).is_ok());

    let missing = VALID.replace("default_queue = \"mini01\"", "default_queue = \"missing\"");
    assert!(matches!(
        ClusterConfig::parse(&missing),
        Err(ConfigError::UnknownDefaultQueue(_))
    ));
}

#[test]
fn queue_cannot_reference_an_unknown_node() {
    let invalid = VALID.replace("nodes = [\"mini01-a\"]", "nodes = [\"mini01-b\"]");
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::UnknownNode(_))
    ));
}

#[test]
fn unsafe_ids_and_duplicate_config_keys_are_rejected() {
    let unsafe_id = VALID.replace("[queues.mini01]", "[queues.bad.name]");
    assert!(matches!(
        ClusterConfig::parse(&unsafe_id),
        Err(ConfigError::InvalidIdentifier { .. })
    ));

    let duplicate = VALID.replace(
        "name = \"macluster\"",
        "name = \"first\"\nname = \"second\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&duplicate),
        Err(ConfigError::DuplicateKey { .. })
    ));
}

#[test]
fn storage_server_must_be_a_declared_compute_node() {
    let invalid = VALID.replace(
        "storage_server = \"mini01-a\"",
        "storage_server = \"missing\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::UnknownNode(_))
    ));
}

#[test]
fn duplicate_ssh_hosts_and_unsafe_remote_binary_paths_are_rejected() {
    let duplicate_host =
        format!("{VALID}\n[nodes.mini01-b]\nhost = \"192.168.2.1\"\ntransport = \"ssh\"\n");
    assert!(matches!(
        ClusterConfig::parse(&duplicate_host),
        Err(ConfigError::DuplicateHost(_))
    ));
    let unsafe_binary = VALID.replace(
        "transport = \"ssh\"",
        "transport = \"ssh\"\nremote_binary = \"/tmp/macluster;touch\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&unsafe_binary),
        Err(ConfigError::InvalidRemoteBinary)
    ));
}

#[test]
fn ssh_identity_file_is_parsed_and_used_by_ssh_arguments() {
    let configured = VALID.replace(
        "transport = \"ssh\"",
        "transport = \"ssh\"\nssh_identity_file = \"/Users/operator/.ssh/macluster/node-key\"",
    );
    let config = ClusterConfig::parse(&configured);
    assert!(
        config.is_ok(),
        "identity-file config was rejected: {config:?}"
    );
    let config = config.unwrap();
    let node = &config.nodes["mini01-a"];
    assert_eq!(
        node.ssh_identity_file.as_deref(),
        Some("/Users/operator/.ssh/macluster/node-key")
    );

    let mut command = std::process::Command::new("ssh");
    node.add_ssh_identity_args(&mut command);
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(
        args.windows(2)
            .any(|pair| { pair == ["-i", "/Users/operator/.ssh/macluster/node-key"] })
    );
    assert!(args.iter().any(|arg| arg == "-oIdentitiesOnly=yes"));
}

#[test]
fn ssh_identity_file_rejects_relative_and_control_character_paths() {
    for path in [
        "relative/key",
        "/Users/operator/.ssh/key\n-oProxyCommand=bad",
    ] {
        let configured = VALID.replace(
            "transport = \"ssh\"",
            &format!("transport = \"ssh\"\nssh_identity_file = {path:?}"),
        );
        let error = ClusterConfig::parse(&configured).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ssh_identity_file must be an absolute path without control characters"
        );
    }
}

#[test]
fn local_node_and_multiple_named_shares_are_accepted() {
    let parsed = ClusterConfig::parse(&extended_config()).unwrap();
    let debug = format!("{parsed:?}");
    assert!(debug.contains("Local"));
    assert!(debug.contains("tools"));
    assert!(debug.contains("/Users/Shared/macluster-shares/tools"));
    assert!(debug.contains("data"));
}

#[test]
fn named_share_can_be_mounted_at_its_source_path() {
    let source = extended_config();
    let same_path_share = format!(
        "{source}\n[shares.analysis]\nserver = \"login\"\nsource_root = \"/Users/operator/mamba/envs/analysis\"\nmount_root = \"/Users/operator/mamba/envs/analysis\"\nshare_uuid = \"00000000-0000-4000-8000-000000000005\"\n"
    );

    let config = ClusterConfig::parse(&same_path_share).unwrap();

    assert_eq!(
        config.shares["analysis"].source_root,
        config.shares["analysis"].mount_root
    );
}

#[test]
fn named_share_can_explicitly_preserve_and_overlay_local_mount_contents() {
    let config_text = format!(
        "{VALID}\n[shares.homebrew]\nserver = \"mini01-a\"\nsource_root = \"/opt/homebrew\"\nmount_root = \"/opt/homebrew\"\nshare_uuid = \"00000000-0000-4000-8000-000000000005\"\nallow_existing_contents = true\n"
    );

    let parsed = ClusterConfig::parse(&config_text);

    assert!(
        parsed.is_ok(),
        "explicit same-path overlay should be valid: {parsed:?}"
    );
}

#[test]
fn named_share_overlay_rejects_different_source_and_mount_paths() {
    let config_text = format!(
        "{VALID}\n[shares.homebrew]\nserver = \"mini01-a\"\nsource_root = \"/opt/homebrew\"\nmount_root = \"/Users/Shared/homebrew\"\nshare_uuid = \"00000000-0000-4000-8000-000000000005\"\nallow_existing_contents = true\n"
    );

    assert!(matches!(
        ClusterConfig::parse(&config_text),
        Err(ConfigError::InvalidSharePath)
    ));
}

#[test]
fn optional_false_overlay_keeps_existing_execution_digest_stable() {
    let base = format!(
        "{VALID}\n[shares.homebrew]\nserver = \"mini01-a\"\nsource_root = \"/opt/homebrew\"\nmount_root = \"/opt/homebrew\"\nshare_uuid = \"00000000-0000-4000-8000-000000000005\"\n"
    );
    let explicit_false = format!("{base}allow_existing_contents = false\n");
    let explicit_true = format!("{base}allow_existing_contents = true\n");
    let old = ClusterConfig::parse(&base).unwrap();
    let false_config = ClusterConfig::parse(&explicit_false).unwrap();
    let overlay = ClusterConfig::parse(&explicit_true).unwrap();

    assert_eq!(
        old.execution_digest().unwrap(),
        false_config.execution_digest().unwrap()
    );
    assert_ne!(
        old.execution_digest().unwrap(),
        overlay.execution_digest().unwrap()
    );
}

fn extended_config() -> String {
    format!(
        r#"
{VALID}

[nodes.login]
host = "192.168.2.3"
transport = "local"
machine_uuid = "00000000-0000-4000-8000-000000000003"
execution_uid = 501

[shares.tools]
server = "mini01-a"
source_root = "/Users/Shared/tools"
mount_root = "/Users/Shared/macluster-shares/tools"
share_uuid = "00000000-0000-4000-8000-000000000002"

[shares.data]
server = "login"
source_root = "/Users/Shared/data"
mount_root = "/Users/Shared/macluster-shares/data"
share_uuid = "00000000-0000-4000-8000-000000000004"
"#
    )
}

#[test]
fn local_transport_requires_machine_uuid_and_execution_uid() {
    let missing_uid = extended_config().replace("execution_uid = 501\n", "");
    assert!(matches!(
        ClusterConfig::parse(&missing_uid),
        Err(ConfigError::MissingLocalIdentity)
    ));
}

#[test]
fn config_allows_only_one_local_transport_node() {
    let duplicate = format!(
        "{}\n[nodes.login2]\nhost = \"192.168.2.4\"\ntransport = \"local\"\nmachine_uuid = \"00000000-0000-4000-8000-000000000005\"\nexecution_uid = 501\n",
        extended_config()
    );
    assert!(matches!(
        ClusterConfig::parse(&duplicate),
        Err(ConfigError::MultipleLocalNodes)
    ));
}

#[test]
fn one_machine_uuid_cannot_be_declared_under_two_node_ids() {
    let duplicate = format!(
        "{}\n[nodes.mini01-b]\nhost = \"192.168.2.2\"\ntransport = \"ssh\"\nmachine_uuid = \"00000000-0000-4000-8000-000000000003\"\n",
        extended_config()
    );
    assert!(ClusterConfig::parse(&duplicate).is_err());
}

#[test]
fn share_server_must_be_a_declared_node() {
    let invalid = extended_config().replace(
        "[shares.tools]\nserver = \"mini01-a\"",
        "[shares.tools]\nserver = \"missing\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::UnknownNode(node)) if node == "missing"
    ));
}

#[test]
fn share_mount_cannot_overlap_primary_task_share() {
    let invalid = extended_config().replace(
        "mount_root = \"/Users/Shared/macluster-shares/tools\"",
        "mount_root = \"/Users/Shared/macluster/shares/tools\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::ShareMountConflict { .. })
    ));
}

#[test]
fn same_server_exports_cannot_overlap() {
    let invalid = extended_config()
        .replace("server = \"login\"", "server = \"mini01-a\"")
        .replace(
            "source_root = \"/Users/Shared/data\"",
            "source_root = \"/Users/Shared/tools/nested\"",
        );
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::ShareSourceConflict { .. })
    ));
}

#[test]
fn share_mount_paths_cannot_overlap_each_other() {
    let invalid = extended_config().replace(
        "mount_root = \"/Users/Shared/macluster-shares/data\"",
        "mount_root = \"/Users/Shared/macluster-shares/tools/nested\"",
    );
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::ShareMountConflict { .. })
    ));
}

#[test]
fn additional_share_requires_a_canonical_uuid() {
    let invalid = extended_config().replace("00000000-0000-4000-8000-000000000004", "not-a-uuid");
    assert!(matches!(
        ClusterConfig::parse(&invalid),
        Err(ConfigError::InvalidShareUuid)
    ));
}

#[test]
fn execution_digest_ignores_ssh_details_and_toml_comments() {
    let original = extended_config();
    let peer = original
        .replace(
            "transport = \"ssh\"",
            "transport = \"ssh\"\nssh_user = \"operator\"\nssh_port = 2222\nssh_identity_file = \"/Users/operator/.ssh/macluster/worker\"\nremote_config = \"/Users/operator/.config/macluster/peer.toml\"",
        )
        .replace("[shares.data]", "# peer-local comment\n[shares.data]");
    let authoritative = ClusterConfig::parse(&original).unwrap();
    let peer = ClusterConfig::parse(&peer).unwrap();

    assert_eq!(
        authoritative.execution_digest().unwrap(),
        peer.execution_digest().unwrap()
    );
}
