use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use macluster_core::config::{ClusterConfig, NodeConfig, QueueConfig, ShareConfig, Transport};
use macluster_protocol::control::{ClientDescriptor, ControlCommand, ControlPayload};
use macluster_protocol::{identifiers::NodeId, types::PROTOCOL_VERSION, types::SchedulerKind};

use crate::{
    client_profile::{ClientProfile, ClientProfileStore, ClientSelection},
    control_client::ControlClient,
};

pub(crate) struct RemoteContext {
    pub profile: ClientProfile,
    pub descriptor: ClientDescriptor,
    pub client: ControlClient,
}

impl RemoteContext {
    pub(crate) fn connect(
        mut profile: ClientProfile,
        ensure_client_storage: bool,
    ) -> Result<Self, String> {
        if storage_command_blocked_by_leave(&profile, ensure_client_storage) {
            return Err(
                "cluster leave is incomplete; rerun `--leave` to finish it or `--join` to reactivate storage"
                    .into(),
            );
        }
        if profile.version == 1 {
            if profile.mounts_enabled {
                profile.mounted_descriptor = profile.descriptor.clone();
            }
        }
        profile.version = crate::client_profile::CLIENT_PROFILE_VERSION;
        let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
        let timeout = Duration::from_secs(8);
        let mut client = ControlClient::connect_remote(&profile, timeout, ensure_client_storage)
            .map_err(|error| error.to_string())?;
        let mut descriptor = request_descriptor(&mut client)?;
        if let Some(binary) = remote_binary_for_descriptor(&profile, &descriptor) {
            profile.remote_binary = binary;
        }
        if needs_mount_reconciliation(
            profile.mounts_enabled,
            ensure_client_storage,
            profile.installed_mount_descriptor(),
            &descriptor,
            &profile.nfs_client_ip,
        ) {
            let mut installed = profile.installed_mount_descriptor().cloned();
            for attempt in 0..3 {
                let mounts_changed = installed.as_ref().is_none_or(|previous| {
                    !crate::client_storage::mount_layout_matches(
                        previous,
                        &descriptor,
                        &profile.nfs_client_ip,
                    )
                });
                if !mounts_changed {
                    break;
                }
                if attempt == 2 {
                    return Err(
                        "Controller configuration kept changing while client mounts were updated; retry the command"
                            .into(),
                    );
                }
                for descriptor in installed.iter().chain(std::iter::once(&descriptor)) {
                    if !profile.transition_mount_descriptors.iter().any(|existing| {
                        crate::client_storage::mount_layout_matches(
                            existing,
                            descriptor,
                            &profile.nfs_client_ip,
                        )
                    }) {
                        profile
                            .transition_mount_descriptors
                            .push(descriptor.clone());
                    }
                }
                store.save(&profile).map_err(|error| error.to_string())?;
                // Do not leave an authenticated control stream idle while
                // administrator prompts can take minutes.
                drop(client);
                if let Some(previous) = installed.as_ref() {
                    crate::client_storage::replace_client_mounts(
                        &profile.cluster_uuid,
                        previous,
                        &descriptor,
                        &profile.nfs_client_ip,
                    )?;
                } else {
                    crate::client_storage::install_client_mounts(
                        &profile.cluster_uuid,
                        &descriptor,
                        &profile.nfs_client_ip,
                    )?;
                }
                installed = Some(descriptor.clone());
                client = ControlClient::connect_remote(&profile, timeout, ensure_client_storage)
                    .map_err(|error| error.to_string())?;
                descriptor = request_descriptor(&mut client)?;
            }
        }
        if profile.mounts_enabled && ensure_client_storage {
            profile.mounted_descriptor = Some(descriptor.clone());
        }
        profile.descriptor_generation = descriptor.config_generation;
        profile.descriptor = Some(descriptor.clone());
        store.save(&profile).map_err(|error| error.to_string())?;
        store
            .mark_used(&profile.cluster_uuid)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            profile,
            descriptor,
            client,
        })
    }

    pub(crate) fn submission_config(&self) -> ClusterConfig {
        let controller = NodeId::new("controller").unwrap();
        let mut nodes = BTreeMap::from([(
            controller.to_string(),
            NodeConfig {
                host: self.profile.controller_host.clone(),
                transport: Transport::Local,
                remote_binary: self.profile.remote_binary.clone(),
                ssh_user: None,
                ssh_port: None,
                ssh_identity_file: None,
                remote_config: None,
                machine_uuid: None,
                execution_uid: Some(self.profile.remote_uid),
            },
        )]);
        let mut queues = BTreeMap::new();
        for queue in &self.descriptor.queues {
            for node in &queue.nodes {
                nodes.entry(node.to_string()).or_insert_with(|| NodeConfig {
                    host: node.to_string(),
                    transport: Transport::Ssh,
                    remote_binary: "macluster".into(),
                    ssh_user: None,
                    ssh_port: None,
                    ssh_identity_file: None,
                    remote_config: None,
                    machine_uuid: None,
                    execution_uid: None,
                });
            }
            queues.insert(
                queue.name.to_string(),
                QueueConfig {
                    nodes: queue.nodes.iter().map(ToString::to_string).collect(),
                    scheduler: SchedulerKind::Fifo,
                },
            );
        }
        let mut shares = BTreeMap::new();
        for share in &self.descriptor.shares {
            nodes
                .entry(share.server.to_string())
                .or_insert_with(|| NodeConfig {
                    host: share.server.to_string(),
                    transport: Transport::Ssh,
                    remote_binary: "macluster".into(),
                    ssh_user: None,
                    ssh_port: None,
                    ssh_identity_file: None,
                    remote_config: None,
                    machine_uuid: None,
                    execution_uid: None,
                });
            shares.insert(
                share.id.clone(),
                ShareConfig {
                    protocol: share
                        .protocol
                        .parse()
                        .unwrap_or(macluster_core::storage_uri::StorageProtocol::Nfs),
                    server: share.server.clone(),
                    source_root: PathBuf::from(&share.source_root),
                    mount_root: PathBuf::from(&share.mount_root),
                    share_uuid: share.share_uuid.clone(),
                    smb_user: share.smb_user.clone(),
                    allow_existing_contents: false,
                },
            );
        }
        let mut roles = BTreeMap::new();
        roles.insert(
            controller.to_string(),
            [macluster_core::config::NodeRole::Controller]
                .into_iter()
                .collect(),
        );
        for queue in queues.values() {
            for node in &queue.nodes {
                roles
                    .entry(node.clone())
                    .or_insert_with(std::collections::BTreeSet::new)
                    .insert(macluster_core::config::NodeRole::Compute);
            }
        }
        ClusterConfig {
            name: self.descriptor.cluster_name.clone(),
            login_node: Some(controller.clone()),
            default_queue: self.descriptor.default_queue.clone(),
            shared_root: PathBuf::from(&self.descriptor.primary_mount_root),
            storage_source_root: None,
            share_uuid: self.descriptor.cluster_uuid.clone(),
            storage_server: controller,
            protocol_version: PROTOCOL_VERSION,
            queues,
            nodes,
            shares,
            roles,
        }
    }
}

fn request_descriptor(client: &mut ControlClient) -> Result<ClientDescriptor, String> {
    let ControlPayload::ClientDescriptor(descriptor) = client
        .request(ControlCommand::ClientDescriptor)
        .map_err(|error| error.to_string())?
    else {
        return Err("Controller returned an invalid client descriptor".into());
    };
    Ok(descriptor)
}

fn remote_binary_for_descriptor(
    profile: &ClientProfile,
    descriptor: &ClientDescriptor,
) -> Option<String> {
    let candidate = descriptor.controller_binary.trim();
    let path = Path::new(candidate);
    (candidate != profile.remote_binary
        && path.is_absolute()
        && !candidate.chars().any(char::is_control)
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)))
    .then(|| candidate.to_owned())
}

fn needs_mount_reconciliation(
    mounts_enabled: bool,
    storage_command: bool,
    installed: Option<&ClientDescriptor>,
    current: &ClientDescriptor,
    client_ip: &str,
) -> bool {
    mounts_enabled
        && storage_command
        && installed.is_none_or(|installed| {
            !crate::client_storage::mount_layout_matches(installed, current, client_ip)
        })
}

fn storage_command_blocked_by_leave(profile: &ClientProfile, storage_command: bool) -> bool {
    storage_command && profile.leave_phase.is_some()
}

pub(crate) fn select_remote_profile(
    config_path: &Path,
    command: &str,
    args: &[String],
    explicit: Option<&str>,
    config_explicit: bool,
    local_controller_stopped: bool,
) -> Result<Option<ClientProfile>, String> {
    if !remote_command_supported(command)
        || args
            .iter()
            .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
    {
        return Ok(None);
    }
    // A local node-admin config is the recovery authority even while its
    // controller is stopped. Forwarding to a stale remote CLI would prevent
    // reset, mount, and node repair from running with the binary in hand.
    if command == "node"
        && explicit.is_none()
        && !config_explicit
        && config_path.exists()
        && !node_command_can_use_remote_profile(args)
    {
        return Ok(None);
    }
    if !should_consider_remote_profile(
        config_path.exists(),
        explicit,
        config_explicit,
        local_controller_stopped,
    ) {
        return Ok(None);
    }
    let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
    match store.select(explicit).map_err(|error| error.to_string())? {
        ClientSelection::Explicit(profile)
        | ClientSelection::LastUsed(profile)
        | ClientSelection::Sole(profile) => Ok(Some(profile)),
        ClientSelection::None => Ok(None),
    }
}

fn should_consider_remote_profile(
    config_exists: bool,
    explicit: Option<&str>,
    config_explicit: bool,
    local_controller_stopped: bool,
) -> bool {
    explicit.is_some() || !config_explicit && (!config_exists || local_controller_stopped)
}

fn node_command_can_use_remote_profile(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("-l" | "--list" | "--failed" | "-migrate")
    )
}

pub(crate) fn remote_command_supported(command: &str) -> bool {
    matches!(
        command,
        "submit" | "job" | "queue" | "kill" | "top" | "fans" | "node"
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use macluster_protocol::identifiers::Id128;

    use super::{
        needs_mount_reconciliation, node_command_can_use_remote_profile, remote_command_supported,
        select_remote_profile, should_consider_remote_profile,
    };

    #[test]
    fn remote_command_selection_is_limited_to_cluster_operations() {
        assert!(remote_command_supported("submit"));
        assert!(remote_command_supported("queue"));
        assert!(!remote_command_supported("init"));
        assert!(!remote_command_supported("internal"));
    }

    #[test]
    fn running_local_controller_precedes_client_profiles() {
        let root = std::env::temp_dir().join(format!("macluster-context-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "config").unwrap();
        assert!(
            select_remote_profile(&config, "queue", &[], None, false, false)
                .unwrap()
                .is_none()
        );
        assert!(
            select_remote_profile(&config, "queue", &[], None, true, true)
                .unwrap()
                .is_none()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stopped_local_controller_forwards_listing_and_migration_to_the_remote_profile() {
        for args in [
            vec!["-l"],
            vec!["--list"],
            vec!["--failed"],
            vec!["-migrate", "controller:login-01"],
        ] {
            let owned = args
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
            assert!(node_command_can_use_remote_profile(&owned), "{args:?}");
        }
        for args in [
            vec!["-a", "worker@192.0.2.20"],
            vec!["-rm", "worker"],
            vec!["-mount", "smb://nas/data"],
        ] {
            let owned = args
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
            assert!(!node_command_can_use_remote_profile(&owned), "{args:?}");
        }
    }

    #[test]
    fn stopped_local_controller_allows_the_joined_profile() {
        assert!(should_consider_remote_profile(true, None, false, true));
    }

    #[test]
    fn node_admin_with_local_config_uses_the_current_binary() {
        let root = std::env::temp_dir().join(format!("macluster-context-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "config").unwrap();

        let selected = select_remote_profile(
            &config,
            "node",
            &[
                "-mount".into(),
                "smb://192.0.2.5/data".into(),
                "--mount-root".into(),
                "/Volumes/test_data".into(),
            ],
            None,
            false,
            true,
        )
        .unwrap();

        assert!(
            selected.is_none(),
            "a valid local config must run node recovery with this binary"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_cluster_selection_overrides_a_local_controller_config() {
        assert!(should_consider_remote_profile(false, None, false, false));
        assert!(!should_consider_remote_profile(true, None, false, false));
        assert!(!should_consider_remote_profile(false, None, true, false));
        assert!(should_consider_remote_profile(
            true,
            Some("remote"),
            false,
            false
        ));
        assert!(should_consider_remote_profile(
            false,
            Some("remote"),
            true,
            false
        ));
    }

    #[test]
    fn read_only_remote_commands_never_trigger_mount_reconciliation() {
        let descriptor = macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 2,
            controller_build_id: "test".into(),
            controller_binary: String::new(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        };
        let mut older = descriptor.clone();
        older.config_generation = 1;
        assert!(!needs_mount_reconciliation(
            true,
            false,
            Some(&older),
            &descriptor,
            "192.0.2.10",
        ));
        assert!(!needs_mount_reconciliation(
            false,
            true,
            None,
            &descriptor,
            "192.0.2.10"
        ));
        assert!(needs_mount_reconciliation(
            true,
            true,
            None,
            &descriptor,
            "192.0.2.10"
        ));
        assert!(!needs_mount_reconciliation(
            true,
            true,
            Some(&older),
            &descriptor,
            "192.0.2.10",
        ));
    }

    #[test]
    fn storage_commands_must_wait_for_an_interrupted_leave_to_finish() {
        let mut profile = super::ClientProfile {
            version: crate::client_profile::CLIENT_PROFILE_VERSION,
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            binding_digest: "b".repeat(64),
            namespace: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            descriptor_generation: 1,
            controller_host: "192.0.2.1".into(),
            controller_user: "mac".into(),
            controller_port: 22,
            known_hosts_path: "/tmp/known_hosts".into(),
            identity_file: "/tmp/id_ed25519".into(),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config.toml".into(),
            remote_state_dir: "/tmp/state".into(),
            mounts_enabled: true,
            nfs_client_id: "client-test".into(),
            nfs_client_ip: "192.0.2.10".into(),
            last_used_unix_ms: 1,
            descriptor: None,
            mounted_descriptor: None,
            transition_mount_descriptors: vec![],
            retired_access: vec![],
            leave_phase: None,
        };
        assert!(!super::storage_command_blocked_by_leave(&profile, true));
        profile.leave_phase = Some(crate::client_profile::ClientLeavePhase::MountsDetached);
        assert!(super::storage_command_blocked_by_leave(&profile, true));
        assert!(!super::storage_command_blocked_by_leave(&profile, false));
    }

    #[test]
    fn configuration_generation_changes_do_not_remount_an_identical_layout() {
        let descriptor = macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 8,
            controller_build_id: "new-build".into(),
            controller_binary: String::new(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        };
        let mut installed = descriptor.clone();
        installed.config_generation = 7;
        installed.default_queue = "batch".parse().unwrap();
        installed.controller_build_id = "old-build".into();
        assert!(!needs_mount_reconciliation(
            true,
            true,
            Some(&installed),
            &descriptor,
            "192.0.2.10",
        ));
    }

    #[test]
    fn controller_binary_refreshes_a_joined_profile_after_a_build_change() {
        let descriptor = macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 2,
            controller_build_id: "new-build".into(),
            controller_binary: "/Users/mac/.local/share/macluster/clusters/test/bin/new/macluster"
                .into(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        };
        let profile = super::ClientProfile {
            version: crate::client_profile::CLIENT_PROFILE_VERSION,
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            binding_digest: "b".repeat(64),
            namespace: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            descriptor_generation: 1,
            controller_host: "192.0.2.1".into(),
            controller_user: "mac".into(),
            controller_port: 22,
            known_hosts_path: "/tmp/known_hosts".into(),
            identity_file: "/tmp/id_ed25519".into(),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config.toml".into(),
            remote_state_dir: "/tmp/state".into(),
            mounts_enabled: true,
            nfs_client_id: "client-test".into(),
            nfs_client_ip: "192.0.2.10".into(),
            last_used_unix_ms: 1,
            descriptor: None,
            mounted_descriptor: None,
            transition_mount_descriptors: vec![],
            retired_access: vec![],
            leave_phase: None,
        };

        assert_eq!(
            super::remote_binary_for_descriptor(&profile, &descriptor),
            Some(descriptor.controller_binary.clone())
        );
        let mut invalid = descriptor;
        invalid.controller_binary = "/tmp/../macluster".into();
        assert_eq!(
            super::remote_binary_for_descriptor(&profile, &invalid),
            None
        );
    }

    #[test]
    fn changing_a_mount_source_requires_reconciliation() {
        let descriptor = macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 8,
            controller_build_id: "same-build".into(),
            controller_binary: String::new(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster-v2".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        };
        let mut installed = descriptor.clone();
        installed.primary_source_root = "/Users/Shared/macluster".into();
        assert!(needs_mount_reconciliation(
            true,
            true,
            Some(&installed),
            &descriptor,
            "192.0.2.10",
        ));
    }
}
