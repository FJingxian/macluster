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
        let timeout = Duration::from_secs(8);
        let mut client = ControlClient::connect_remote(&profile, timeout, ensure_client_storage)
            .map_err(|error| error.to_string())?;
        let mut descriptor = request_descriptor(&mut client)?;
        if profile.mounts_enabled {
            let mut installed = profile.descriptor.clone();
            for attempt in 0..3 {
                let mounts_changed = installed.as_ref().is_none_or(|previous| {
                    previous.config_generation != descriptor.config_generation
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
                // Do not leave an authenticated control stream idle while
                // administrator prompts can take minutes.
                drop(client);
                if let Some(previous) = installed.as_ref() {
                    crate::client_storage::replace_client_mounts(
                        &profile.cluster_uuid,
                        previous,
                        &descriptor,
                    )?;
                } else {
                    crate::client_storage::install_client_mounts(
                        &profile.cluster_uuid,
                        &descriptor,
                    )?;
                }
                installed = Some(descriptor.clone());
                client = ControlClient::connect_remote(&profile, timeout, ensure_client_storage)
                    .map_err(|error| error.to_string())?;
                descriptor = request_descriptor(&mut client)?;
            }
        }
        profile.descriptor_generation = descriptor.config_generation;
        profile.descriptor = Some(descriptor.clone());
        let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
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
                    server: share.server.clone(),
                    source_root: PathBuf::from(&share.source_root),
                    mount_root: PathBuf::from(&share.mount_root),
                    share_uuid: share.share_uuid.clone(),
                    allow_existing_contents: false,
                },
            );
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

pub(crate) fn select_remote_profile(
    config_path: &Path,
    command: &str,
    args: &[String],
    explicit: Option<&str>,
    config_explicit: bool,
) -> Result<Option<ClientProfile>, String> {
    if !remote_command_supported(command)
        || args
            .iter()
            .any(|argument| matches!(argument.as_str(), "-h" | "--help"))
        || !should_consider_remote_profile(config_path.exists(), explicit, config_explicit)
    {
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
) -> bool {
    explicit.is_some() || !config_explicit && !config_exists
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

    use super::{remote_command_supported, select_remote_profile, should_consider_remote_profile};

    #[test]
    fn remote_command_selection_is_limited_to_cluster_operations() {
        assert!(remote_command_supported("submit"));
        assert!(remote_command_supported("queue"));
        assert!(!remote_command_supported("init"));
        assert!(!remote_command_supported("internal"));
    }

    #[test]
    fn local_config_precedes_client_profiles() {
        let root = std::env::temp_dir().join(format!("macluster-context-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "config").unwrap();
        assert!(
            select_remote_profile(&config, "queue", &[], None, false)
                .unwrap()
                .is_none()
        );
        assert!(
            select_remote_profile(&config, "queue", &[], None, true)
                .unwrap()
                .is_none()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_cluster_selection_overrides_a_local_controller_config() {
        assert!(should_consider_remote_profile(false, None, false));
        assert!(!should_consider_remote_profile(true, None, false));
        assert!(!should_consider_remote_profile(false, None, true));
        assert!(should_consider_remote_profile(true, Some("remote"), false));
        assert!(should_consider_remote_profile(false, Some("remote"), true));
    }
}
