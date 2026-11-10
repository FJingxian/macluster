use std::path::PathBuf;

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::{control::ClientDescriptor, identifiers::Id128};
use serde::{Deserialize, Serialize};

use crate::{
    client_profile::{ClientProfile, ClientProfileStore},
    node_admin, ssh_bootstrap,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinEndpoint {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl JoinEndpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (user, address) = value
            .split_once('@')
            .ok_or_else(|| "join endpoint must be USER@HOST[:PORT]".to_owned())?;
        if user.is_empty()
            || user.len() > 64
            || !user.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                }
            })
        {
            return Err("join SSH user is invalid".into());
        }
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| "join SSH port is invalid".to_owned())?,
            ),
            _ => (address, 22),
        };
        if host.is_empty()
            || host.len() > 253
            || host.chars().any(char::is_whitespace)
            || host.chars().any(char::is_control)
        {
            return Err("join SSH host is invalid".into());
        }
        Ok(Self {
            user: user.into(),
            host: host.into(),
            port,
        })
    }

    fn node(&self) -> NodeConfig {
        NodeConfig {
            host: self.host.clone(),
            transport: Transport::Ssh,
            remote_binary: "macluster".into(),
            ssh_user: Some(self.user.clone()),
            ssh_port: Some(self.port),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: None,
            execution_uid: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootstrapResponse {
    pub descriptor: ClientDescriptor,
    pub remote_uid: u32,
    pub remote_binary: String,
    pub remote_config: String,
    pub remote_state_dir: String,
    pub host_fingerprint: String,
    pub known_hosts_path: String,
}

pub fn profile_from_bootstrap(
    endpoint: &JoinEndpoint,
    bootstrap: BootstrapResponse,
    identity_file: PathBuf,
) -> Result<ClientProfile, String> {
    Id128::parse(&bootstrap.descriptor.cluster_uuid)
        .map_err(|_| "Controller returned an invalid cluster UUID".to_owned())?;
    if !bootstrap
        .descriptor
        .capabilities
        .iter()
        .any(|capability| capability == macluster_protocol::control::MULTI_ENTRY_CLIENT_FEATURE)
    {
        return Err("Controller does not support multi-entry clients; update it first".into());
    }
    Ok(ClientProfile {
        version: 1,
        cluster_uuid: bootstrap.descriptor.cluster_uuid.to_ascii_lowercase(),
        cluster_name: bootstrap.descriptor.cluster_name,
        descriptor_generation: bootstrap.descriptor.config_generation,
        controller_host: endpoint.host.clone(),
        controller_user: endpoint.user.clone(),
        controller_port: endpoint.port,
        known_hosts_path: bootstrap.known_hosts_path,
        identity_file: identity_file.to_string_lossy().into_owned(),
        remote_uid: bootstrap.remote_uid,
        remote_binary: bootstrap.remote_binary,
        remote_config: bootstrap.remote_config,
        remote_state_dir: bootstrap.remote_state_dir,
        last_used_unix_ms: 0,
    })
}

pub fn join_cluster(endpoint: &str, _control_only: bool) -> Result<ClientProfile, String> {
    let endpoint = JoinEndpoint::parse(endpoint)?;
    let mut node = endpoint.node();
    ssh_bootstrap::ensure_ssh_access(
        &mut node,
        &format!("{}@{}:{}", endpoint.user, endpoint.host, endpoint.port),
    )?;
    let output = node_admin::ssh_output(&node, "macluster internal client-bootstrap --json", None)
        .map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(format!(
            "Controller bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let bootstrap: BootstrapResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Controller bootstrap returned invalid JSON: {error}"))?;
    let identity = node
        .ssh_identity_file
        .as_deref()
        .ok_or_else(|| "SSH bootstrap did not retain a client identity".to_owned())?;
    let profile = profile_from_bootstrap(&endpoint, bootstrap, PathBuf::from(identity))?;
    let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
    store.save(&profile).map_err(|error| error.to_string())?;
    store
        .mark_used(&profile.cluster_uuid)
        .map_err(|error| error.to_string())?;
    store
        .load(&profile.cluster_uuid)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{BootstrapResponse, JoinEndpoint, profile_from_bootstrap};

    fn descriptor() -> macluster_protocol::control::ClientDescriptor {
        macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            config_generation: 7,
            controller_build_id: "macluster/0.1.8".into(),
            controller_uid: 501,
            capabilities: vec![macluster_protocol::control::MULTI_ENTRY_CLIENT_FEATURE.into()],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            shares: vec![],
            queues: vec![],
        }
    }

    #[test]
    fn parses_host_port_and_rejects_missing_user() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1:2222").unwrap();
        assert_eq!(endpoint.user, "mac");
        assert_eq!(endpoint.host, "192.0.2.1");
        assert_eq!(endpoint.port, 2222);
        assert!(JoinEndpoint::parse("192.0.2.1").is_err());
    }

    #[test]
    fn join_rejects_old_controller_without_multi_entry_feature() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let mut descriptor = descriptor();
        descriptor.capabilities.clear();
        let bootstrap = BootstrapResponse {
            descriptor,
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            known_hosts_path: "/tmp/known_hosts".into(),
        };
        assert!(profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).is_err());
    }

    #[test]
    fn join_stores_profile_only_after_descriptor_validation() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            known_hosts_path: "/tmp/known_hosts".into(),
        };
        let profile = profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).unwrap();
        assert_eq!(profile.cluster_name, "home");
        assert_eq!(profile.controller_user, "mac");
    }
}
