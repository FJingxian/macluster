use std::{fs, path::PathBuf};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::{control::ClientDescriptor, framing::sha256_hex, identifiers::Id128};
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
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
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
    pub binding_digest: String,
    pub remote_uid: u32,
    pub remote_binary: String,
    pub remote_config: String,
    pub remote_state_dir: String,
    pub host_fingerprint: String,
    pub nfs_client_id: String,
    pub nfs_client_ip: String,
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
    if bootstrap.nfs_client_id.is_empty()
        || bootstrap.nfs_client_id.len() > 64
        || !bootstrap
            .nfs_client_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !bootstrap
            .nfs_client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || bootstrap
            .nfs_client_ip
            .parse::<std::net::Ipv4Addr>()
            .is_err()
        || !bootstrap.host_fingerprint.starts_with("SHA256:")
        || bootstrap.host_fingerprint.chars().any(char::is_control)
    {
        return Err("Controller returned an invalid client network identity".into());
    }
    if bootstrap.descriptor.primary_source_host.is_empty()
        || !std::path::Path::new(&bootstrap.descriptor.primary_source_root).is_absolute()
        || !std::path::Path::new(&bootstrap.descriptor.primary_mount_root).is_absolute()
        || bootstrap.descriptor.shares.iter().any(|share| {
            share.server_host.is_empty()
                || !std::path::Path::new(&share.source_root).is_absolute()
                || !std::path::Path::new(&share.mount_root).is_absolute()
        })
    {
        return Err("Controller returned invalid client storage mappings".into());
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "cannot locate the client account HOME for SSH host pinning".to_owned())?;
    let known_hosts_path = home
        .join(".ssh/macluster")
        .join(&bootstrap.descriptor.cluster_uuid)
        .join("known_hosts");
    Ok(ClientProfile {
        version: 1,
        cluster_uuid: bootstrap.descriptor.cluster_uuid.to_ascii_lowercase(),
        cluster_name: bootstrap.descriptor.cluster_name.clone(),
        binding_digest: bootstrap.binding_digest,
        namespace: bootstrap.descriptor.cluster_uuid.clone(),
        descriptor_generation: bootstrap.descriptor.config_generation,
        controller_host: endpoint.host.clone(),
        controller_user: endpoint.user.clone(),
        controller_port: endpoint.port,
        known_hosts_path: known_hosts_path.to_string_lossy().into_owned(),
        identity_file: identity_file.to_string_lossy().into_owned(),
        remote_uid: bootstrap.remote_uid,
        remote_binary: bootstrap.remote_binary,
        remote_config: bootstrap.remote_config,
        remote_state_dir: bootstrap.remote_state_dir,
        mounts_enabled: false,
        nfs_client_id: bootstrap.nfs_client_id,
        nfs_client_ip: bootstrap.nfs_client_ip,
        last_used_unix_ms: 0,
        descriptor: Some(bootstrap.descriptor),
    })
}

pub fn join_cluster(endpoint: &str, control_only: bool) -> Result<ClientProfile, String> {
    let endpoint = JoinEndpoint::parse(endpoint)?;
    let mut node = endpoint.node();
    ssh_bootstrap::ensure_ssh_access(
        &mut node,
        &format!("{}@{}:{}", endpoint.user, endpoint.host, endpoint.port),
    )?;
    let identity = node
        .ssh_identity_file
        .as_deref()
        .ok_or_else(|| "SSH bootstrap did not retain a client identity".to_owned())?;
    let public_key = fs::read(format!("{identity}.pub"))
        .map_err(|error| format!("cannot read the dedicated client public key: {error}"))?;
    let client_key_digest =
        sha256_hex(&public_key).map_err(|error| format!("cannot hash the client key: {error}"))?;
    let bootstrap_command = format!(
        "macluster internal client-bootstrap --json{} --client-key-digest {client_key_digest}",
        if control_only { " --control-only" } else { "" }
    );
    let output =
        node_admin::ssh_output(&node, &bootstrap_command, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(format!(
            "Controller bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let bootstrap: BootstrapResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Controller bootstrap returned invalid JSON: {error}"))?;
    let host_fingerprint = bootstrap.host_fingerprint.clone();
    let mut profile = profile_from_bootstrap(&endpoint, bootstrap, PathBuf::from(identity))?;
    ssh_bootstrap::pin_client_host_key(
        &endpoint.node(),
        &format!("macluster-{}", profile.cluster_uuid),
        &host_fingerprint,
        std::path::Path::new(&profile.known_hosts_path),
    )?;
    let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
    let existing = match store.load(&profile.cluster_uuid) {
        Ok(existing) => Some(existing),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    if control_only && let Some(existing) = existing.as_ref().filter(|value| value.mounts_enabled) {
        if let Some(descriptor) = existing.descriptor.as_ref() {
            crate::client_storage::remove_client_mounts(&existing.cluster_uuid, descriptor)?;
        }
        crate::remote_admin::revoke_client_nfs_access(existing)?;
    }
    if !control_only {
        if let Some(descriptor) = profile.descriptor.as_ref() {
            let result = if let Some(previous) = existing
                .as_ref()
                .filter(|value| value.mounts_enabled)
                .and_then(|value| value.descriptor.as_ref())
            {
                crate::client_storage::replace_client_mounts(
                    &profile.cluster_uuid,
                    previous,
                    descriptor,
                )
            } else {
                crate::client_storage::install_client_mounts(&profile.cluster_uuid, descriptor)
            };
            result.map_err(|error| {
                format!(
                    "Controller access is ready, but client NFS mounts were not configured: {error}. If you only need remote control commands, rerun `macluster --join --control-only {}@{}:{}`.",
                    endpoint.user, endpoint.host, endpoint.port
                )
            })?;
        }
        profile.mounts_enabled = true;
    }
    store.save(&profile).map_err(|error| error.to_string())?;
    store
        .mark_used(&profile.cluster_uuid)
        .map_err(|error| error.to_string())?;
    let profile = store
        .load(&profile.cluster_uuid)
        .map_err(|error| error.to_string())?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::{BootstrapResponse, JoinEndpoint, profile_from_bootstrap};

    fn descriptor() -> macluster_protocol::control::ClientDescriptor {
        macluster_protocol::control::ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            default_queue: "default".parse().unwrap(),
            config_generation: 7,
            controller_build_id: "macluster/0.2.0".into(),
            controller_uid: 501,
            capabilities: vec![macluster_protocol::control::MULTI_ENTRY_CLIENT_FEATURE.into()],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
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
        assert!(JoinEndpoint::parse("mac@-oProxyCommand=bad").is_err());
        assert!(JoinEndpoint::parse("mac@[2001:db8::1]:22").is_err());
    }

    #[test]
    fn join_rejects_old_controller_without_multi_entry_feature() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let mut descriptor = descriptor();
        descriptor.capabilities.clear();
        let bootstrap = BootstrapResponse {
            descriptor,
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
        };
        assert!(profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).is_err());
    }

    #[test]
    fn join_stores_profile_only_after_descriptor_validation() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
        };
        let profile = profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).unwrap();
        assert_eq!(profile.cluster_name, "home");
        assert_eq!(profile.controller_user, "mac");
    }

    #[test]
    fn join_profile_uses_a_client_local_host_pin_path() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
        };
        let profile = profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).unwrap();
        assert_ne!(profile.known_hosts_path, "/tmp/known_hosts");
        assert!(profile.known_hosts_path.contains(&profile.cluster_uuid));
    }

    #[test]
    fn join_rejects_invalid_nfs_client_identity() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let mut bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
        };
        bootstrap.nfs_client_id = "bad\nclient".into();
        assert!(profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).is_err());

        let bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "not-an-ip".into(),
        };
        assert!(profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).is_err());

        let mut bootstrap = BootstrapResponse {
            descriptor: descriptor(),
            binding_digest: "b".repeat(64),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config".into(),
            remote_state_dir: "/tmp/state".into(),
            host_fingerprint: "SHA256:test".into(),
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
        };
        bootstrap.descriptor.primary_source_host.clear();
        assert!(profile_from_bootstrap(&endpoint, bootstrap, "/tmp/key".into()).is_err());
    }
}
