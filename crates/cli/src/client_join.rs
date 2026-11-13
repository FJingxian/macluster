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
                || !matches!(share.protocol.as_str(), "nfs" | "smb")
                || !std::path::Path::new(&share.source_root).is_absolute()
                || !std::path::Path::new(&share.mount_root).is_absolute()
        })
    {
        return Err("Controller returned invalid client storage mappings".into());
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "cannot locate the client account HOME for SSH host pinning".to_owned())?;
    let endpoint_digest =
        sha256_hex(format!("{}\0{}\0{}", endpoint.user, endpoint.host, endpoint.port).as_bytes())
            .map_err(|error| error.to_string())?;
    let known_hosts_path = home
        .join(".ssh/macluster")
        .join(&bootstrap.descriptor.cluster_uuid)
        .join(format!("known_hosts-{}", &endpoint_digest[..16]));
    Ok(ClientProfile {
        version: crate::client_profile::CLIENT_PROFILE_VERSION,
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
        mounted_descriptor: None,
        transition_mount_descriptors: vec![],
        retired_access: vec![],
        leave_phase: None,
    })
}

pub fn join_cluster(endpoint: &str, control_only: bool) -> Result<ClientProfile, String> {
    join_cluster_expected(endpoint, control_only, None)
}

pub fn join_cluster_expected(
    endpoint: &str,
    control_only: bool,
    expected_cluster_uuid: Option<&str>,
) -> Result<ClientProfile, String> {
    join_cluster_expected_with_binary(
        endpoint,
        control_only,
        expected_cluster_uuid,
        None,
        false,
        false,
    )
}

pub(crate) fn join_cluster_expected_with_binary(
    endpoint: &str,
    control_only: bool,
    expected_cluster_uuid: Option<&str>,
    remote_binary_override: Option<&str>,
    preserve_existing_mounts: bool,
    adopt_existing_mounts: bool,
) -> Result<ClientProfile, String> {
    let endpoint = JoinEndpoint::parse(endpoint)?;
    let mut node = endpoint.node();
    if let Some(binary) = remote_binary_override {
        node.remote_binary = parse_remote_macluster_path(binary.as_bytes())?;
    }
    let access = ssh_bootstrap::ensure_ssh_access_with_receipt(
        &mut node,
        &format!("{}@{}:{}", endpoint.user, endpoint.host, endpoint.port),
    )?;
    let identity = node
        .ssh_identity_file
        .clone()
        .ok_or_else(|| "SSH bootstrap did not retain a client identity".to_owned())?;
    let public_key = access
        .public_key
        .clone()
        .map(String::into_bytes)
        .or_else(|| fs::read(format!("{identity}.pub")).ok())
        .ok_or_else(|| "cannot read the dedicated client public key".to_owned())?;
    let client_key_digest =
        sha256_hex(&public_key).map_err(|error| format!("cannot hash the client key: {error}"))?;
    let mut profile_persisted = false;
    let mut known_hosts_cleanup = None;
    let result = (|| {
        let remote_binary = match remote_binary_override {
            Some(binary) => parse_remote_macluster_path(binary.as_bytes())?,
            None => resolve_remote_macluster(&node)?,
        };
        node.remote_binary = remote_binary.clone();
        let bootstrap_command = format!(
            "{} internal client-bootstrap --json --client-key-digest {client_key_digest}",
            node_admin::shell_quote(&remote_binary)
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
        verify_expected_cluster_uuid(&bootstrap.descriptor.cluster_uuid, expected_cluster_uuid)?;
        let host_fingerprint = bootstrap.host_fingerprint.clone();
        let mut profile = profile_from_bootstrap(&endpoint, bootstrap, PathBuf::from(&identity))?;
        let known_hosts_path = PathBuf::from(&profile.known_hosts_path);
        if !known_hosts_path.exists() {
            known_hosts_cleanup = Some(known_hosts_path.clone());
        }
        ssh_bootstrap::pin_client_host_key(
            &endpoint.node(),
            &format!("macluster-{}", profile.cluster_uuid),
            &host_fingerprint,
            &known_hosts_path,
        )?;
        let store = ClientProfileStore::current().map_err(|error| error.to_string())?;
        let existing = match store.load(&profile.cluster_uuid) {
            Ok(existing) => Some(existing),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        profile.mounts_enabled = !control_only || adopt_existing_mounts;
        profile.retired_access = existing
            .as_ref()
            .map(|existing| existing.retired_access.clone())
            .unwrap_or_default();
        if let Some(existing) = existing.as_ref()
            && existing.identity_file != profile.identity_file
            && !profile
                .retired_access
                .iter()
                .any(|retired| retired.identity_file == existing.identity_file)
        {
            profile
                .retired_access
                .push(crate::client_profile::RetiredClientAccess::from_profile(
                    existing,
                ));
        }
        if control_only
            && !adopt_existing_mounts
            && let Some(existing) = existing.as_ref().filter(|value| {
                !value.nfs_client_id.is_empty()
                    && value.nfs_client_ip.parse::<std::net::Ipv4Addr>().is_ok()
            })
            && !profile.retired_access.iter().any(|retired| {
                retired.identity_file == existing.identity_file
                    && retired.nfs_client_id == existing.nfs_client_id
                    && retired.nfs_client_ip == existing.nfs_client_ip
            })
        {
            profile.retired_access.push(
                crate::client_profile::RetiredClientAccess::nfs_cleanup_from_profile(existing),
            );
        }
        let existing_mounts_active = existing.as_ref().is_some_and(existing_mounts_are_active);
        profile.mounted_descriptor = if adopt_existing_mounts {
            profile.descriptor.clone()
        } else {
            existing
                .as_ref()
                .filter(|_| existing_mounts_active)
                .and_then(|value| value.installed_mount_descriptor().cloned())
        };
        if adopt_existing_mounts {
            profile.transition_mount_descriptors = existing
                .as_ref()
                .map(|value| value.transition_mount_descriptors.clone())
                .unwrap_or_default();
        } else if control_only {
            profile.transition_mount_descriptors = existing
                .as_ref()
                .filter(|_| existing_mounts_active)
                .map(|value| {
                    crate::client_storage::distinct_mount_layouts(
                        value.mount_cleanup_descriptors(),
                        &value.nfs_client_ip,
                    )
                })
                .unwrap_or_default();
        } else {
            profile.transition_mount_descriptors = existing
                .as_ref()
                .filter(|_| existing_mounts_active)
                .map(|value| value.transition_mount_descriptors.clone())
                .unwrap_or_default();
        }
        // Persist the previous access and every interrupted mount layout before
        // mutating the host or discarding the old profile.
        store.save(&profile).map_err(|error| error.to_string())?;
        profile_persisted = true;
        if control_only
            && !preserve_existing_mounts
            && !adopt_existing_mounts
            && let Some(existing) = existing.as_ref()
        {
            for descriptor in crate::client_storage::distinct_mount_layouts(
                existing.mount_cleanup_descriptors(),
                &existing.nfs_client_ip,
            ) {
                crate::client_storage::remove_client_mounts(
                    &existing.cluster_uuid,
                    &descriptor,
                    &existing.nfs_client_ip,
                )?;
            }
            profile.mounted_descriptor = None;
            profile.transition_mount_descriptors.clear();
        }
        if !control_only {
            crate::remote_admin::authorize_client_nfs_access(&profile).map_err(|error| {
                format!(
                    "Controller access is ready, but login-client NFS authorization failed: {error}. Run `macluster --cluster {} --leave` to clean up, then retry `--join`.",
                    profile.cluster_uuid
                )
            })?;
            let client_id = profile.nfs_client_id.clone();
            if profile.supersede_nfs_cleanup_for(&client_id) {
                store.save(&profile).map_err(|error| error.to_string())?;
            }
            if let Some(descriptor) = profile.descriptor.as_ref() {
                let previous = profile.mounted_descriptor.clone();
                profile
                    .transition_mount_descriptors
                    .extend(previous.clone());
                profile
                    .transition_mount_descriptors
                    .push(descriptor.clone());
                // An explicit join is also a repair operation. Always run the
                // idempotent mount helper even when the cached layout matches,
                // because the helper or a mount may have disappeared.
                profile.mounted_descriptor = Some(descriptor.clone());
                store.save(&profile).map_err(|error| error.to_string())?;
                let result = if let Some(previous) = previous.as_ref() {
                    crate::client_storage::replace_client_mounts(
                        &profile.cluster_uuid,
                        previous,
                        descriptor,
                        &profile.nfs_client_ip,
                    )
                } else {
                    crate::client_storage::install_client_mounts(
                        &profile.cluster_uuid,
                        descriptor,
                        &profile.nfs_client_ip,
                    )
                };
                result.map_err(|error| {
                    format!(
                        "Controller access is ready, but client NFS mounts were not configured: {error}. If you only need remote control commands, rerun `macluster --join --control-only {}@{}:{}`.",
                        endpoint.user, endpoint.host, endpoint.port
                    )
                })?;
            }
        }
        resume_retired_access(&store, &mut profile, false)?;
        store.save(&profile).map_err(|error| error.to_string())?;
        if let Err(error) = store.mark_used(&profile.cluster_uuid) {
            eprintln!(
                "Client profile was saved, but its last-used time could not be updated: {error}"
            );
        }
        store
            .load(&profile.cluster_uuid)
            .map_err(|error| error.to_string())
    })();

    match result {
        Ok(profile) => Ok(profile),
        Err(error) => {
            let mut error = error;
            if join_key_cleanup_required(profile_persisted, access.key_installed) {
                let public_key = String::from_utf8_lossy(&public_key);
                match ssh_bootstrap::revoke_public_key(&node, &public_key) {
                    Ok(()) => {
                        let _ = fs::remove_file(&identity);
                        let _ = fs::remove_file(format!("{identity}.pub"));
                    }
                    Err(cleanup_error) => {
                        error.push_str(&format!(
                            "; the newly installed client key also could not be removed: {cleanup_error}"
                        ));
                    }
                }
            }
            if join_local_cleanup_required(profile_persisted)
                && let Some(path) = known_hosts_cleanup
            {
                let _ = fs::remove_file(&path);
                if let Some(parent) = path.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            Err(error)
        }
    }
}

fn join_key_cleanup_required(profile_persisted: bool, key_installed: bool) -> bool {
    key_installed && !profile_persisted
}

fn resolve_remote_macluster(node: &NodeConfig) -> Result<String, String> {
    let script = remote_macluster_search_script();
    let output = node_admin::ssh_output(node, script, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(format!(
            "cannot locate macluster on the login node: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_remote_macluster_path(&output.stdout)
}

fn remote_macluster_search_script() -> &'static str {
    r#"set -eu
for candidate in "$HOME/.local/bin/macluster" "$HOME/.macluster/bin/macluster" /usr/local/bin/macluster /opt/homebrew/bin/macluster; do
  if [ -x "$candidate" ]; then /usr/bin/printf '%s\n' "$candidate"; exit 0; fi
done
candidate=$(command -v macluster 2>/dev/null || true)
[ -n "$candidate" ] || { echo 'macluster is not installed on this login node' >&2; exit 127; }
/usr/bin/printf '%s\n' "$candidate"
"#
}

fn parse_remote_macluster_path(output: &[u8]) -> Result<String, String> {
    let path = String::from_utf8(output.to_vec())
        .map_err(|_| "login-node macluster path is not valid UTF-8".to_owned())?;
    let path = path.trim();
    let parsed = std::path::Path::new(path);
    if path.is_empty()
        || !parsed.is_absolute()
        || path.chars().any(char::is_control)
        || parsed
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("login-node macluster path is invalid".into());
    }
    Ok(path.to_owned())
}

fn verify_expected_cluster_uuid(actual: &str, expected: Option<&str>) -> Result<(), String> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "the discovered endpoint belongs to cluster {actual}, not the expected cluster {expected}"
        ))
    }
}

fn join_local_cleanup_required(profile_persisted: bool) -> bool {
    !profile_persisted
}

fn existing_mounts_are_active(profile: &ClientProfile) -> bool {
    profile.mounts_enabled
        && !profile.leave_has_completed(crate::client_profile::ClientLeavePhase::MountsDetached)
}

pub(crate) fn resume_retired_access(
    store: &ClientProfileStore,
    profile: &mut ClientProfile,
    require_complete: bool,
) -> Result<(), String> {
    let mut index = 0;
    while index < profile.retired_access.len() {
        let retired = profile.retired_access[index].clone();
        let mut changed = false;
        if retired.nfs_revocation_pending {
            match crate::remote_admin::revoke_client_nfs_access_target(
                profile,
                &retired.nfs_client_id,
                &retired.nfs_client_ip,
            ) {
                Ok(()) => {
                    profile.retired_access[index].nfs_revocation_pending = false;
                    changed = true;
                }
                Err(error) => eprintln!(
                    "Warning: a previous login-client NFS registration still needs cleanup: {error}"
                ),
            }
        }
        if profile.retired_access[index].key_revocation_pending {
            let identity_shared = store.load_all().map_or(true, |profiles| {
                profiles.iter().any(|other| {
                    other.cluster_uuid != profile.cluster_uuid
                        && other.identity_file == retired.identity_file
                })
            });
            if identity_shared {
                profile.retired_access[index].key_revocation_pending = false;
                changed = true;
            } else {
                let public_key = retired.public_key.clone().or_else(|| {
                    fs::read_to_string(format!("{}.pub", retired.identity_file))
                        .ok()
                        .map(|value| value.trim().to_owned())
                        .filter(|value| !value.is_empty())
                });
                match public_key {
                    Some(public_key) => {
                        let transport = if profile.controller_user == retired.controller_user {
                            profile.clone()
                        } else {
                            retired_transport_profile(profile, &retired)
                        };
                        match crate::remote_admin::revoke_retired_public_key_with_transport(
                            &transport,
                            &public_key,
                        ) {
                            Ok(()) => {
                                let _ = fs::remove_file(&retired.identity_file);
                                let _ = fs::remove_file(format!("{}.pub", retired.identity_file));
                                let _ = fs::remove_file(&retired.known_hosts_path);
                                if let Some(parent) =
                                    std::path::Path::new(&retired.known_hosts_path).parent()
                                {
                                    let _ = fs::remove_dir(parent);
                                }
                                profile.retired_access[index].key_revocation_pending = false;
                                changed = true;
                            }
                            Err(error) => eprintln!(
                                "Warning: a previous login-client SSH key still needs cleanup: {error}"
                            ),
                        }
                    }
                    None => eprintln!(
                        "Warning: a previous login-client SSH public key is unavailable; its remote authorization cannot be verified or revoked automatically"
                    ),
                }
            }
        }
        if profile.retired_access[index].control_master_close_pending {
            match crate::remote_admin::close_control_master_for(
                &profile.cluster_uuid,
                &retired.controller_user,
                &retired.controller_host,
                retired.controller_port,
                &retired.identity_file,
            ) {
                Ok(()) => {
                    profile.retired_access[index].control_master_close_pending = false;
                    changed = true;
                }
                Err(error) => eprintln!(
                    "Warning: a previous login-client SSH control connection still needs cleanup: {error}"
                ),
            }
        }
        if changed {
            store.save(profile).map_err(|error| error.to_string())?;
        }
        if profile.retired_access[index].has_pending_cleanup() {
            index += 1;
        } else {
            profile.retired_access.remove(index);
            store.save(profile).map_err(|error| error.to_string())?;
        }
    }
    if require_complete && profile.has_pending_retired_access() {
        return Err(
            "previous login-client access still needs cleanup; reconnect its endpoint or resolve the warning above, then rerun the command"
                .into(),
        );
    }
    Ok(())
}

fn retired_transport_profile(
    current: &ClientProfile,
    retired: &crate::client_profile::RetiredClientAccess,
) -> ClientProfile {
    let mut profile = current.clone();
    profile.controller_host = retired.controller_host.clone();
    profile.controller_user = retired.controller_user.clone();
    profile.controller_port = retired.controller_port;
    profile.known_hosts_path = retired.known_hosts_path.clone();
    profile.identity_file = retired.identity_file.clone();
    profile
}

#[cfg(test)]
mod tests {
    use super::{
        BootstrapResponse, JoinEndpoint, existing_mounts_are_active, join_key_cleanup_required,
        join_local_cleanup_required, parse_remote_macluster_path, profile_from_bootstrap,
        remote_macluster_search_script, verify_expected_cluster_uuid,
    };

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
    fn failed_join_revokes_only_a_key_installed_before_profile_persistence() {
        assert!(join_key_cleanup_required(false, true));
        assert!(!join_key_cleanup_required(true, true));
        assert!(!join_key_cleanup_required(false, false));
        assert!(join_local_cleanup_required(false));
        assert!(!join_local_cleanup_required(true));
    }

    #[test]
    fn host_pins_are_isolated_by_controller_endpoint() {
        let first_endpoint = JoinEndpoint::parse("mac@192.0.2.1:22").unwrap();
        let second_endpoint = JoinEndpoint::parse("mac@192.0.2.2:22").unwrap();
        let first = profile_from_bootstrap(
            &first_endpoint,
            BootstrapResponse {
                descriptor: descriptor(),
                binding_digest: "b".repeat(64),
                remote_uid: 501,
                remote_binary: "/opt/homebrew/bin/macluster".into(),
                remote_config: "/tmp/config".into(),
                remote_state_dir: "/tmp/state".into(),
                host_fingerprint: "SHA256:first".into(),
                nfs_client_id: "client-one".into(),
                nfs_client_ip: "192.0.2.10".into(),
            },
            "/tmp/key-one".into(),
        )
        .unwrap();
        let second = profile_from_bootstrap(
            &second_endpoint,
            BootstrapResponse {
                descriptor: descriptor(),
                binding_digest: "b".repeat(64),
                remote_uid: 501,
                remote_binary: "/opt/homebrew/bin/macluster".into(),
                remote_config: "/tmp/config".into(),
                remote_state_dir: "/tmp/state".into(),
                host_fingerprint: "SHA256:second".into(),
                nfs_client_id: "client-two".into(),
                nfs_client_ip: "192.0.2.11".into(),
            },
            "/tmp/key-two".into(),
        )
        .unwrap();
        assert_ne!(first.known_hosts_path, second.known_hosts_path);
    }

    #[test]
    fn an_interrupted_leave_cannot_make_rejoin_trust_stale_mounts() {
        let endpoint = JoinEndpoint::parse("mac@192.0.2.1").unwrap();
        let mut profile = profile_from_bootstrap(
            &endpoint,
            BootstrapResponse {
                descriptor: descriptor(),
                binding_digest: "b".repeat(64),
                remote_uid: 501,
                remote_binary: "/opt/homebrew/bin/macluster".into(),
                remote_config: "/tmp/config".into(),
                remote_state_dir: "/tmp/state".into(),
                host_fingerprint: "SHA256:test".into(),
                nfs_client_id: "client-test".into(),
                nfs_client_ip: "192.0.2.10".into(),
            },
            "/tmp/key".into(),
        )
        .unwrap();
        profile.mounts_enabled = true;
        assert!(existing_mounts_are_active(&profile));
        profile.leave_phase = Some(crate::client_profile::ClientLeavePhase::MountsDetached);
        assert!(!existing_mounts_are_active(&profile));
    }

    #[test]
    fn automatic_join_rejects_a_controller_from_another_cluster() {
        assert!(
            verify_expected_cluster_uuid(
                "f779bcf5-ea85-5caa-9579-74b395f3cce5",
                Some("f779bcf5-ea85-5caa-9579-74b395f3cce5")
            )
            .is_ok()
        );
        assert!(
            verify_expected_cluster_uuid(
                "f779bcf5-ea85-5caa-9579-74b395f3cce5",
                Some("82d02835-f6ab-52b4-aaab-f90cafde9981")
            )
            .is_err()
        );
    }

    #[test]
    fn login_node_binary_path_must_be_a_safe_absolute_path() {
        assert_eq!(
            parse_remote_macluster_path(b"/opt/homebrew/bin/macluster\n").unwrap(),
            "/opt/homebrew/bin/macluster"
        );
        assert!(parse_remote_macluster_path(b"macluster\n").is_err());
        assert!(parse_remote_macluster_path(b"/tmp/../macluster\n").is_err());
        assert!(parse_remote_macluster_path(b"/tmp/macluster\nmalicious\n").is_err());
    }

    #[test]
    fn login_node_binary_search_prefers_a_stable_user_install() {
        let script = remote_macluster_search_script();
        let local = script.find("\"$HOME/.local/bin/macluster\"").unwrap();
        let homebrew = script.find("/opt/homebrew/bin/macluster").unwrap();

        assert!(local < homebrew, "{script}");
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
