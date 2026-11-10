use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use macluster_core::config::{ClusterConfig, ShareConfig};
use macluster_protocol::identifiers::Id128;

use crate::node_admin::{NfsExportRequest, ensure_nfs_exports, remove_managed_nfs_exports};

pub(crate) fn current_ssh_client_ipv4() -> Result<String, String> {
    for key in ["SSH_CONNECTION", "SSH_CLIENT"] {
        if let Some(value) = env::var_os(key)
            && let Ok(ip) = parse_ssh_client_ipv4(value.to_string_lossy().as_ref())
        {
            return Ok(ip);
        }
    }
    Err("cannot determine the remote login client's IPv4 address from the SSH session".into())
}

fn parse_ssh_client_ipv4(value: &str) -> Result<String, String> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let ip = fields
        .first()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| "SSH client address is not an IPv4 address".to_owned())?;
    if ip.is_unspecified() || ip.is_loopback() {
        return Err("SSH client address must be a usable cluster IPv4 address".into());
    }
    Ok(ip.to_string())
}

fn client_requests(
    config: &ClusterConfig,
    client_id: &str,
    client_ip: &str,
) -> Result<BTreeMap<String, Vec<NfsExportRequest>>, String> {
    validate_client_id(client_id)?;
    validate_client_ip(client_ip)?;

    let mut grouped = BTreeMap::new();
    grouped
        .entry(config.storage_server.to_string())
        .or_insert_with(Vec::new)
        .push(NfsExportRequest {
            root: config.primary_source_root().to_string_lossy().into_owned(),
            client_ip: client_ip.to_owned(),
            share_uuid: config.share_uuid.to_ascii_lowercase(),
            node_id: client_id.to_owned(),
        });
    for share in config.shares.values() {
        grouped
            .entry(share.server.to_string())
            .or_insert_with(Vec::new)
            .push(NfsExportRequest {
                root: share.source_root.to_string_lossy().into_owned(),
                client_ip: client_ip.to_owned(),
                share_uuid: share.share_uuid.to_ascii_lowercase(),
                node_id: client_id.to_owned(),
            });
    }
    Ok(grouped)
}

fn validate_client_id(client_id: &str) -> Result<(), String> {
    if client_id.is_empty()
        || client_id.len() > 64
        || !client_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("client NFS identity is invalid".into());
    }
    Ok(())
}

fn validate_client_ip(client_ip: &str) -> Result<(), String> {
    client_ip
        .parse::<Ipv4Addr>()
        .map(|_| ())
        .map_err(|_| "client NFS address is not an IPv4 address".to_owned())
}

pub(crate) fn authorize_client(
    config: &ClusterConfig,
    client_id: &str,
    client_ip: &str,
) -> Result<(), String> {
    for (server_id, requests) in client_requests(config, client_id, client_ip)? {
        let server = config
            .nodes
            .get(&server_id)
            .ok_or_else(|| format!("NFS storage server '{server_id}' is not configured"))?;
        let (_, result) = ensure_nfs_exports(server, &requests, &Id128::random().to_string());
        result.map_err(|error| {
            format!(
                "could not authorize login client {client_ip} for {server_id} NFS storage: {error}"
            )
        })?;
    }
    Ok(())
}

pub(crate) fn revoke_client(
    config: &ClusterConfig,
    client_id: &str,
    client_ip: &str,
) -> Result<(), String> {
    for (server_id, requests) in client_requests(config, client_id, client_ip)? {
        let server = config
            .nodes
            .get(&server_id)
            .ok_or_else(|| format!("NFS storage server '{server_id}' is not configured"))?;
        remove_managed_nfs_exports(server, &requests, &Id128::random().to_string()).map_err(
            |error| {
                format!(
                    "could not revoke login client {client_ip} from {server_id} NFS storage: {error}"
                )
            },
        )?;
    }
    Ok(())
}

fn client_network_root(state_dir: &Path) -> PathBuf {
    state_dir.join("client-networks")
}

fn client_network_path(state_dir: &Path, client_id: &str) -> Result<PathBuf, String> {
    validate_client_id(client_id)?;
    Ok(client_network_root(state_dir).join(format!("{client_id}.ip")))
}

fn read_registered_address(state_dir: &Path, client_id: &str) -> Result<Option<String>, String> {
    let path = client_network_path(state_dir, client_id)?;
    match fs::read_to_string(&path) {
        Ok(value) => {
            let value = value.trim().to_owned();
            validate_client_ip(&value)?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot read login-client network registration {}: {error}",
            path.display()
        )),
    }
}

fn write_registered_address(
    state_dir: &Path,
    client_id: &str,
    client_ip: &str,
) -> Result<(), String> {
    validate_client_ip(client_ip)?;
    let root = client_network_root(state_dir);
    fs::create_dir_all(&root).map_err(|error| {
        format!(
            "cannot create login-client network registry {}: {error}",
            root.display()
        )
    })?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| format!("cannot inspect login-client registry: {error}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("login-client network registry is unsafe".into());
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot secure login-client registry: {error}"))?;
    let path = client_network_path(state_dir, client_id)?;
    let temporary = root.join(format!(".{client_id}-{}", Id128::random()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("cannot create login-client registration: {error}"))?;
        writeln!(file, "{client_ip}")
            .map_err(|error| format!("cannot write login-client registration: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot save login-client registration: {error}"))?;
        fs::rename(&temporary, &path)
            .map_err(|error| format!("cannot install login-client registration: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(crate) fn registered_client_share_requests(
    state_dir: &Path,
    share: &ShareConfig,
) -> Result<Vec<NfsExportRequest>, String> {
    let root = client_network_root(state_dir);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "cannot inspect login-client network registry {}: {error}",
                root.display()
            ));
        }
    };
    let mut requests = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("cannot inspect login-client registry: {error}"))?
            .path();
        if path.extension().and_then(|value| value.to_str()) != Some("ip") {
            continue;
        }
        let client_id = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "login-client registry has a non-UTF-8 identity".to_owned())?;
        let client_ip = read_registered_address(state_dir, client_id)?
            .ok_or_else(|| format!("login-client registry entry {} disappeared", path.display()))?;
        requests.push(NfsExportRequest {
            root: share.source_root.to_string_lossy().into_owned(),
            client_ip,
            share_uuid: share.share_uuid.to_ascii_lowercase(),
            node_id: client_id.to_owned(),
        });
    }
    requests.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(requests)
}

pub(crate) fn authorize_registered_client(
    config: &ClusterConfig,
    state_dir: &Path,
    client_id: &str,
    current_ip: &str,
) -> Result<(), String> {
    if let Some(previous_ip) = read_registered_address(state_dir, client_id)?
        && previous_ip != current_ip
    {
        revoke_client(config, client_id, &previous_ip)?;
    }
    authorize_client(config, client_id, current_ip)?;
    write_registered_address(state_dir, client_id, current_ip)
}

pub(crate) fn replace_registered_client_address(
    config: &ClusterConfig,
    state_dir: &Path,
    client_id: &str,
    fallback_previous_ip: &str,
    current_ip: &str,
) -> Result<(), String> {
    let registered = read_registered_address(state_dir, client_id)?;
    let previous = registered.as_deref().unwrap_or(fallback_previous_ip);
    if !previous.is_empty() && previous != current_ip {
        revoke_client(config, client_id, previous)?;
    }
    authorize_client(config, client_id, current_ip)?;
    write_registered_address(state_dir, client_id, current_ip)
}

pub(crate) fn revoke_client_at_current_address(
    config: &ClusterConfig,
    state_dir: &Path,
    client_id: &str,
    recorded_ip: &str,
) -> Result<(), String> {
    let registered_ip = read_registered_address(state_dir, client_id)?;
    let current_ip = current_ssh_client_ipv4().ok();
    let mut addresses = vec![recorded_ip.to_owned()];
    if let Some(ip) = registered_ip {
        addresses.push(ip);
    }
    if let Some(ip) = current_ip {
        addresses.push(ip);
    }
    addresses.sort();
    addresses.dedup();
    for address in addresses.into_iter().filter(|address| !address.is_empty()) {
        revoke_client(config, client_id, &address)?;
    }
    let path = client_network_path(state_dir, client_id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove login-client network registration: {error}"
        )),
    }
}

pub(crate) fn revoke_all_registered_clients(
    config: &ClusterConfig,
    state_dir: &Path,
) -> Result<usize, String> {
    let root = client_network_root(state_dir);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(format!(
                "cannot inspect login-client network registry {}: {error}",
                root.display()
            ));
        }
    };
    let mut revoked = 0;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot inspect login-client registry {}: {error}",
                root.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("ip") {
            continue;
        }
        let client_id = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "login-client registry has a non-UTF-8 identity".to_owned())?;
        let client_ip = read_registered_address(state_dir, client_id)?
            .ok_or_else(|| format!("login-client registry entry {} disappeared", path.display()))?;
        revoke_client(config, client_id, &client_ip)?;
        fs::remove_file(&path).map_err(|error| {
            format!(
                "cannot remove login-client registry entry {}: {error}",
                path.display()
            )
        })?;
        revoked += 1;
    }
    Ok(revoked)
}

pub(crate) fn forget_registered_client(state_dir: &Path, client_id: &str) -> Result<(), String> {
    let path = client_network_path(state_dir, client_id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove login-client network registration: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use macluster_core::config::ClusterConfig;
    use macluster_protocol::identifiers::Id128;

    use super::{
        client_requests, forget_registered_client, parse_ssh_client_ipv4, read_registered_address,
        registered_client_share_requests, write_registered_address,
    };

    #[test]
    fn ssh_connection_uses_only_a_usable_ipv4_client_address() {
        assert_eq!(
            parse_ssh_client_ipv4("192.0.2.10 51000 192.0.2.1 22").unwrap(),
            "192.0.2.10"
        );
        assert!(parse_ssh_client_ipv4("2001:db8::10").is_err());
        assert!(parse_ssh_client_ipv4("127.0.0.1 51000 127.0.0.1 22").is_err());
    }

    #[test]
    fn client_requests_cover_primary_and_every_named_share() {
        let config = ClusterConfig::parse(
            r#"
[cluster]
name = "client-access"
login_node = "login"
default_queue = "compute"
shared_root = "/Users/Shared/macluster"
share_uuid = "f779bcf5-ea85-5caa-9579-74b395f3cce5"
storage_server = "login"
protocol_version = 1

[queues.compute]
nodes = ["worker"]
scheduler = "fifo"

[nodes.login]
host = "192.0.2.1"
transport = "local"
machine_uuid = "4c0f4722-1130-50cf-ae36-55ff1abb5146"
execution_uid = 501

[nodes.worker]
host = "192.0.2.2"
transport = "ssh"

[shares.tools]
server = "login"
source_root = "/Users/Shared/tools"
mount_root = "/Users/Shared/tools"
share_uuid = "82d02835-f6ab-52b4-aaab-f90cafde9981"
"#,
        )
        .unwrap();
        let grouped = client_requests(&config, "client-test", "192.0.2.10").unwrap();
        let requests = grouped.get("login").unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.client_ip == "192.0.2.10")
        );
        assert!(requests.iter().any(|request| {
            request.root == "/Users/Shared/macluster"
                && request.share_uuid == "f779bcf5-ea85-5caa-9579-74b395f3cce5"
        }));
        assert!(requests.iter().any(|request| {
            request.root == "/Users/Shared/tools"
                && request.share_uuid == "82d02835-f6ab-52b4-aaab-f90cafde9981"
        }));
    }

    #[test]
    fn client_network_registration_persists_the_current_address_privately() {
        let state =
            std::env::temp_dir().join(format!("macluster-client-network-{}", Id128::random()));
        write_registered_address(&state, "client-test", "192.0.2.10").unwrap();
        assert_eq!(
            read_registered_address(&state, "client-test")
                .unwrap()
                .as_deref(),
            Some("192.0.2.10")
        );
        let path = state.join("client-networks/client-test.ip");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        forget_registered_client(&state, "client-test").unwrap();
        assert_eq!(
            read_registered_address(&state, "client-test").unwrap(),
            None
        );
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn registered_clients_are_included_in_share_export_cleanup() {
        let state =
            std::env::temp_dir().join(format!("macluster-client-share-{}", Id128::random()));
        write_registered_address(&state, "client-test", "192.0.2.10").unwrap();
        let config = ClusterConfig::parse(
            r#"
[cluster]
name = "client-share"
login_node = "login"
default_queue = "compute"
shared_root = "/Users/Shared/macluster"
share_uuid = "f779bcf5-ea85-5caa-9579-74b395f3cce5"
storage_server = "login"
protocol_version = 1

[queues.compute]
nodes = []
scheduler = "fifo"

[nodes.login]
host = "192.0.2.1"
transport = "local"
machine_uuid = "4c0f4722-1130-50cf-ae36-55ff1abb5146"
execution_uid = 501

[shares.tools]
server = "login"
source_root = "/Users/Shared/tools"
mount_root = "/Users/Shared/tools"
share_uuid = "82d02835-f6ab-52b4-aaab-f90cafde9981"
"#,
        )
        .unwrap();
        let requests = registered_client_share_requests(&state, &config.shares["tools"]).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].node_id, "client-test");
        assert_eq!(requests[0].client_ip, "192.0.2.10");
        std::fs::remove_dir_all(state).unwrap();
    }
}
