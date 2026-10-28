//! Shared, private OpenSSH ControlMaster socket naming.

use std::{
    env, fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::framing::sha256_hex;
use thiserror::Error;

const SOCKET_PATH_LIMIT: usize = 100;
const CONTROL_PERSIST: &str = "10";
const CONTROL_PATH_TOKEN_LEN: usize = "%C".len();
const OPENSSH_CONTROL_HASH_LEN: usize = 40;
const OPENSSH_CONTROL_SUFFIX_LEN: usize = 17;
const SOCKET_PATH_NUL_LEN: usize = 1;
const CONTROL_PATH_EXPANSION_LEN: usize = OPENSSH_CONTROL_HASH_LEN - CONTROL_PATH_TOKEN_LEN
    + OPENSSH_CONTROL_SUFFIX_LEN
    + SOCKET_PATH_NUL_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionKey {
    namespace: String,
    node_id: String,
    node_uuid: String,
    host: String,
    user: String,
    port: u16,
    identity_digest: String,
    host_key_policy_digest: String,
}

impl ConnectionKey {
    pub fn for_node(
        namespace: &str,
        node_id: &str,
        node: &NodeConfig,
    ) -> Result<Self, SshPoolError> {
        if node.transport != Transport::Ssh {
            return Err(SshPoolError::LocalNode);
        }
        let host = node.host.clone();
        let user = node.ssh_user.clone().unwrap_or_default();
        let port = node.ssh_port.unwrap_or(22);
        let node_uuid = node
            .machine_uuid
            .clone()
            .filter(|uuid| !uuid.is_empty())
            .unwrap_or_else(|| node_id.to_owned());
        let identity_digest = digest_identity(node)?;
        let host_key_policy_digest = digest_host_key_policy(node)?;
        Ok(Self {
            namespace: namespace.to_owned(),
            node_id: node_id.to_owned(),
            node_uuid,
            host,
            user,
            port,
            identity_digest,
            host_key_policy_digest,
        })
    }

    pub fn cache_fingerprint(&self) -> Result<String, SshPoolError> {
        digest_fields([
            self.namespace.as_str(),
            self.node_id.as_str(),
            self.node_uuid.as_str(),
            self.host.as_str(),
            self.user.as_str(),
            &self.port.to_string(),
            self.identity_digest.as_str(),
            self.host_key_policy_digest.as_str(),
        ])
    }
}

/// An OpenSSH ControlMaster directory scoped to one local cluster binding.
/// The SSH process remains the owner of each short-lived master; this pool only
/// ensures that separately spawned CLI/controller SSH clients select the same
/// socket when every authentication and host-trust input matches.
#[derive(Clone, Debug)]
pub struct SshPool {
    namespace: String,
}

impl SshPool {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn append_args(
        &self,
        key: &ConnectionKey,
        command: &mut Command,
    ) -> Result<(), SshPoolError> {
        if key.namespace != self.namespace {
            return Err(SshPoolError::NamespaceMismatch);
        }
        let namespace_hash = digest_fields([self.namespace.as_str()])?;
        let root = PathBuf::from(format!(
            "/tmp/mc-{}-{}",
            unsafe { libc::geteuid() },
            &namespace_hash[..8]
        ));
        ensure_private_directory(&root)?;

        let connection_hash = key.cache_fingerprint()?;
        let control_path = root.join(format!("{}-%C", &connection_hash[..16]));
        // OpenSSH expands %C to a 40-byte digest and may append a dot plus a
        // 16-byte suffix to the listener path on macOS. Include the NUL byte
        // and keep the resolved path below sockaddr_un's limit.
        if control_path
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .saturating_add(CONTROL_PATH_EXPANSION_LEN)
            >= SOCKET_PATH_LIMIT
        {
            return Err(SshPoolError::SocketPathTooLong);
        }
        command
            .arg("-oControlMaster=auto")
            .arg(format!("-oControlPersist={CONTROL_PERSIST}"))
            .arg(format!("-oControlPath={}", control_path.display()));
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SshPoolError {
    #[error("SSH connection reuse was requested for a local node")]
    LocalNode,
    #[error("SSH connection key belongs to a different cluster namespace")]
    NamespaceMismatch,
    #[error("SSH ControlPath exceeds the macOS Unix socket path limit")]
    SocketPathTooLong,
    #[error("cannot create a private SSH control directory: {0}")]
    Io(#[from] io::Error),
    #[error("could not fingerprint SSH connection policy: {0}")]
    Fingerprint(String),
}

fn ensure_private_directory(path: &Path) -> Result<(), SshPoolError> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSH control path is not a real directory",
        )
        .into());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSH control directory belongs to a different user",
        )
        .into());
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn digest_identity(node: &NodeConfig) -> Result<String, SshPoolError> {
    let mut values = vec!["ssh-identity-v1".to_owned()];
    if let Some(path) = node.ssh_identity_file.as_deref() {
        values.push(format!("configured:{}", file_fingerprint(Path::new(path))));
    }
    let home = env::var_os("HOME").map(PathBuf::from);
    if node.ssh_identity_file.is_none() {
        if let Some(home) = &home {
            for name in ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"] {
                let path = home.join(".ssh").join(name);
                values.push(format!("default:{}", file_fingerprint(&path)));
            }
        }
    }
    if let Some(home) = &home {
        values.push(format!(
            "ssh-config:{}",
            file_fingerprint(&home.join(".ssh/config"))
        ));
    }
    let agent = env::var("SSH_AUTH_SOCK").unwrap_or_default();
    values.push(format!("agent:{agent}"));
    if !agent.is_empty() {
        values.push(file_fingerprint(Path::new(&agent)));
    }
    digest_owned_fields(values)
}

fn digest_host_key_policy(node: &NodeConfig) -> Result<String, SshPoolError> {
    let mut values = vec!["strict-host-key-checking=yes".to_owned()];
    if let Some((path, alias)) = node.ssh_host_key_pin() {
        values.push(format!("pin-alias:{alias}"));
        values.push(format!("pin-file:{}", file_fingerprint(&path)));
        values.push(format!(
            "pin-address:{}",
            file_fingerprint(&path.with_extension("address"))
        ));
    } else if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        values.push(format!(
            "user-ssh-config:{}",
            file_fingerprint(&home.join(".ssh/config"))
        ));
        values.push(format!(
            "known-hosts:{}",
            file_fingerprint(&home.join(".ssh/known_hosts"))
        ));
    }
    values.push(format!(
        "system-ssh-config:{}",
        file_fingerprint(Path::new("/etc/ssh/ssh_config"))
    ));
    digest_owned_fields(values)
}

fn file_fingerprint(path: &Path) -> String {
    let Ok(canonical) = path.canonicalize() else {
        return format!("{}:missing", path.display());
    };
    let Ok(metadata) = fs::metadata(&canonical) else {
        return format!("{}:missing", canonical.display());
    };
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        canonical.display(),
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.uid(),
        metadata.mode()
    )
}

fn digest_owned_fields(fields: Vec<String>) -> Result<String, SshPoolError> {
    digest_fields(fields.iter().map(String::as_str))
}

fn digest_fields<'a>(fields: impl IntoIterator<Item = &'a str>) -> Result<String, SshPoolError> {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(field.len().to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(field.as_bytes());
    }
    sha256_hex(&bytes).map_err(|error| SshPoolError::Fingerprint(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use macluster_core::config::{NodeConfig, Transport};

    use super::{ConnectionKey, SshPool};

    fn node() -> NodeConfig {
        NodeConfig {
            host: "192.0.2.10".into(),
            transport: Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("operator".into()),
            ssh_port: Some(2222),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("00000000-0000-4000-8000-000000000010".into()),
            execution_uid: Some(501),
        }
    }

    fn control_path(pool: &SshPool, key: &ConnectionKey) -> String {
        let mut command = Command::new("ssh");
        pool.append_args(key, &mut command).unwrap();
        command
            .get_args()
            .find_map(|arg| {
                arg.to_string_lossy()
                    .strip_prefix("-oControlPath=")
                    .map(str::to_owned)
            })
            .unwrap()
    }

    fn cleanup_control_path(path: &str) {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn identical_node_identity_reuses_control_socket() {
        let node = node();
        let pool = SshPool::new("reuse-test");
        let first = ConnectionKey::for_node("reuse-test", "worker-a", &node).unwrap();
        let second = ConnectionKey::for_node("reuse-test", "worker-a", &node).unwrap();

        let first_path = control_path(&pool, &first);
        let second_path = control_path(&pool, &second);
        assert_eq!(first_path, second_path);
        cleanup_control_path(&first_path);
    }

    #[test]
    fn cluster_node_and_transport_identity_changes_never_reuse_socket() {
        let base = node();
        let key = ConnectionKey::for_node("cluster-a", "worker-a", &base).unwrap();
        let same_namespace = SshPool::new("cluster-a");
        let other_namespace = SshPool::new("cluster-b");
        let other_cluster_key = ConnectionKey::for_node("cluster-b", "worker-a", &base).unwrap();
        let mut other_host = base.clone();
        other_host.host = "192.0.2.11".into();
        let mut other_user = base.clone();
        other_user.ssh_user = Some("other".into());
        let mut other_port = base.clone();
        other_port.ssh_port = Some(2223);
        let mut other_machine = base.clone();
        other_machine.machine_uuid = Some("00000000-0000-4000-8000-000000000011".into());

        let paths = [
            control_path(&same_namespace, &key),
            control_path(&other_namespace, &other_cluster_key),
            control_path(
                &same_namespace,
                &ConnectionKey::for_node("cluster-a", "worker-a", &other_host).unwrap(),
            ),
            control_path(
                &same_namespace,
                &ConnectionKey::for_node("cluster-a", "worker-a", &other_user).unwrap(),
            ),
            control_path(
                &same_namespace,
                &ConnectionKey::for_node("cluster-a", "worker-a", &other_port).unwrap(),
            ),
            control_path(
                &same_namespace,
                &ConnectionKey::for_node("cluster-a", "worker-a", &other_machine).unwrap(),
            ),
        ];
        let unique = paths.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), paths.len());
        for path in &paths {
            cleanup_control_path(path);
        }
    }

    #[test]
    fn control_socket_root_is_private_and_paths_fit_macos_unix_limit() {
        let node = node();
        let key = ConnectionKey::for_node("cluster-with-long-name", "worker-a", &node).unwrap();
        let pool = SshPool::new("cluster-with-long-name");
        let path = control_path(&pool, &key);
        assert!(path.len() < 100, "ControlPath too long: {path}");
        let resolved_path_len = path.len() - "%C".len() + 40 + 17 + 1;
        assert!(
            resolved_path_len < 100,
            "expanded ControlPath too long for macOS: {path}"
        );
        assert!(path.starts_with("/tmp/"));
        assert!(path.contains("%C"));
        assert!(path.ends_with("-%C"));
        use std::os::unix::fs::MetadataExt;
        let root = std::path::Path::new(&path).parent().unwrap();
        let metadata = fs::symlink_metadata(root).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        cleanup_control_path(&path);
    }

    #[test]
    fn rotating_identity_file_uses_a_new_control_socket() {
        let root = std::env::temp_dir().join(format!(
            "macluster-ssh-key-{}",
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let identity = root.join("id_ed25519");
        fs::write(&identity, b"first private key").unwrap();
        let mut node = node();
        node.ssh_identity_file = Some(identity.display().to_string());
        let first = ConnectionKey::for_node("identity-rotation-test", "worker-a", &node).unwrap();
        fs::write(&identity, b"rotated private key with a different size").unwrap();
        let second = ConnectionKey::for_node("identity-rotation-test", "worker-a", &node).unwrap();
        assert_ne!(
            first.cache_fingerprint().unwrap(),
            second.cache_fingerprint().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_host_key_policy_change_uses_a_different_connection_key() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "macluster-ssh-hostkey-{}",
            macluster_protocol::identifiers::Id128::random()
        ));
        let ssh_dir = root.join(".ssh");
        let pin_dir = ssh_dir.join("macluster");
        fs::create_dir_all(&pin_dir).unwrap();
        fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&pin_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let old_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &root) };
        let node = node();
        let pinned = pin_dir.join("host-00000000-0000-4000-8000-000000000010");
        fs::write(&pinned, "[192.0.2.10]:2222 ssh-ed25519 AAAA\n").unwrap();
        fs::set_permissions(&pinned, fs::Permissions::from_mode(0o600)).unwrap();
        let first = ConnectionKey::for_node("hostkey-policy-test", "worker-a", &node).unwrap();
        fs::write(&pinned, "[192.0.2.10]:2222 ssh-ed25519 BBBBBBBBBBBB\n").unwrap();
        let second = ConnectionKey::for_node("hostkey-policy-test", "worker-a", &node).unwrap();
        if let Some(home) = old_home {
            unsafe { std::env::set_var("HOME", home) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        assert_ne!(first.host_key_policy_digest, second.host_key_policy_digest);
        fs::remove_dir_all(root).unwrap();
    }
}
