use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use macluster_protocol::{
    framing::sha256_hex,
    identifiers::{Id128, IdentifierError, NodeId, QueueName},
    types::{PROTOCOL_VERSION, SchedulerKind},
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterConfig {
    pub name: String,
    pub login_node: Option<NodeId>,
    pub default_queue: QueueName,
    pub shared_root: PathBuf,
    pub storage_source_root: Option<PathBuf>,
    pub share_uuid: String,
    pub storage_server: NodeId,
    pub protocol_version: u16,
    pub queues: BTreeMap<String, QueueConfig>,
    pub nodes: BTreeMap<String, NodeConfig>,
    pub shares: BTreeMap<String, ShareConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    pub nodes: Vec<String>,
    pub scheduler: SchedulerKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub host: String,
    pub transport: Transport,
    pub remote_binary: String,
    pub ssh_user: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_identity_file: Option<String>,
    pub remote_config: Option<String>,
    pub machine_uuid: Option<String>,
    pub execution_uid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareConfig {
    pub server: NodeId,
    pub source_root: PathBuf,
    pub mount_root: PathBuf,
    pub share_uuid: String,
}

impl NodeConfig {
    pub fn ssh_host_key_pin(&self) -> Option<(PathBuf, String)> {
        let uuid = Id128::parse(self.machine_uuid.as_deref()?).ok()?;
        let home = PathBuf::from(std::env::var_os("HOME")?);
        if !home.is_absolute() {
            return None;
        }
        Some((
            home.join(".ssh/macluster").join(format!("host-{uuid}")),
            format!("macluster-{uuid}"),
        ))
    }

    pub fn add_pinned_host_key_args(&self, command: &mut Command) {
        let Some((path, alias)) = self.ssh_host_key_pin() else {
            return;
        };
        add_trusted_node_ssh_args(command, &path, &alias, &self.host);
    }

    /// Add explicit SSH identity options while leaving legacy nodes to OpenSSH
    /// configuration when those fields are absent.
    pub fn add_ssh_identity_args(&self, command: &mut Command) {
        self.add_pinned_host_key_args(command);
        if let Some(port) = self.ssh_port {
            command.arg("-p").arg(port.to_string());
        }
        if let Some(user) = &self.ssh_user {
            command.arg("-l").arg(user);
        }
        if let Some(identity_file) = &self.ssh_identity_file {
            command
                .arg("-i")
                .arg(identity_file)
                .arg("-oIdentitiesOnly=yes");
        }
    }

    /// Add the config selector before the remote subcommand, if this node has
    /// a cluster-specific managed config path.
    pub fn add_remote_config_args(&self, command: &mut Command) {
        if let Some(path) = &self.remote_config {
            command.arg("--config").arg(path);
        }
    }
}

fn add_trusted_node_ssh_args(
    command: &mut Command,
    path: &Path,
    alias: &str,
    registered_host: &str,
) {
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return;
    };
    let private_parent = path
        .parent()
        .and_then(|parent| std::fs::symlink_metadata(parent).ok())
        .is_some_and(|parent| {
            parent.is_dir()
                && !parent.file_type().is_symlink()
                && parent.uid() == unsafe { libc::geteuid() }
                && parent.permissions().mode() & 0o022 == 0
        });
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
        && private_parent
    {
        command
            .arg(format!("-oUserKnownHostsFile={}", path.display()))
            .arg(format!("-oHostKeyAlias={alias}"));
        let address_path = path.with_extension("address");
        if let Ok(metadata) = std::fs::symlink_metadata(&address_path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() <= 128
            && let Ok(text) = std::fs::read_to_string(&address_path)
        {
            let fields = text.split_whitespace().collect::<Vec<_>>();
            if (2..=8).contains(&fields.len())
                && fields.contains(&registered_host)
                && fields[1]
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback())
            {
                command.arg(format!("-oHostName={}", fields[1]));
            }
        }
    } else {
        command.args([
            "-oUserKnownHostsFile=/dev/null",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oStrictHostKeyChecking=yes",
        ]);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Ssh,
    Local,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfigError {
    #[error("configuration line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("configuration repeats key '{key}' in [{section}]")]
    DuplicateKey { section: String, key: String },
    #[error("configuration repeats table [{0}]")]
    DuplicateTable(String),
    #[error("unknown or unsupported table [{0}]")]
    UnsupportedTable(String),
    #[error("[{section}] is missing required key '{key}'")]
    MissingKey { section: String, key: String },
    #[error("unknown key '{key}' in [{section}]")]
    UnknownKey { section: String, key: String },
    #[error("invalid {kind} identifier '{value}'")]
    InvalidIdentifier { kind: String, value: String },
    #[error("default queue '{0}' is not declared")]
    UnknownDefaultQueue(String),
    #[error("node '{0}' is not declared")]
    UnknownNode(String),
    #[error("queue '{queue}' lists node '{node}' more than once")]
    DuplicateMember { queue: String, node: String },
    #[error("shared root must be an absolute path")]
    SharedRootNotAbsolute,
    #[error("storage_source_root must be a normalized absolute path")]
    InvalidStorageSourceRoot,
    #[error("login_node must use the local transport")]
    LoginNodeMustBeLocal,
    #[error("share_uuid must be a canonical UUID")]
    InvalidShareUuid,
    #[error("protocol version {0} is incompatible with this binary")]
    IncompatibleProtocol(u16),
    #[error("unsupported scheduler '{0}'")]
    UnsupportedScheduler(String),
    #[error("unsupported transport '{0}'")]
    UnsupportedTransport(String),
    #[error("node address is empty or unsafe for SSH")]
    InvalidHost,
    #[error("SSH user is empty or contains characters unsupported by mnode")]
    InvalidSshUser,
    #[error("SSH port must be in 1..=65535")]
    InvalidSshPort,
    #[error("ssh_identity_file must be an absolute path without control characters")]
    InvalidSshIdentityFile,
    #[error("multiple node IDs use the same SSH host '{0}'")]
    DuplicateHost(String),
    #[error(
        "remote_binary must be a normalized absolute file path using only ASCII letters, digits, slash, dot, underscore, or hyphen"
    )]
    InvalidRemoteBinary,
    #[error(
        "remote_config must be a normalized absolute file path using only ASCII letters, digits, slash, dot, underscore, or hyphen"
    )]
    InvalidRemoteConfig,
    #[error("machine_uuid must be a canonical UUID")]
    InvalidMachineUuid,
    #[error("execution_uid must fit a 32-bit unsigned integer")]
    InvalidExecutionUid,
    #[error("local transport requires machine_uuid and execution_uid")]
    MissingLocalIdentity,
    #[error("only one local transport node may be configured")]
    MultipleLocalNodes,
    #[error("multiple node IDs refer to the same machine UUID '{0}'")]
    DuplicateMachineUuid(String),
    #[error(
        "share paths must be normalized absolute paths using only ASCII letters, digits, slash, dot, underscore, or hyphen"
    )]
    InvalidSharePath,
    #[error("share '{share}' mount path overlaps another managed path '{path}'")]
    ShareMountConflict { share: String, path: String },
    #[error("share '{share}' source path overlaps another export '{path}' on the same server")]
    ShareSourceConflict { share: String, path: String },
    #[error("share '{share}' source path overlaps mount path '{path}' on a client")]
    ShareSourceMountConflict { share: String, path: String },
    #[error("could not calculate execution configuration digest")]
    DigestFailure,
    #[error(
        "this minimal TOML reader only accepts strings, arrays of strings, and unsigned integers"
    )]
    UnsupportedValue,
}

impl From<IdentifierError> for ConfigError {
    fn from(_: IdentifierError) -> Self {
        Self::InvalidIdentifier {
            kind: "name".to_owned(),
            value: String::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    String(String),
    Strings(Vec<String>),
    Integer(u64),
}

type Table = BTreeMap<String, Value>;

impl ClusterConfig {
    /// The login node is for submissions, control, and storage. Legacy configs
    /// may still list it in queues, but it must never be eligible for jobs.
    pub fn is_login_node(&self, node_id: &str) -> bool {
        self.login_node.as_ref().map_or_else(
            || {
                self.nodes
                    .get(node_id)
                    .is_some_and(|node| node.transport == Transport::Local)
            },
            |login_node| login_node.as_str() == node_id,
        )
    }

    /// Return a queue view suitable for dispatch while preserving raw
    /// membership in the parsed config for compatibility with existing files.
    pub fn queue_for_dispatch(&self, queue_name: &str) -> Option<QueueConfig> {
        let mut queue = self.queues.get(queue_name)?.clone();
        queue.nodes.retain(|node_id| !self.is_login_node(node_id));
        Some(queue)
    }

    /// Queue members presented to operators as compute workers.
    pub fn queue_compute_nodes(&self, queue_name: &str) -> Vec<String> {
        self.queue_for_dispatch(queue_name)
            .map_or_else(Vec::new, |queue| queue.nodes)
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let document = parse_document(input)?;
        let mut cluster =
            document
                .get("cluster")
                .cloned()
                .ok_or_else(|| ConfigError::MissingKey {
                    section: "cluster".to_owned(),
                    key: "name".to_owned(),
                })?;

        let name = take_string(&mut cluster, "cluster", "name")?;
        let login_node_raw = take_optional_string(&mut cluster, "cluster", "login_node")?;
        let storage_source_root_raw =
            take_optional_string(&mut cluster, "cluster", "storage_source_root")?;
        let default_queue_raw = take_string(&mut cluster, "cluster", "default_queue")?;
        let default_queue = QueueName::new(default_queue_raw.clone()).map_err(|_| {
            ConfigError::InvalidIdentifier {
                kind: "queue".to_owned(),
                value: default_queue_raw,
            }
        })?;
        let shared_root_raw = take_string(&mut cluster, "cluster", "shared_root")?;
        let shared_root = PathBuf::from(shared_root_raw);
        if !shared_root.is_absolute() {
            return Err(ConfigError::SharedRootNotAbsolute);
        }
        let storage_source_root = storage_source_root_raw
            .map(|value| {
                if !safe_absolute_remote_file(&value) {
                    return Err(ConfigError::InvalidStorageSourceRoot);
                }
                Ok(PathBuf::from(value))
            })
            .transpose()?;
        let share_uuid = take_string(&mut cluster, "cluster", "share_uuid")?;
        if macluster_protocol::identifiers::Id128::parse(&share_uuid).is_err() {
            return Err(ConfigError::InvalidShareUuid);
        }
        let storage_server_raw = take_string(&mut cluster, "cluster", "storage_server")?;
        let storage_server = NodeId::new(storage_server_raw.clone()).map_err(|_| {
            ConfigError::InvalidIdentifier {
                kind: "node".to_owned(),
                value: storage_server_raw,
            }
        })?;
        let protocol_version =
            u16::try_from(take_integer(&mut cluster, "cluster", "protocol_version")?)
                .map_err(|_| ConfigError::IncompatibleProtocol(u16::MAX))?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(ConfigError::IncompatibleProtocol(protocol_version));
        }
        reject_unknown_keys(&cluster, "cluster")?;

        let mut queues = BTreeMap::new();
        let mut nodes = BTreeMap::new();
        let mut shares = BTreeMap::new();
        for (section, mut table) in document {
            if section == "cluster" {
                continue;
            }
            if let Some(name) = section.strip_prefix("queues.") {
                let queue = QueueName::new(name.to_owned()).map_err(|_| {
                    ConfigError::InvalidIdentifier {
                        kind: "queue".to_owned(),
                        value: name.to_owned(),
                    }
                })?;
                let name = queue.to_string();
                let members = take_strings(&mut table, &section, "nodes")?;
                let scheduler_raw = take_string(&mut table, &section, "scheduler")?;
                let scheduler = match scheduler_raw.as_str() {
                    "fifo" => SchedulerKind::Fifo,
                    _ => return Err(ConfigError::UnsupportedScheduler(scheduler_raw)),
                };
                reject_unknown_keys(&table, &section)?;
                let mut seen = BTreeSet::new();
                for member in &members {
                    let node = NodeId::new(member.clone()).map_err(|_| {
                        ConfigError::InvalidIdentifier {
                            kind: "node".to_owned(),
                            value: member.clone(),
                        }
                    })?;
                    if !seen.insert(node.to_string()) {
                        return Err(ConfigError::DuplicateMember {
                            queue: name,
                            node: member.clone(),
                        });
                    }
                }
                queues.insert(
                    name,
                    QueueConfig {
                        nodes: members,
                        scheduler,
                    },
                );
                continue;
            }
            if let Some(name) = section.strip_prefix("nodes.") {
                let node =
                    NodeId::new(name.to_owned()).map_err(|_| ConfigError::InvalidIdentifier {
                        kind: "node".to_owned(),
                        value: name.to_owned(),
                    })?;
                let name = node.to_string();
                let host = take_string(&mut table, &section, "host")?;
                if host.is_empty()
                    || host.starts_with('-')
                    || host.chars().any(char::is_whitespace)
                    || host.chars().any(char::is_control)
                {
                    return Err(ConfigError::InvalidHost);
                }
                let transport_raw = take_string(&mut table, &section, "transport")?;
                let transport = match transport_raw.as_str() {
                    "ssh" => Transport::Ssh,
                    "local" => Transport::Local,
                    _ => return Err(ConfigError::UnsupportedTransport(transport_raw)),
                };
                let remote_binary = take_optional_string(&mut table, &section, "remote_binary")?
                    .unwrap_or_else(|| "/usr/local/bin/macluster".into());
                if !safe_absolute_remote_file(&remote_binary) {
                    return Err(ConfigError::InvalidRemoteBinary);
                }
                let ssh_user = take_optional_string(&mut table, &section, "ssh_user")?;
                if ssh_user.as_ref().is_some_and(|user| {
                    user.is_empty()
                        || user.len() > 64
                        || !user.bytes().enumerate().all(|(index, byte)| {
                            if index == 0 {
                                byte.is_ascii_alphanumeric() || byte == b'_'
                            } else {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                            }
                        })
                }) {
                    return Err(ConfigError::InvalidSshUser);
                }
                let ssh_port = take_optional_integer(&mut table, &section, "ssh_port")?
                    .map(|port| {
                        u16::try_from(port)
                            .ok()
                            .filter(|port| *port != 0)
                            .ok_or(ConfigError::InvalidSshPort)
                    })
                    .transpose()?;
                let ssh_identity_file =
                    take_optional_string(&mut table, &section, "ssh_identity_file")?;
                if ssh_identity_file
                    .as_deref()
                    .is_some_and(|path| !safe_absolute_ssh_identity_file(path))
                    || (transport == Transport::Local && ssh_identity_file.is_some())
                {
                    return Err(ConfigError::InvalidSshIdentityFile);
                }
                let remote_config = take_optional_string(&mut table, &section, "remote_config")?;
                if remote_config
                    .as_ref()
                    .is_some_and(|path| !safe_absolute_remote_file(path))
                {
                    return Err(ConfigError::InvalidRemoteConfig);
                }
                let machine_uuid = take_optional_string(&mut table, &section, "machine_uuid")?
                    .map(|value| {
                        macluster_protocol::identifiers::Id128::parse(&value)
                            .map(|uuid| uuid.to_string())
                            .map_err(|_| ConfigError::InvalidMachineUuid)
                    })
                    .transpose()?;
                let execution_uid = take_optional_integer(&mut table, &section, "execution_uid")?
                    .map(|uid| u32::try_from(uid).map_err(|_| ConfigError::InvalidExecutionUid))
                    .transpose()?;
                if transport == Transport::Local
                    && (machine_uuid.is_none() || execution_uid.is_none())
                {
                    return Err(ConfigError::MissingLocalIdentity);
                }
                reject_unknown_keys(&table, &section)?;
                if transport == Transport::Local
                    && nodes
                        .values()
                        .any(|node: &NodeConfig| node.transport == Transport::Local)
                {
                    return Err(ConfigError::MultipleLocalNodes);
                }
                nodes.insert(
                    name,
                    NodeConfig {
                        host,
                        transport,
                        remote_binary,
                        ssh_user,
                        ssh_port,
                        ssh_identity_file,
                        remote_config,
                        machine_uuid,
                        execution_uid,
                    },
                );
                continue;
            }
            if let Some(name) = section.strip_prefix("shares.") {
                let share =
                    NodeId::new(name.to_owned()).map_err(|_| ConfigError::InvalidIdentifier {
                        kind: "share".to_owned(),
                        value: name.to_owned(),
                    })?;
                let name = share.to_string();
                let server_raw = take_string(&mut table, &section, "server")?;
                let server = NodeId::new(server_raw.clone()).map_err(|_| {
                    ConfigError::InvalidIdentifier {
                        kind: "node".to_owned(),
                        value: server_raw,
                    }
                })?;
                let source_raw = take_string(&mut table, &section, "source_root")?;
                let mount_raw = take_string(&mut table, &section, "mount_root")?;
                if !safe_absolute_remote_file(&source_raw) || !safe_absolute_remote_file(&mount_raw)
                {
                    return Err(ConfigError::InvalidSharePath);
                }
                let share_uuid = take_string(&mut table, &section, "share_uuid")?;
                if macluster_protocol::identifiers::Id128::parse(&share_uuid).is_err() {
                    return Err(ConfigError::InvalidShareUuid);
                }
                reject_unknown_keys(&table, &section)?;
                shares.insert(
                    name,
                    ShareConfig {
                        server,
                        source_root: PathBuf::from(source_raw),
                        mount_root: PathBuf::from(mount_raw),
                        share_uuid: share_uuid.to_ascii_lowercase(),
                    },
                );
                continue;
            }
            return Err(ConfigError::UnsupportedTable(section));
        }

        if !queues.contains_key(default_queue.as_str()) {
            return Err(ConfigError::UnknownDefaultQueue(default_queue.to_string()));
        }
        for queue in queues.values() {
            for node in &queue.nodes {
                if !nodes.contains_key(node) {
                    return Err(ConfigError::UnknownNode(node.clone()));
                }
            }
        }
        if !nodes.contains_key(storage_server.as_str()) {
            return Err(ConfigError::UnknownNode(storage_server.to_string()));
        }
        let login_node = login_node_raw
            .map(|value| {
                NodeId::new(value.clone()).map_err(|_| ConfigError::InvalidIdentifier {
                    kind: "node".to_owned(),
                    value,
                })
            })
            .transpose()?;
        if let Some(login_node) = &login_node {
            let node = nodes
                .get(login_node.as_str())
                .ok_or_else(|| ConfigError::UnknownNode(login_node.to_string()))?;
            if node.transport != Transport::Local {
                return Err(ConfigError::LoginNodeMustBeLocal);
            }
        }
        let mut hosts = BTreeSet::new();
        let mut machine_uuids = BTreeSet::new();
        for node in nodes.values() {
            if !hosts.insert(node.host.as_str()) {
                return Err(ConfigError::DuplicateHost(node.host.clone()));
            }
            if let Some(uuid) = &node.machine_uuid
                && !machine_uuids.insert(uuid.as_str())
            {
                return Err(ConfigError::DuplicateMachineUuid(uuid.clone()));
            }
        }
        for (share_id, share) in &shares {
            if !nodes.contains_key(share.server.as_str()) {
                return Err(ConfigError::UnknownNode(share.server.to_string()));
            }
            if paths_overlap(&share.mount_root, &shared_root) {
                return Err(ConfigError::ShareMountConflict {
                    share: share_id.clone(),
                    path: shared_root.to_string_lossy().into_owned(),
                });
            }
            let primary_source_root = storage_source_root.as_deref().unwrap_or(&shared_root);
            if share.server == storage_server
                && paths_overlap(&share.source_root, primary_source_root)
            {
                return Err(ConfigError::ShareSourceConflict {
                    share: share_id.clone(),
                    path: primary_source_root.to_string_lossy().into_owned(),
                });
            }
            for (other_id, other) in &shares {
                if share_id >= other_id {
                    continue;
                }
                if paths_overlap(&share.mount_root, &other.mount_root) {
                    return Err(ConfigError::ShareMountConflict {
                        share: share_id.clone(),
                        path: other.mount_root.to_string_lossy().into_owned(),
                    });
                }
                if share.server == other.server
                    && paths_overlap(&share.source_root, &other.source_root)
                {
                    return Err(ConfigError::ShareSourceConflict {
                        share: share_id.clone(),
                        path: other.source_root.to_string_lossy().into_owned(),
                    });
                }
                if paths_overlap(&share.source_root, &other.mount_root)
                    && share.source_root != share.mount_root
                {
                    return Err(ConfigError::ShareSourceMountConflict {
                        share: share_id.clone(),
                        path: other.mount_root.to_string_lossy().into_owned(),
                    });
                }
                if paths_overlap(&other.source_root, &share.mount_root)
                    && other.source_root != other.mount_root
                {
                    return Err(ConfigError::ShareSourceMountConflict {
                        share: other_id.clone(),
                        path: share.mount_root.to_string_lossy().into_owned(),
                    });
                }
            }
        }

        Ok(Self {
            name,
            login_node,
            default_queue,
            shared_root,
            storage_source_root,
            share_uuid,
            storage_server,
            protocol_version,
            queues,
            nodes,
            shares,
        })
    }

    /// The server-side path exported as the primary share. Older configs use
    /// `shared_root` for both server storage and client mount point.
    pub fn primary_source_root(&self) -> &Path {
        self.storage_source_root
            .as_deref()
            .unwrap_or(&self.shared_root)
    }

    /// Hash normalized scheduling and storage state, omitting per-host SSH and
    /// executable/config paths so managed peer copies produce the same digest.
    pub fn execution_digest(&self) -> Result<String, ConfigError> {
        let mut rows = vec![format!(
            "cluster\0{}\0{}\0{}\0{}\0{}\0{}",
            self.name,
            self.default_queue,
            self.shared_root.display(),
            self.share_uuid.to_ascii_lowercase(),
            self.storage_server,
            self.protocol_version
        )];
        for (id, queue) in &self.queues {
            let mut members = queue.nodes.clone();
            members.sort();
            rows.push(format!(
                "queue\0{id}\0{:?}\0{}",
                queue.scheduler,
                members.join("\0")
            ));
        }
        for (id, node) in &self.nodes {
            rows.push(format!(
                "node\0{id}\0{}\0{:?}\0{}\0{}",
                node.host,
                node.transport,
                node.machine_uuid.as_deref().unwrap_or(""),
                node.execution_uid
                    .map_or_else(String::new, |uid| uid.to_string())
            ));
        }
        for (id, share) in &self.shares {
            rows.push(format!(
                "share\0{id}\0{}\0{}\0{}\0{}",
                share.server,
                share.source_root.display(),
                share.mount_root.display(),
                share.share_uuid.to_ascii_lowercase()
            ));
        }
        if let Some(login_node) = &self.login_node {
            rows.push(format!("login\0{login_node}"));
        }
        if self.primary_source_root() != self.shared_root {
            rows.push(format!(
                "primary-source\0{}",
                self.primary_source_root().display()
            ));
        }
        let encoded = serde_json::to_vec(&rows).map_err(|_| ConfigError::DigestFailure)?;
        sha256_hex(&encoded).map_err(|_| ConfigError::DigestFailure)
    }
}

fn safe_absolute_remote_file(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn safe_absolute_ssh_identity_file(path: &str) -> bool {
    Path::new(path).is_absolute()
        && path != "/"
        && !path.ends_with('/')
        && !path.chars().any(char::is_control)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn parse_document(input: &str) -> Result<BTreeMap<String, Table>, ConfigError> {
    let mut document = BTreeMap::new();
    let mut current = String::new();
    for (index, source) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(source).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') || line.starts_with("[[") || line.ends_with("]]") {
                return Err(parse_error(line_number, "invalid table header"));
            }
            let body = line[1..line.len() - 1].trim();
            let mut parts = body.split('.');
            let kind = parts.next().unwrap_or_default();
            let name = parts.next();
            let valid = match (kind, name, parts.next()) {
                ("cluster", None, None) => "cluster".to_owned(),
                ("queues" | "nodes" | "shares", Some(name), None) if !name.is_empty() => {
                    let validation = match kind {
                        "queues" => QueueName::new(name.to_owned()).map(|_| ()),
                        _ => NodeId::new(name.to_owned()).map(|_| ()),
                    };
                    if validation.is_err() {
                        return Err(ConfigError::InvalidIdentifier {
                            kind: match kind {
                                "queues" => "queue",
                                "shares" => "share",
                                _ => "node",
                            }
                            .to_owned(),
                            value: name.to_owned(),
                        });
                    }
                    format!("{kind}.{name}")
                }
                ("queues" | "nodes" | "shares", _, _) => {
                    return Err(ConfigError::InvalidIdentifier {
                        kind: match kind {
                            "queues" => "queue",
                            "shares" => "share",
                            _ => "node",
                        }
                        .to_owned(),
                        value: body.to_owned(),
                    });
                }
                _ => return Err(ConfigError::UnsupportedTable(body.to_owned())),
            };
            if document.insert(valid.clone(), Table::new()).is_some() {
                return Err(ConfigError::DuplicateTable(valid));
            }
            current = valid;
            continue;
        }
        if current.is_empty() {
            return Err(parse_error(
                line_number,
                "key appears before a table header",
            ));
        }
        let Some(equals) = find_unquoted(line, '=') else {
            return Err(parse_error(line_number, "expected key = value"));
        };
        let key = line[..equals].trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(parse_error(line_number, "invalid key"));
        }
        let value = parse_value(line[equals + 1..].trim())
            .map_err(|message| parse_error(line_number, &message))?;
        let table = document.get_mut(&current).expect("current table exists");
        if table.insert(key.to_owned(), value).is_some() {
            return Err(ConfigError::DuplicateKey {
                section: current.clone(),
                key: key.to_owned(),
            });
        }
    }
    Ok(document)
}

fn parse_value(value: &str) -> Result<Value, String> {
    if value.starts_with('"') {
        let (parsed, consumed) = parse_string_prefix(value)?;
        if !value[consumed..].trim().is_empty() {
            return Err("unexpected text after string value".to_owned());
        }
        return Ok(Value::String(parsed));
    }
    if value.starts_with('[') {
        if !value.ends_with(']') {
            return Err("unterminated array".to_owned());
        }
        let mut rest = value[1..value.len() - 1].trim();
        let mut values = Vec::new();
        while !rest.is_empty() {
            let (item, consumed) = parse_string_prefix(rest)?;
            values.push(item);
            rest = rest[consumed..].trim_start();
            if rest.is_empty() {
                break;
            }
            if !rest.starts_with(',') {
                return Err("expected ',' between array items".to_owned());
            }
            rest = rest[1..].trim_start();
            if rest.is_empty() {
                break;
            }
        }
        return Ok(Value::Strings(values));
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) && !value.is_empty() {
        return value
            .parse::<u64>()
            .map(Value::Integer)
            .map_err(|_| "integer is out of range".to_owned());
    }
    Err("unsupported value".to_owned())
}

fn parse_string_prefix(input: &str) -> Result<(String, usize), String> {
    if !input.starts_with('"') {
        return Err("expected a double-quoted string".to_owned());
    }
    let bytes = input.as_bytes();
    let mut output = String::new();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok((output, index + 1)),
            b'\\' => {
                index += 1;
                if index == bytes.len() {
                    return Err("unterminated string escape".to_owned());
                }
                output.push(match bytes[index] {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    _ => return Err("unsupported string escape".to_owned()),
                });
                index += 1;
            }
            byte if byte < 0x20 => return Err("control character in string".to_owned()),
            _ => {
                let character = input[index..]
                    .chars()
                    .next()
                    .ok_or_else(|| "invalid string".to_owned())?;
                output.push(character);
                index += character.len_utf8();
            }
        }
    }
    Err("unterminated string".to_owned())
}

fn find_unquoted(input: &str, needle: char) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == needle {
            return Some(index);
        }
    }
    None
}

fn strip_comment(input: &str) -> &str {
    find_unquoted(input, '#').map_or(input, |index| &input[..index])
}

fn take_string(table: &mut Table, section: &str, key: &str) -> Result<String, ConfigError> {
    match table.remove(key) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(parse_error(
            0,
            &format!("[{section}] key '{key}' must be a string"),
        )),
        None => Err(ConfigError::MissingKey {
            section: section.to_owned(),
            key: key.to_owned(),
        }),
    }
}

fn take_optional_string(
    table: &mut Table,
    section: &str,
    key: &str,
) -> Result<Option<String>, ConfigError> {
    match table.remove(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(parse_error(
            0,
            &format!("[{section}] key '{key}' must be a string"),
        )),
        None => Ok(None),
    }
}

fn take_strings(table: &mut Table, section: &str, key: &str) -> Result<Vec<String>, ConfigError> {
    match table.remove(key) {
        Some(Value::Strings(value)) => Ok(value),
        Some(_) => Err(parse_error(
            0,
            &format!("[{section}] key '{key}' must be a string array"),
        )),
        None => Err(ConfigError::MissingKey {
            section: section.to_owned(),
            key: key.to_owned(),
        }),
    }
}

fn take_integer(table: &mut Table, section: &str, key: &str) -> Result<u64, ConfigError> {
    match table.remove(key) {
        Some(Value::Integer(value)) => Ok(value),
        Some(_) => Err(parse_error(
            0,
            &format!("[{section}] key '{key}' must be an integer"),
        )),
        None => Err(ConfigError::MissingKey {
            section: section.to_owned(),
            key: key.to_owned(),
        }),
    }
}

fn take_optional_integer(
    table: &mut Table,
    section: &str,
    key: &str,
) -> Result<Option<u64>, ConfigError> {
    match table.remove(key) {
        Some(Value::Integer(value)) => Ok(Some(value)),
        Some(_) => Err(parse_error(
            0,
            &format!("[{section}] key '{key}' must be an integer"),
        )),
        None => Ok(None),
    }
}

fn reject_unknown_keys(table: &Table, section: &str) -> Result<(), ConfigError> {
    if let Some(key) = table.keys().next() {
        return Err(ConfigError::UnknownKey {
            section: section.to_owned(),
            key: key.clone(),
        });
    }
    Ok(())
}

fn parse_error(line: usize, message: &str) -> ConfigError {
    ConfigError::Parse {
        line,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod address_ssh_tests {
    use super::*;
    use std::fs;

    #[test]
    fn verified_address_cache_is_scoped_to_original_host_and_private_pin() {
        let root = std::env::temp_dir().join(format!("macluster-address-ssh-{}", Id128::random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = root.join("host-node");
        fs::write(&pin, "macluster-node ssh-ed25519 fixture\n").unwrap();
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).unwrap();
        let cache = pin.with_extension("address");
        fs::write(&cache, "192.0.2.1 192.0.2.3\n").unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o600)).unwrap();
        let args = |host: &str| {
            let mut command = Command::new("ssh");
            add_trusted_node_ssh_args(&mut command, &pin, "macluster-node", host);
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert!(args("192.0.2.1").contains(&"-oHostName=192.0.2.3".into()));
        assert!(args("192.0.2.3").contains(&"-oHostKeyAlias=macluster-node".into()));
        assert!(
            !args("192.0.2.9")
                .iter()
                .any(|arg| arg.starts_with("-oHostName="))
        );
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            !args("192.0.2.1")
                .iter()
                .any(|arg| arg.starts_with("-oHostName="))
        );
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(args("192.0.2.1").contains(&"-oUserKnownHostsFile=/dev/null".into()));
        assert!(args("192.0.2.1").contains(&"-oStrictHostKeyChecking=yes".into()));
        fs::remove_dir_all(root).unwrap();
    }
}
