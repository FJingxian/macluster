//! Run local compute work through the macOS SSH daemon.
//!
//! A LaunchAgent controller is the TCC "responsible process" for direct
//! children. Network volumes such as SMB then require Full Disk Access for
//! every controller build and every destination Mac. Launching the runner
//! through loopback SSH makes the Apple-signed SSH server responsible instead,
//! so a controller can migrate without another privacy-settings approval.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use macluster_core::config::{ClusterConfig, NodeConfig, Transport};
use macluster_protocol::identifiers::Id128;
use serde::{Deserialize, Serialize};

use crate::{AgentError, ProcessIdentity, process_identity, process_start_identity};

pub const FEATURE: &str = "agent.local-ssh-loopback.v1";

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(10);
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchedProcess {
    pub pid: u32,
    pub start_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct LaunchSpec {
    version: u32,
    program: PathBuf,
    arguments: Vec<String>,
    working_directory: PathBuf,
    receipt: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LaunchReceipt {
    Started { pid: u32, start_id: String },
    Failed { message: String },
}

struct KeyPaths {
    identity: PathBuf,
    known_hosts: PathBuf,
}

struct ExclusiveLock(File);

impl ExclusiveLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Local compute jobs need SSH responsibility when they can access a named
/// network share. Primary-storage-only and ordinary local paths keep the
/// lower-overhead direct launch path.
pub fn required(config: &ClusterConfig, node_id: &str, required_shares: Option<&[String]>) -> bool {
    config
        .nodes
        .get(node_id)
        .is_some_and(|node| node.transport == Transport::Local)
        && config.is_compute_node(node_id)
        && required_shares.is_none_or(|required| !required.is_empty())
        && !config.shares.is_empty()
}

pub fn launch(
    state_dir: &Path,
    config: &ClusterConfig,
    node_id: &str,
    command: CommandSpec,
) -> Result<LaunchedProcess, AgentError> {
    let node = config
        .nodes
        .get(node_id)
        .ok_or_else(|| AgentError::State(format!("local node '{node_id}' is absent")))?;
    if node.transport != Transport::Local {
        return Err(AgentError::State(format!(
            "node '{node_id}' does not use the local transport"
        )));
    }
    if !command.program.is_absolute() || !command.working_directory.is_absolute() {
        return Err(AgentError::State(
            "local SSH loopback requires absolute program and working-directory paths".into(),
        ));
    }

    let key_paths = ensure_key_material(state_dir, node, &config.share_uuid)?;
    let root = loopback_root(state_dir);
    let operation = Id128::random();
    let spec_path = root.join(format!("launch-{operation}.json"));
    let receipt_path = root.join(format!("receipt-{operation}.json"));
    let ssh_log_path = root.join(format!("ssh-{operation}.log"));
    write_json_atomic(
        &spec_path,
        &LaunchSpec {
            version: 1,
            program: command.program,
            arguments: command.arguments,
            working_directory: command.working_directory,
            receipt: receipt_path.clone(),
        },
    )?;

    let executable = std::env::current_exe()?;
    let executable = executable
        .to_str()
        .ok_or_else(|| AgentError::State("loopback executable path is not UTF-8".into()))?;
    let spec_path_text = spec_path
        .to_str()
        .ok_or_else(|| AgentError::State("loopback spec path is not UTF-8".into()))?;
    let remote_command = format!(
        "{} internal loopback-exec --spec {}",
        shell_quote(executable),
        shell_quote(spec_path_text)
    );
    let user = node.ssh_user.clone().unwrap_or_else(current_user_name);
    let port = node.ssh_port.unwrap_or(22);
    let host_key_alias = format!(
        "macluster-loopback-{}-{port}",
        config
            .share_uuid
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .take(16)
            .collect::<String>()
    );

    let mut ssh = Command::new("/usr/bin/ssh");
    ssh.arg("-f")
        .arg("-T")
        .arg("-E")
        .arg(&ssh_log_path)
        .args([
            "-oBatchMode=yes",
            "-oConnectTimeout=5",
            "-oConnectionAttempts=1",
            "-oLogLevel=ERROR",
            "-oPreferredAuthentications=publickey",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
            "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=accept-new",
            "-oControlMaster=no",
            "-oControlPath=none",
            "-oCheckHostIP=no",
            "-oServerAliveInterval=15",
            "-oServerAliveCountMax=4",
        ])
        .arg(format!(
            "-oUserKnownHostsFile={}",
            key_paths.known_hosts.display()
        ))
        .arg(format!("-oHostKeyAlias={host_key_alias}"))
        .arg("-i")
        .arg(&key_paths.identity)
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@127.0.0.1"))
        .arg(remote_command)
        .current_dir(state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = ssh.output()?;
    if !status.status.success() {
        let detail = read_log_tail(&ssh_log_path);
        remove_if_exists(&spec_path);
        remove_if_exists(&receipt_path);
        remove_if_exists(&ssh_log_path);
        return Err(AgentError::State(format!(
            "local SSH loopback authorization failed for {user}@127.0.0.1:{port}: {}{}",
            status.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }

    let deadline = Instant::now() + RECEIPT_TIMEOUT;
    let receipt = loop {
        match fs::read(&receipt_path) {
            Ok(bytes) => {
                break serde_json::from_slice::<LaunchReceipt>(&bytes).map_err(|error| {
                    AgentError::State(format!(
                        "local SSH loopback wrote an invalid receipt: {error}"
                    ))
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(RECEIPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let detail = read_log_tail(&ssh_log_path);
                remove_if_exists(&spec_path);
                remove_if_exists(&ssh_log_path);
                return Err(AgentError::State(format!(
                    "local SSH loopback did not start within {} seconds for {user}@127.0.0.1:{port}{}",
                    RECEIPT_TIMEOUT.as_secs(),
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                )));
            }
            Err(error) => return Err(error.into()),
        }
    };
    remove_if_exists(&spec_path);
    remove_if_exists(&receipt_path);
    remove_if_exists(&ssh_log_path);

    let LaunchReceipt::Started { pid, start_id } = receipt else {
        let LaunchReceipt::Failed { message } = receipt else {
            unreachable!();
        };
        return Err(AgentError::State(format!(
            "local SSH loopback could not start the requested command: {message}"
        )));
    };
    if process_identity(pid, &start_id) != ProcessIdentity::Match {
        return Err(AgentError::State(format!(
            "local SSH loopback process {pid} changed identity before authorization"
        )));
    }
    Ok(LaunchedProcess { pid, start_id })
}

/// Internal SSH command that owns the process group for the actual local
/// runner. It writes the remote PID and start identity before waiting.
pub fn execute(arguments: &[String]) -> Result<i32, AgentError> {
    if arguments.len() != 2 || arguments[0] != "--spec" {
        return Err(AgentError::State(
            "loopback-exec requires --spec PATH".into(),
        ));
    }
    let spec_path = Path::new(&arguments[1]);
    let bytes = fs::read(spec_path)?;
    let spec: LaunchSpec = serde_json::from_slice(&bytes)
        .map_err(|error| AgentError::State(format!("invalid loopback spec: {error}")))?;
    remove_if_exists(spec_path);
    if spec.version != 1 {
        write_receipt(
            &spec.receipt,
            &LaunchReceipt::Failed {
                message: format!("unsupported loopback spec version {}", spec.version),
            },
        )?;
        return Err(AgentError::State(
            "unsupported loopback spec version".into(),
        ));
    }

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.arguments)
        .current_dir(&spec.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            write_receipt(
                &spec.receipt,
                &LaunchReceipt::Failed {
                    message: error.to_string(),
                },
            )?;
            return Err(error.into());
        }
    };
    let pid = child.id();
    let Some(start_id) = process_start_identity(pid) else {
        let _ = child.kill();
        let _ = child.wait();
        write_receipt(
            &spec.receipt,
            &LaunchReceipt::Failed {
                message: "could not verify loopback child identity".into(),
            },
        )?;
        return Err(AgentError::State(
            "could not verify loopback child identity".into(),
        ));
    };
    write_receipt(&spec.receipt, &LaunchReceipt::Started { pid, start_id })?;
    let status = child.wait()?;
    if let Some(code) = status.code() {
        Ok(code)
    } else {
        Ok(128 + status.signal().unwrap_or(libc::SIGKILL))
    }
}

fn loopback_root(state_dir: &Path) -> PathBuf {
    state_dir.join("local-ssh")
}

fn ensure_key_material(
    state_dir: &Path,
    node: &NodeConfig,
    cluster_uuid: &str,
) -> Result<KeyPaths, AgentError> {
    let root = loopback_root(state_dir);
    ensure_private_directory(&root)?;
    let _lock = ExclusiveLock::acquire(&root.join("material.lock"))?;
    let identity = root.join("id_ed25519");
    let public = root.join("id_ed25519.pub");
    if !identity.exists() {
        let output = Command::new("/usr/bin/ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &format!("macluster-loopback:{cluster_uuid}"),
                "-f",
            ])
            .arg(&identity)
            .output()?;
        if !output.status.success() {
            return Err(AgentError::State(format!(
                "could not generate the local SSH loopback key: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }
    validate_private_file(&identity)?;
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))?;
    let public_text = if public.exists() {
        validate_private_file(&public)?;
        fs::read_to_string(&public)?
    } else {
        let output = Command::new("/usr/bin/ssh-keygen")
            .args(["-y", "-f"])
            .arg(&identity)
            .output()?;
        if !output.status.success() {
            return Err(AgentError::State(format!(
                "could not recover the local SSH loopback public key: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| AgentError::State("loopback public key is not UTF-8".into()))?
    };
    let public_text = public_text.trim();
    let mut fields = public_text.split_whitespace();
    if fields.next() != Some("ssh-ed25519") || fields.next().is_none() {
        return Err(AgentError::State(
            "local SSH loopback public key is invalid".into(),
        ));
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| AgentError::State("HOME is unavailable for loopback SSH".into()))?;
    install_authorized_key(&home, public_text, cluster_uuid, &node.host)?;

    let known_hosts = root.join("known_hosts");
    ensure_private_file(&known_hosts)?;
    Ok(KeyPaths {
        identity,
        known_hosts,
    })
}

fn install_authorized_key(
    home: &Path,
    public_key: &str,
    cluster_uuid: &str,
    host: &str,
) -> Result<(), AgentError> {
    let ssh_dir = home.join(".ssh");
    ensure_private_directory(&ssh_dir)?;
    let authorized_keys = ssh_dir.join("authorized_keys");
    let existing = match fs::symlink_metadata(&authorized_keys) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(AgentError::State(format!(
                "{} must be a regular file",
                authorized_keys.display()
            )));
        }
        Ok(metadata) => {
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(AgentError::State(format!(
                    "{} is owned by another account",
                    authorized_keys.display()
                )));
            }
            fs::read(&authorized_keys)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };

    let mut fields = public_key.split_whitespace();
    let key_type = fields.next().unwrap_or_default();
    let key_blob = fields.next().unwrap_or_default();
    if key_type.is_empty() || key_blob.is_empty() {
        return Err(AgentError::State(
            "cannot authorize an invalid loopback public key".into(),
        ));
    }
    let key_blob = key_blob.as_bytes();
    let managed_prefix = format!("macluster-loopback:{cluster_uuid}:");
    let mut retained = Vec::new();
    for line in existing.split_inclusive(|byte| *byte == b'\n') {
        let contains_this_key = line
            .split(|byte| byte.is_ascii_whitespace())
            .any(|field| field == key_blob);
        let is_managed_loopback_key = line
            .split(|byte| byte.is_ascii_whitespace())
            .any(|field| field.starts_with(managed_prefix.as_bytes()));
        if !contains_this_key && !is_managed_loopback_key {
            retained.extend_from_slice(line);
        }
    }
    if retained.last().is_some_and(|byte| *byte != b'\n') {
        retained.push(b'\n');
    }
    retained.extend_from_slice(
        format!("restrict,from=\"127.0.0.1\" {public_key} {managed_prefix}{host}\n").as_bytes(),
    );
    if retained == existing {
        return Ok(());
    }
    write_atomic(&authorized_keys, &retained, 0o600)
}

fn validate_private_file(path: &Path) -> Result<(), AgentError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AgentError::State(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(AgentError::State(format!(
            "{} is owned by another account",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), AgentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(AgentError::State(format!(
                "{} must be a real directory",
                path.display()
            )));
        }
        Ok(metadata) => {
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(AgentError::State(format!(
                    "{} is owned by another account",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<(), AgentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(AgentError::State(format!(
                "{} must be a regular file",
                path.display()
            )));
        }
        Ok(metadata) => {
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(AgentError::State(format!(
                    "{} is owned by another account",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            file.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_receipt(path: &Path, receipt: &LaunchReceipt) -> Result<(), AgentError> {
    write_json_atomic(path, receipt)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), AgentError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| AgentError::State(format!("cannot encode loopback state: {error}")))?;
    write_atomic(path, &bytes, 0o600)
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AgentError> {
    let parent = path
        .parent()
        .ok_or_else(|| AgentError::State(format!("{} has no parent", path.display())))?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        Id128::random()
    ));
    let result = (|| -> Result<(), AgentError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        remove_if_exists(&temporary);
    }
    result
}

fn remove_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

fn read_log_tail(path: &Path) -> String {
    fs::read(path)
        .ok()
        .map(|bytes| {
            let text = String::from_utf8_lossy(&bytes);
            text.lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn current_user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| unsafe { libc::geteuid() }.to_string())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn config(source: &str) -> ClusterConfig {
        ClusterConfig::parse(source).unwrap()
    }

    #[test]
    fn local_smb_compute_requires_ssh_loopback() {
        let config = config(
            "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nlogin_node=\"controller\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"controller\"\nprotocol_version=1\n[queues.q]\nnodes=[\"controller\"]\nscheduler=\"fifo\"\n[nodes.controller]\nhost=\"192.0.2.1\"\ntransport=\"local\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\nroles=[\"controller\",\"compute\"]\n[nodes.nas]\nhost=\"192.0.2.20\"\ntransport=\"storage\"\n[shares.data]\nprotocol=\"smb\"\nserver=\"nas\"\nsource_root=\"/data\"\nmount_root=\"/Users/Shared/data\"\nshare_uuid=\"00000000-0000-4000-8000-000000000002\"\nsmb_user=\"operator\"\n",
        );
        assert!(required(&config, "controller", Some(&["data".into()])));
    }

    #[test]
    fn local_named_nfs_compute_requires_ssh_loopback() {
        let config = config(
            "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nlogin_node=\"controller\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"controller\"\nprotocol_version=1\n[queues.q]\nnodes=[\"controller\"]\nscheduler=\"fifo\"\n[nodes.controller]\nhost=\"192.0.2.1\"\ntransport=\"local\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\nroles=[\"controller\",\"compute\"]\n[nodes.tools]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\n[shares.tools]\nprotocol=\"nfs\"\nserver=\"tools\"\nsource_root=\"/opt/tools\"\nmount_root=\"/opt/tools\"\nshare_uuid=\"00000000-0000-4000-8000-000000000002\"\n",
        );
        assert!(required(&config, "controller", Some(&["tools".into()])));
        assert!(!required(&config, "controller", Some(&[])));
    }

    #[test]
    fn local_controller_without_smb_keeps_direct_runner() {
        let config = config(
            "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nlogin_node=\"controller\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"controller\"\nprotocol_version=1\n[queues.q]\nnodes=[\"controller\"]\nscheduler=\"fifo\"\n[nodes.controller]\nhost=\"192.0.2.1\"\ntransport=\"local\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\nroles=[\"controller\",\"compute\"]\n",
        );
        assert!(!required(&config, "controller", None));
    }

    #[test]
    fn authorized_key_installation_is_idempotent_and_scoped_to_loopback() {
        let root = std::env::temp_dir().join(format!("macluster-loopback-key-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::write(
            root.join(".ssh/authorized_keys"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUnrelated unrelated\n\
             restrict,from=\"127.0.0.1\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStale macluster-loopback:test:old\n\
             restrict,from=\"127.0.0.1\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther macluster-loopback:other:old\n",
        )
        .unwrap();
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey";
        install_authorized_key(&root, public_key, "test", "192.0.2.1").unwrap();
        install_authorized_key(&root, public_key, "test", "192.0.2.1").unwrap();
        let contents = fs::read_to_string(root.join(".ssh/authorized_keys")).unwrap();
        assert!(contents.contains("AAAAIUnrelated"));
        assert!(!contents.contains("AAAAIStale"));
        assert!(contents.contains("AAAAIOther"));
        assert_eq!(
            contents.matches("AAAAC3NzaC1lZDI1NTE5AAAAITestKey").count(),
            1
        );
        assert!(contents.contains("restrict,from=\"127.0.0.1\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loopback_exec_starts_a_new_session_and_reports_its_identity() {
        let root =
            std::env::temp_dir().join(format!("macluster-loopback-exec-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let spec = root.join("spec.json");
        let receipt = root.join("receipt.json");
        write_json_atomic(
            &spec,
            &LaunchSpec {
                version: 1,
                program: PathBuf::from("/bin/sh"),
                arguments: vec![
                    "-c".into(),
                    "value=$(/bin/ps -o pgid= -p $$); [ \"$value\" -eq \"$$\" ]".into(),
                ],
                working_directory: root.clone(),
                receipt: receipt.clone(),
            },
        )
        .unwrap();
        let status = execute(&[
            "--spec".into(),
            OsString::from(spec)
                .into_string()
                .expect("temporary path is UTF-8"),
        ])
        .unwrap();
        assert_eq!(status, 0);
        let receipt: LaunchReceipt = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert!(matches!(receipt, LaunchReceipt::Started { pid, .. } if pid > 0));
        fs::remove_dir_all(root).unwrap();
    }
}
