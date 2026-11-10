use std::{
    collections::BTreeMap,
    io::{self, IsTerminal},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    process::{Child, Command},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::client_profile::ClientProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InteractiveRequest {
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
}

pub(crate) fn validate_interactive_request_path(
    path: &Path,
    shared_root: &Path,
) -> Result<(), String> {
    if !path.starts_with(shared_root)
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("interactive request path must be inside the primary shared root".into());
    }
    Ok(())
}

pub(crate) fn run(profile: &ClientProfile, args: &[String], tty: bool) -> io::Result<i32> {
    if tty && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote command requires an interactive terminal",
        ));
    }
    let mut remote = vec![
        profile.remote_binary.clone(),
        "--config".into(),
        profile.remote_config.clone(),
        "--state-dir".into(),
        profile.remote_state_dir.clone(),
    ];
    remote.extend(args.iter().cloned());
    let mut command = ssh_command(
        profile,
        tty,
        &remote
            .iter()
            .map(|value| crate::node_admin::shell_quote(value))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let status = command.status()?;
    Ok(status.code().unwrap_or(1))
}

fn ssh_command(profile: &ClientProfile, tty: bool, remote_command: &str) -> Command {
    let mut command = Command::new("/usr/bin/ssh");
    command.args(routine_ssh_args(profile, tty));
    command.arg(remote_command);
    command
}

pub(crate) fn close_control_master(profile: &ClientProfile) -> Result<(), String> {
    let socket =
        crate::remote_transport::control_socket_path(profile).map_err(|error| error.to_string())?;
    close_control_master_socket(&socket, &profile.controller_host)
}

pub(crate) fn close_control_master_for(
    cluster_uuid: &str,
    controller_user: &str,
    controller_host: &str,
    controller_port: u16,
    identity_file: &str,
) -> Result<(), String> {
    let socket = crate::remote_transport::control_socket_path_for(
        cluster_uuid,
        controller_user,
        controller_host,
        controller_port,
        identity_file,
    )
    .map_err(|error| error.to_string())?;
    close_control_master_socket(&socket, controller_host)
}

fn close_control_master_socket(socket: &str, controller_host: &str) -> Result<(), String> {
    let socket_identity = match std::fs::symlink_metadata(&socket) {
        Ok(metadata) => Some((metadata.dev(), metadata.ino())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect the SSH control socket: {error}")),
    };
    let output = macluster_controller::transport::run_child_bounded(
        close_control_master_socket_command(socket, controller_host),
        None,
        Duration::from_secs(3),
    )
    .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if control_socket_was_abandoned(&stderr) {
        return remove_stale_control_socket_if_unchanged(socket, socket_identity);
    }
    Err(format!(
        "closing the SSH control master exited with {}: {}",
        output.status.code().unwrap_or(1),
        stderr.trim()
    ))
}

fn control_socket_was_abandoned(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("connection refused") || stderr.contains("no such file")
}

#[cfg(test)]
fn remove_stale_control_socket(socket: &str) -> Result<(), String> {
    remove_stale_control_socket_if_unchanged(socket, None)
}

fn remove_stale_control_socket_if_unchanged(
    socket: &str,
    expected_identity: Option<(u64, u64)>,
) -> Result<(), String> {
    let path = Path::new(socket);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect abandoned SSH control socket: {error}"
            ));
        }
    };
    let parent = path
        .parent()
        .ok_or_else(|| "SSH control socket has no parent directory".to_owned())?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect SSH control socket directory: {error}"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("refusing to remove an unowned or unsafe control socket".into());
    }
    if expected_identity.is_some_and(|expected| expected != (metadata.dev(), metadata.ino())) {
        return Err(
            "SSH control socket changed while it was being closed; refusing to remove it".into(),
        );
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove abandoned SSH control socket: {error}"
        )),
    }
}

fn close_control_master_socket_command(socket: &str, controller_host: &str) -> Command {
    let mut command = Command::new("/usr/bin/ssh");
    command
        .args([
            "-O",
            "exit",
            "-oLogLevel=ERROR",
            &format!("-oControlPath={socket}"),
        ])
        .arg(controller_host);
    command
}

pub(crate) fn start_forward(
    profile: &ClientProfile,
    local_port: u16,
    remote_port: u16,
) -> io::Result<Child> {
    let mut command = Command::new("/usr/bin/ssh");
    let mut args = routine_ssh_args(profile, false);
    let host = args.pop().expect("SSH arguments include a host");
    args.extend([
        "-N".into(),
        "-L".into(),
        format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"),
        host,
    ]);
    command.args(args);
    command.spawn()
}

pub(crate) fn revoke_client_key(profile: &ClientProfile) -> Result<(), String> {
    let path = format!("{}.pub", profile.identity_file);
    let Some(public_key) = read_public_key_for_revocation(&path)? else {
        return Ok(());
    };
    revoke_public_key_with_transport(profile, &public_key, true)
}

pub(crate) fn revoke_retired_public_key_with_transport(
    profile: &ClientProfile,
    public_key: &str,
) -> Result<(), String> {
    revoke_public_key_with_transport(profile, public_key, false)
}

fn revoke_public_key_with_transport(
    profile: &ClientProfile,
    public_key: &str,
    allow_already_revoked: bool,
) -> Result<(), String> {
    let script = revoke_script(public_key);
    let mut command = Command::new("/usr/bin/ssh");
    command.args(routine_ssh_args(profile, false));
    command.arg(script);
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if key_revocation_failure_is_idempotent(&stderr, allow_already_revoked) {
            return Ok(());
        }
        Err(format!(
            "remote client key revocation exited with {}: {}",
            output.status.code().unwrap_or(1),
            stderr.trim()
        ))
    }
}

fn key_authentication_was_already_revoked(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("permission denied")
        || stderr.contains("no supported authentication methods available")
}

fn key_revocation_failure_is_idempotent(stderr: &str, revoking_transport_identity: bool) -> bool {
    revoking_transport_identity && key_authentication_was_already_revoked(stderr)
}

fn read_public_key_for_revocation(path: &str) -> Result<Option<String>, String> {
    let public_key = match std::fs::read_to_string(path) {
        Ok(public_key) => public_key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read client public key: {error}")),
    };
    let key = public_key.trim();
    if key.is_empty() || key.chars().any(char::is_control) {
        return Err("client public key is invalid".into());
    }
    Ok(Some(key.to_owned()))
}

pub(crate) fn revoke_client_nfs_access(profile: &ClientProfile) -> Result<(), String> {
    revoke_client_nfs_access_target(profile, &profile.nfs_client_id, &profile.nfs_client_ip)
}

pub(crate) fn revoke_client_nfs_access_target(
    transport_profile: &ClientProfile,
    client_id: &str,
    client_ip: &str,
) -> Result<(), String> {
    let code = run(
        transport_profile,
        &client_revoke_args(client_id, client_ip),
        false,
    )
    .map_err(|error| error.to_string())?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("remote NFS access revocation exited with {code}"))
    }
}

fn client_revoke_args(client_id: &str, client_ip: &str) -> Vec<String> {
    vec![
        "internal".into(),
        "client-revoke".into(),
        "--json".into(),
        "--client-id".into(),
        client_id.into(),
        "--client-ip".into(),
        client_ip.into(),
    ]
}

pub(crate) fn authorize_client_nfs_access(profile: &ClientProfile) -> Result<(), String> {
    let code = run(
        profile,
        &[
            "internal".into(),
            "client-authorize".into(),
            "--json".into(),
            "--client-id".into(),
            profile.nfs_client_id.clone(),
        ],
        false,
    )
    .map_err(|error| error.to_string())?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "remote NFS access authorization exited with {code}"
        ))
    }
}

fn revoke_script(public_key: &str) -> String {
    let key = crate::node_admin::shell_quote(public_key);
    format!(
        "set -eu; f=\"$HOME/.ssh/authorized_keys\"; [ -f \"$f\" ] || exit 0; [ ! -L \"$f\" ]; t=\"$f.macluster.$$\"; /usr/bin/awk -v key={key} '$0 != key {{ print }}' \"$f\" > \"$t\"; /bin/chmod 600 \"$t\"; /bin/mv \"$t\" \"$f\""
    )
}

fn routine_ssh_args(profile: &ClientProfile, tty: bool) -> Vec<String> {
    let mut args = vec![
        if tty { "-tt".into() } else { "-T".into() },
        "-oLogLevel=ERROR".into(),
        "-oBatchMode=yes".into(),
        "-oStrictHostKeyChecking=yes".into(),
        format!("-oUserKnownHostsFile={}", profile.known_hosts_path),
        format!("-oHostKeyAlias=macluster-{}", profile.cluster_uuid),
        "-oConnectTimeout=4".into(),
        "-oConnectionAttempts=1".into(),
        "-oServerAliveInterval=5".into(),
        "-oServerAliveCountMax=3".into(),
        "-oControlMaster=auto".into(),
        "-oControlPersist=300".into(),
    ];
    if let Ok(path) = crate::remote_transport::control_socket_path(profile) {
        args.push(format!("-oControlPath={path}"));
    }
    args.extend([
        "-i".into(),
        profile.identity_file.clone(),
        "-oIdentitiesOnly=yes".into(),
        "-p".into(),
        profile.controller_port.to_string(),
        "-l".into(),
        profile.controller_user.clone(),
        profile.controller_host.clone(),
    ]);
    args
}

#[cfg(test)]
mod tests {
    use std::io;

    use serde_json::json;

    use crate::client_profile::ClientProfile;

    use macluster_protocol::identifiers::Id128;

    #[test]
    fn shell_quote_preserves_argument_boundaries() {
        let value = crate::node_admin::shell_quote("a b'c");
        assert_eq!(value, "'a b'\\''c'");
    }

    #[test]
    fn interactive_request_path_must_stay_inside_shared_root() {
        assert!(
            super::validate_interactive_request_path(
                std::path::Path::new("/Users/Shared/macluster/.macluster-client-requests/one"),
                std::path::Path::new("/Users/Shared/macluster")
            )
            .is_ok()
        );
        assert!(
            super::validate_interactive_request_path(
                std::path::Path::new("/tmp/one"),
                std::path::Path::new("/Users/Shared/macluster")
            )
            .is_err()
        );
    }

    #[test]
    fn leave_revokes_only_the_exact_public_key() {
        let script = super::revoke_script("ssh-ed25519 AAAA macluster-client");
        assert!(script.contains("authorized_keys"));
        assert!(script.contains("ssh-ed25519 AAAA macluster-client"));
        assert!(script.contains("$0 != key"));
    }

    #[test]
    fn missing_public_key_means_key_revocation_already_finished() {
        let path = std::env::temp_dir().join(format!("missing-key-{}", Id128::random()));
        assert_eq!(
            super::read_public_key_for_revocation(&path.to_string_lossy()).unwrap(),
            None
        );
    }

    #[test]
    fn an_already_revoked_key_is_idempotent_but_unreachable_controller_is_not() {
        assert!(super::key_authentication_was_already_revoked(
            "Permission denied (publickey,keyboard-interactive)."
        ));
        assert!(!super::key_authentication_was_already_revoked(
            "ssh: connect to host 192.0.2.1 port 22: Connection timed out"
        ));
        assert!(super::key_revocation_failure_is_idempotent(
            "Permission denied (publickey).",
            true
        ));
        assert!(!super::key_revocation_failure_is_idempotent(
            "Permission denied (publickey).",
            false
        ));
    }

    #[test]
    fn rejoin_can_revoke_the_previous_client_identity_through_the_new_transport() {
        assert_eq!(
            super::client_revoke_args("client-old", "192.0.2.20"),
            vec![
                "internal",
                "client-revoke",
                "--json",
                "--client-id",
                "client-old",
                "--client-ip",
                "192.0.2.20",
            ]
        );
    }

    #[test]
    fn routine_commands_use_the_endpoint_scoped_control_socket() {
        let profile: ClientProfile = serde_json::from_value(json!({
            "version": 2,
            "cluster_uuid": "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            "cluster_name": "home",
            "binding_digest": "b".repeat(64),
            "namespace": "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            "descriptor_generation": 1,
            "controller_host": "192.0.2.1",
            "controller_user": "mac",
            "controller_port": 22,
            "known_hosts_path": "/tmp/known_hosts",
            "identity_file": "/tmp/id_ed25519",
            "remote_uid": 501,
            "remote_binary": "/opt/homebrew/bin/macluster",
            "remote_config": "/tmp/config.toml",
            "remote_state_dir": "/tmp/state",
            "mounts_enabled": false,
            "nfs_client_id": "client-test",
            "nfs_client_ip": "192.0.2.10",
            "last_used_unix_ms": 1,
            "descriptor": null,
            "mounted_descriptor": null
        }))
        .unwrap();
        let expected = format!(
            "-oControlPath={}",
            crate::remote_transport::control_socket_path(&profile).unwrap()
        );
        let command = super::ssh_command(&profile, false, "/usr/bin/true");
        assert!(
            command
                .get_args()
                .any(|argument| argument == expected.as_str())
        );
    }

    #[test]
    fn leave_closes_the_same_endpoint_scoped_ssh_control_master() {
        let profile: ClientProfile = serde_json::from_value(json!({
            "version": 2,
            "cluster_uuid": "55fb9b02-ce96-5a69-8ad3-356563eff27b",
            "cluster_name": "home",
            "binding_digest": "b".repeat(64),
            "namespace": "55fb9b02-ce96-5a69-8ad3-356563eff27b",
            "descriptor_generation": 1,
            "controller_host": "192.0.2.1",
            "controller_user": "mac",
            "controller_port": 22,
            "known_hosts_path": "/tmp/known_hosts",
            "identity_file": "/tmp/id_ed25519",
            "remote_uid": 501,
            "remote_binary": "/opt/homebrew/bin/macluster",
            "remote_config": "/tmp/config.toml",
            "remote_state_dir": "/tmp/state",
            "mounts_enabled": false,
            "nfs_client_id": "client-test",
            "nfs_client_ip": "192.0.2.10",
            "last_used_unix_ms": 1,
            "descriptor": null,
            "mounted_descriptor": null
        }))
        .unwrap();
        let socket = crate::remote_transport::control_socket_path(&profile).unwrap();
        let expected = format!("-oControlPath={socket}");
        let command = super::close_control_master_socket_command(&socket, &profile.controller_host);
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|argument| argument == "-O"));
        assert!(args.iter().any(|argument| argument == "exit"));
        assert!(args.iter().any(|argument| argument == &expected));
        assert_eq!(args.last().map(String::as_str), Some("192.0.2.1"));
    }

    #[test]
    fn refused_or_missing_control_socket_is_already_closed() {
        assert!(super::control_socket_was_abandoned(
            "Control socket connect(/tmp/mc.sock): Connection refused"
        ));
        assert!(super::control_socket_was_abandoned(
            "Control socket connect(/tmp/mc.sock): No such file or directory"
        ));
        assert!(!super::control_socket_was_abandoned(
            "Permission denied while closing control socket"
        ));
    }

    #[test]
    fn abandoned_owned_control_socket_can_be_removed() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};

        let directory = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap()
            .join(".ssh/macluster");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(format!(
            "test-{}.sock",
            Id128::random().to_string().split_at(8).0
        ));
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(path.exists());
        super::remove_stale_control_socket(&path.to_string_lossy()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_replacement_control_socket_is_never_removed() {
        use std::os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixListener,
        };

        let directory = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap()
            .join(".ssh/macluster");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(format!(
            "test-{}.sock",
            Id128::random().to_string().split_at(8).0
        ));
        let first = UnixListener::bind(&path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let first_identity = (metadata.dev(), metadata.ino());
        drop(first);
        std::fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        let result = super::remove_stale_control_socket_if_unchanged(
            &path.to_string_lossy(),
            Some(first_identity),
        );
        assert!(result.is_err());
        assert!(path.exists());
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn remote_pty_is_rejected_when_local_stdio_is_not_a_terminal() {
        let profile: ClientProfile = serde_json::from_value(json!({
            "version": 2,
            "cluster_uuid": "82d02835-f6ab-52b4-aaab-f90cafde9981",
            "cluster_name": "home",
            "binding_digest": "b".repeat(64),
            "namespace": "82d02835-f6ab-52b4-aaab-f90cafde9981",
            "descriptor_generation": 1,
            "controller_host": "192.0.2.1",
            "controller_user": "mac",
            "controller_port": 22,
            "known_hosts_path": "/tmp/known_hosts",
            "identity_file": "/tmp/id_ed25519",
            "remote_uid": 501,
            "remote_binary": "/opt/homebrew/bin/macluster",
            "remote_config": "/tmp/config.toml",
            "remote_state_dir": "/tmp/state",
            "mounts_enabled": false,
            "nfs_client_id": "client-test",
            "nfs_client_ip": "192.0.2.10",
            "last_used_unix_ms": 1,
            "descriptor": null,
            "mounted_descriptor": null
        }))
        .unwrap();
        let error = super::run(&profile, &["controller".into(), "status".into()], true)
            .expect_err("non-terminal caller must not receive a remote PTY");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
