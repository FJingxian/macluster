use std::{
    collections::BTreeMap,
    io,
    path::Path,
    process::{Child, Command},
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
    let mut command = Command::new("/usr/bin/ssh");
    if tty {
        command.arg("-tt");
    } else {
        command.arg("-T");
    }
    command.args([
        "-oLogLevel=ERROR",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        &format!("-oUserKnownHostsFile={}", profile.known_hosts_path),
        &format!("-oHostKeyAlias=macluster-{}", profile.cluster_uuid),
        "-oConnectTimeout=4",
        "-oConnectionAttempts=1",
        "-oControlMaster=auto",
        "-oControlPersist=300",
        &format!(
            "-oControlPath={}/.ssh/macluster/client-{}.sock",
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
            profile.cluster_uuid
        ),
        "-i",
        &profile.identity_file,
        "-oIdentitiesOnly=yes",
        "-p",
        &profile.controller_port.to_string(),
        "-l",
        &profile.controller_user,
        &profile.controller_host,
    ]);
    let mut remote = vec![
        profile.remote_binary.clone(),
        "--config".into(),
        profile.remote_config.clone(),
        "--state-dir".into(),
        profile.remote_state_dir.clone(),
    ];
    remote.extend(args.iter().cloned());
    command.arg(
        remote
            .iter()
            .map(|value| crate::node_admin::shell_quote(value))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let status = command.status()?;
    Ok(status.code().unwrap_or(1))
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
    let public_key = std::fs::read_to_string(format!("{}.pub", profile.identity_file))
        .map_err(|error| format!("cannot read client public key: {error}"))?;
    let key = public_key.trim();
    if key.is_empty() || key.chars().any(char::is_control) {
        return Err("client public key is invalid".into());
    }
    let script = revoke_script(key);
    let mut command = Command::new("/usr/bin/ssh");
    command.args(routine_ssh_args(profile, false));
    command.arg(script);
    let status = command.status().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "remote client key revocation exited with {}",
            status.code().unwrap_or(1)
        ))
    }
}

pub(crate) fn revoke_client_nfs_access(profile: &ClientProfile) -> Result<(), String> {
    let code = run(
        profile,
        &[
            "internal".into(),
            "client-revoke".into(),
            "--json".into(),
            "--client-id".into(),
            profile.nfs_client_id.clone(),
            "--client-ip".into(),
            profile.nfs_client_ip.clone(),
        ],
        false,
    )
    .map_err(|error| error.to_string())?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("remote NFS access revocation exited with {code}"))
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
}
