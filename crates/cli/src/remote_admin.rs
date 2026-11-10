use std::{io, process::Command};

use crate::client_profile::ClientProfile;

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

#[cfg(test)]
mod tests {
    #[test]
    fn shell_quote_preserves_argument_boundaries() {
        let value = crate::node_admin::shell_quote("a b'c");
        assert_eq!(value, "'a b'\\''c'");
    }
}
