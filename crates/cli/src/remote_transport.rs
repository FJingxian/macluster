use std::{
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use crate::client_profile::ClientProfile;

pub(crate) struct RemoteControlStream {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl RemoteControlStream {
    pub(crate) fn connect(profile: &ClientProfile) -> io::Result<Self> {
        let mut child = Command::new("/usr/bin/ssh")
            .args(remote_ssh_args(profile))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "remote control stdin is unavailable",
            )
        })?;
        let output = child.stdout.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "remote control stdout is unavailable",
            )
        })?;
        Ok(Self {
            child,
            input,
            output,
        })
    }
}

impl Read for RemoteControlStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.output.read(buffer)
    }
}

impl Write for RemoteControlStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.input.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.input.flush()
    }
}

impl Drop for RemoteControlStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn remote_ssh_args(profile: &ClientProfile) -> Vec<String> {
    vec![
        "-T".into(),
        "-oLogLevel=ERROR".into(),
        "-oBatchMode=yes".into(),
        "-oStrictHostKeyChecking=yes".into(),
        format!("-oUserKnownHostsFile={}", profile.known_hosts_path),
        format!("-oHostKeyAlias=macluster-{}", profile.cluster_uuid),
        "-oConnectTimeout=4".into(),
        "-oConnectionAttempts=1".into(),
        "-oControlMaster=auto".into(),
        "-oControlPersist=300".into(),
        format!(
            "-oControlPath={}/.ssh/macluster/client-{}.sock",
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
            profile.cluster_uuid
        ),
        "-i".into(),
        profile.identity_file.clone(),
        "-oIdentitiesOnly=yes".into(),
        "-p".into(),
        profile.controller_port.to_string(),
        "-l".into(),
        profile.controller_user.clone(),
        profile.controller_host.clone(),
        profile.remote_binary.clone(),
        "--config".into(),
        profile.remote_config.clone(),
        "--state-dir".into(),
        profile.remote_state_dir.clone(),
        "internal".into(),
        "control-proxy".into(),
    ]
}

pub(crate) fn validate_proxy_args(args: &[String]) -> Result<(String, String), String> {
    if args.len() != 4 || args[0] != "--config" || args[2] != "--state-dir" {
        return Err("control-proxy requires --config PATH --state-dir PATH".into());
    }
    Ok((args[1].clone(), args[3].clone()))
}

#[cfg(test)]
mod tests {
    use crate::client_profile::ClientProfile;

    use super::remote_ssh_args;

    fn profile() -> ClientProfile {
        ClientProfile {
            version: 1,
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "home".into(),
            binding_digest: "b".repeat(64),
            namespace: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            descriptor_generation: 7,
            controller_host: "192.0.2.1".into(),
            controller_user: "mac".into(),
            controller_port: 2222,
            known_hosts_path: "/tmp/known_hosts".into(),
            identity_file: "/tmp/id_ed25519".into(),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/tmp/config.toml".into(),
            remote_state_dir: "/tmp/state".into(),
            last_used_unix_ms: 0,
            descriptor: None,
        }
    }

    #[test]
    fn remote_ssh_args_pin_host_and_identity() {
        let args = remote_ssh_args(&profile());
        assert!(args.contains(&"-oUserKnownHostsFile=/tmp/known_hosts".into()));
        assert!(args.contains(&"-oStrictHostKeyChecking=yes".into()));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-i", "/tmp/id_ed25519"])
        );
        assert!(args.windows(2).any(|pair| pair == ["-p", "2222"]));
        assert!(args.windows(2).any(|pair| pair == ["-l", "mac"]));
        assert!(args.iter().any(|value| value == "192.0.2.1"));
    }

    #[test]
    fn remote_proxy_command_uses_profile_paths() {
        let args = remote_ssh_args(&profile());
        let command = args.iter().rposition(|value| value == "192.0.2.1").unwrap() + 1;
        assert_eq!(
            &args[command..],
            &[
                "/opt/homebrew/bin/macluster",
                "--config",
                "/tmp/config.toml",
                "--state-dir",
                "/tmp/state",
                "internal",
                "control-proxy"
            ]
        );
    }

    #[test]
    fn control_proxy_validation_rejects_extra_arguments() {
        assert!(
            super::validate_proxy_args(&[
                "--config".into(),
                "x".into(),
                "--state-dir".into(),
                "y".into()
            ])
            .is_ok()
        );
        assert!(super::validate_proxy_args(&["extra".into()]).is_err());
    }
}
