use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use crate::client_profile::ClientProfile;

pub(crate) struct RemoteControlStream {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl RemoteControlStream {
    pub(crate) fn connect(
        profile: &ClientProfile,
        ensure_client_storage: bool,
    ) -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        let directory = home.join(".ssh/macluster");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let mut child = Command::new("/usr/bin/ssh")
            .args(remote_ssh_args(profile, ensure_client_storage))
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

pub(crate) fn control_socket_path(profile: &ClientProfile) -> io::Result<String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let endpoint = format!(
        "{}\0{}\0{}\0{}",
        profile.controller_user,
        profile.controller_host,
        profile.controller_port,
        profile.identity_file
    );
    let digest = macluster_protocol::framing::sha256_hex(endpoint.as_bytes())
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(home
        .join(".ssh/macluster")
        .join(format!(
            "mc-{}-{}.sock",
            &profile.cluster_uuid[..8],
            &digest[..16]
        ))
        .to_string_lossy()
        .into_owned())
}

pub(crate) fn remote_ssh_args(profile: &ClientProfile, ensure_client_storage: bool) -> Vec<String> {
    let mut args = vec![
        "-T".into(),
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
    let control_path = control_socket_path(profile)
        .map(|path| format!("-oControlPath={path}"))
        .unwrap_or_else(|_| "-oControlMaster=no".into());
    args.push(control_path);
    args.extend([
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
    ]);
    if ensure_client_storage && profile.mounts_enabled {
        args.extend([
            "--client-storage-id".into(),
            profile.nfs_client_id.clone(),
            "--registered-client-ip".into(),
            profile.nfs_client_ip.clone(),
        ]);
    }
    args
}

pub(crate) struct ProxyArgs {
    pub(crate) config_path: String,
    pub(crate) state_dir: String,
    pub(crate) client_storage: Option<(String, String)>,
}

pub(crate) fn validate_proxy_args(args: &[String]) -> Result<ProxyArgs, String> {
    if args.len() != 4 && args.len() != 8 {
        return Err("control-proxy requires --config PATH --state-dir PATH [--client-storage-id ID --registered-client-ip IP]".into());
    }
    if args[0] != "--config" || args[2] != "--state-dir" {
        return Err("control-proxy requires --config PATH --state-dir PATH".into());
    }
    let client_storage = if args.len() == 8 {
        if args[4] != "--client-storage-id" || args[6] != "--registered-client-ip" {
            return Err("control-proxy received invalid client-storage arguments".into());
        }
        Some((args[5].clone(), args[7].clone()))
    } else {
        None
    };
    Ok(ProxyArgs {
        config_path: args[1].clone(),
        state_dir: args[3].clone(),
        client_storage,
    })
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
            mounts_enabled: true,
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
            last_used_unix_ms: 0,
            descriptor: None,
        }
    }

    #[test]
    fn remote_ssh_args_pin_host_and_identity() {
        let args = remote_ssh_args(&profile(), false);
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
        let args = remote_ssh_args(&profile(), false);
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
        assert!(
            super::validate_proxy_args(&[
                "--config".into(),
                "x".into(),
                "--state-dir".into(),
                "y".into(),
                "--client-storage-id".into(),
                "client-test".into(),
                "--registered-client-ip".into(),
                "192.0.2.10".into(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn control_socket_identity_changes_with_the_controller_endpoint() {
        let first = profile();
        let mut second = first.clone();
        second.controller_host = "192.0.2.2".into();
        let control_path = |args: Vec<String>| {
            args.into_iter()
                .find(|argument| argument.starts_with("-oControlPath="))
                .expect("SSH arguments include a control path")
        };
        assert_ne!(
            control_path(remote_ssh_args(&first, false)),
            control_path(remote_ssh_args(&second, false))
        );
    }
}
