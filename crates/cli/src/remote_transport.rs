use std::{
    cell::Cell,
    fs,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use crate::client_profile::ClientProfile;

pub(crate) struct RemoteControlStream {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    timeout: Cell<Duration>,
}

impl RemoteControlStream {
    pub(crate) fn connect(
        profile: &ClientProfile,
        ensure_client_storage: bool,
        timeout: Duration,
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
            timeout: Cell::new(timeout),
        })
    }

    pub(crate) fn set_timeout(&self, timeout: Duration) {
        self.timeout.set(timeout);
    }

    fn wait_ready(&mut self, descriptor: i32, events: i16) -> io::Result<()> {
        match wait_fd(descriptor, events, self.timeout.get()) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Err(io::Error::new(
                    error.kind(),
                    format!("remote control connection timed out: {error}"),
                ))
            }
        }
    }
}

impl Read for RemoteControlStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.wait_ready(self.output.as_raw_fd(), libc::POLLIN)?;
        self.output.read(buffer)
    }
}

impl Write for RemoteControlStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.wait_ready(self.input.as_raw_fd(), libc::POLLOUT)?;
        self.input.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.input.flush()
    }
}

fn wait_fd(descriptor: i32, events: i16, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "descriptor did not become ready before the deadline",
            ));
        }
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if result > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file descriptor is invalid",
                ));
            }
            return Ok(());
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "descriptor did not become ready before the deadline",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

impl Drop for RemoteControlStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn control_socket_path(profile: &ClientProfile) -> io::Result<String> {
    control_socket_path_for(
        &profile.cluster_uuid,
        &profile.controller_user,
        &profile.controller_host,
        profile.controller_port,
        &profile.identity_file,
    )
}

pub(crate) fn control_socket_path_for(
    cluster_uuid: &str,
    controller_user: &str,
    controller_host: &str,
    controller_port: u16,
    identity_file: &str,
) -> io::Result<String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let endpoint = format!(
        "{}\0{}\0{}\0{}",
        controller_user, controller_host, controller_port, identity_file
    );
    let digest = macluster_protocol::framing::sha256_hex(endpoint.as_bytes())
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(home
        .join(".ssh/macluster")
        .join(format!("mc-{}-{}.sock", &cluster_uuid[..8], &digest[..16]))
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
    ]);
    let mut remote = vec![
        profile.remote_binary.clone(),
        "--config".into(),
        profile.remote_config.clone(),
        "--state-dir".into(),
        profile.remote_state_dir.clone(),
        "internal".into(),
        "control-proxy".into(),
    ];
    if ensure_client_storage && profile.mounts_enabled {
        remote.extend([
            "--client-storage-id".into(),
            profile.nfs_client_id.clone(),
            "--registered-client-ip".into(),
            profile.nfs_client_ip.clone(),
        ]);
    }
    args.push(
        remote
            .iter()
            .map(|value| crate::node_admin::shell_quote(value))
            .collect::<Vec<_>>()
            .join(" "),
    );
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
    use std::{fs, io, os::unix::fs::PermissionsExt, process::Command};

    use crate::client_profile::ClientProfile;
    use macluster_protocol::identifiers::Id128;

    use super::remote_ssh_args;

    fn profile() -> ClientProfile {
        ClientProfile {
            version: 2,
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
            mounted_descriptor: None,
            transition_mount_descriptors: vec![],
            retired_access: vec![],
            leave_phase: None,
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
            &args[command],
            "/opt/homebrew/bin/macluster --config /tmp/config.toml --state-dir /tmp/state internal control-proxy"
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

    #[test]
    fn remote_command_survives_ssh_style_shell_joining() {
        let root = std::env::temp_dir().join(format!("macluster-remote-args-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("fake command; untouched");
        let config = root.join("config with spaces");
        let state = root.join("state with spaces");
        fs::write(
            &binary,
            "#!/bin/sh\nprintf '%s\\0' \"$0\"\nfor argument in \"$@\"; do printf '%s\\0' \"$argument\"; done\n",
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();

        let mut value = profile();
        value.remote_binary = binary.to_string_lossy().into_owned();
        value.remote_config = config.to_string_lossy().into_owned();
        value.remote_state_dir = state.to_string_lossy().into_owned();
        let args = remote_ssh_args(&value, true);
        let command = args.last().expect("remote command argument");
        let output = Command::new("/bin/sh")
            .args(["-c", command])
            .output()
            .expect("run remote command through a shell");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let arguments = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| String::from_utf8(argument.to_vec()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            vec![
                value.remote_binary,
                "--config".into(),
                value.remote_config,
                "--state-dir".into(),
                value.remote_state_dir,
                "internal".into(),
                "control-proxy".into(),
                "--client-storage-id".into(),
                value.nfs_client_id,
                "--registered-client-ip".into(),
                value.nfs_client_ip,
            ]
        );
        assert!(!root.join("untouched").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn silent_remote_pipe_returns_timed_out() {
        let mut descriptors = [0; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let result = super::wait_fd(
            descriptors[0],
            libc::POLLIN,
            std::time::Duration::from_millis(50),
        );
        unsafe {
            libc::close(descriptors[0]);
            libc::close(descriptors[1]);
        }
        assert_eq!(
            result.expect_err("an idle pipe must time out").kind(),
            io::ErrorKind::TimedOut
        );
    }
}
