//! Authenticated socket broker for the narrowly typed NFS administrator API.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use macluster_protocol::nfs_admin::{
    MAX_NFS_ADMIN_REQUEST_BYTES, NFS_ADMIN_SERVICE_VERSION, NfsAdminOperation, NfsAdminReply,
    NfsAdminRequest,
};
const SOCKET: &str = "/var/run/org.macluster.nfs-admin.sock";
const ADMIN_CLI: &str = "/Library/PrivilegedHelperTools/org.macluster.nfs-admin";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_ADMIN_STDERR_BYTES: usize = 256 * 1024;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
enum MountStatus {
    NotMounted,
    Expected,
    Conflict(String),
}

pub(crate) fn start(peer_uid: libc::uid_t) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("NFS administrator socket must run as root".into());
    }
    if !authorized_peer(peer_uid, peer_uid) {
        return Err("configured NFS administrator UID must be non-root".into());
    }
    let socket = Path::new(SOCKET);
    match fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(socket).map_err(|error| format!("remove stale NFS socket: {error}"))?;
        }
        Ok(_) => {
            return Err(format!(
                "refusing to replace non-socket {}",
                socket.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect NFS socket: {error}")),
    }
    let listener =
        UnixListener::bind(socket).map_err(|error| format!("bind NFS socket: {error}"))?;
    let account = unsafe { libc::getpwuid(peer_uid) };
    if account.is_null() {
        let _ = fs::remove_file(socket);
        return Err("configured NFS execution account no longer exists".into());
    }
    let group_id = unsafe { (*account).pw_gid };
    let socket_c = std::ffi::CString::new(SOCKET).expect("socket path has no NUL");
    if unsafe { libc::chown(socket_c.as_ptr(), peer_uid, group_id) } != 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_file(socket);
        return Err(format!("assign NFS socket to cluster account: {error}"));
    }
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("protect NFS socket: {error}"))?;

    thread::Builder::new()
        .name("macluster-nfs-admin".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(mut stream) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                        if let Err(error) = serve_client(&mut stream, peer_uid) {
                            eprintln!("macluster-power: NFS admin request failed: {error}");
                        }
                    }
                    Err(error) => eprintln!("macluster-power: accept NFS admin client: {error}"),
                }
            }
        })
        .map_err(|error| format!("start NFS socket worker: {error}"))?;
    Ok(())
}

pub(crate) fn client() -> Result<(), String> {
    let mut request_bytes = Vec::new();
    io::stdin()
        .take(MAX_NFS_ADMIN_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut request_bytes)
        .map_err(|error| format!("read NFS admin request: {error}"))?;
    if request_bytes.len() > MAX_NFS_ADMIN_REQUEST_BYTES {
        return Err("NFS_ADMIN_UNAVAILABLE: NFS admin request exceeds the 1 MiB limit".into());
    }
    let request: NfsAdminRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("invalid NFS admin request: {error}"))?;
    request.validate(unsafe { libc::geteuid() })?;
    let mut stream = UnixStream::connect(SOCKET).map_err(|error| {
        format!("NFS_ADMIN_UNAVAILABLE: privileged NFS service is not available: {error}")
    })?;
    stream
        .write_all(&request_bytes)
        .and_then(|_| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|error| format!("send NFS admin request: {error}"))?;
    let reply_bytes = read_limited(&mut stream, MAX_NFS_ADMIN_REQUEST_BYTES)?;
    let reply: NfsAdminReply = serde_json::from_slice(&reply_bytes)
        .map_err(|error| format!("invalid response from privileged NFS service: {error}"))?;
    println!(
        "{}",
        serde_json::to_string(&reply).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn serve_client(stream: &mut UnixStream, peer_uid: libc::uid_t) -> Result<(), String> {
    let actual_uid =
        peer_uid_for(stream).map_err(|error| format!("inspect socket peer: {error}"))?;
    if !authorized_peer(actual_uid, peer_uid) {
        return write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, "unauthorized local user"),
        );
    }
    let request_bytes = read_limited(stream, MAX_NFS_ADMIN_REQUEST_BYTES)?;
    let request: NfsAdminRequest = match serde_json::from_slice(&request_bytes) {
        Ok(request) => request,
        Err(error) => {
            return write_reply(
                stream,
                NfsAdminReply::failure(
                    NFS_ADMIN_SERVICE_VERSION,
                    format!("invalid request: {error}"),
                ),
            );
        }
    };
    if let Err(error) = request.validate(actual_uid) {
        return write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
        );
    }
    if let Err(error) = preflight_mounts(&request) {
        return write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
        );
    }
    let response = match run_root_admin_cli(&request_bytes, actual_uid) {
        Ok(reply) => reply,
        Err(error) => NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
    };
    write_reply(stream, response)
}

fn preflight_mounts(request: &NfsAdminRequest) -> Result<(), String> {
    let mounts = match &request.operation {
        NfsAdminOperation::Mount { mounts } | NfsAdminOperation::Unmount { mounts, .. } => mounts,
        NfsAdminOperation::Ping
        | NfsAdminOperation::RemoveMarker { .. }
        | NfsAdminOperation::CheckMarker { .. }
        | NfsAdminOperation::CheckAlias { .. }
        | NfsAdminOperation::UpdateExports { .. } => return Ok(()),
    };
    if mounts.is_empty() {
        return Ok(());
    }
    let output = run_command("/sbin/mount", &[], Duration::from_secs(10))?;
    if !output.status.success() {
        return Err(format!(
            "cannot inspect current mounts: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let table = String::from_utf8_lossy(&output.stdout);
    for mount in mounts {
        match classify_mount(&table, &mount.source, &mount.target) {
            MountStatus::NotMounted | MountStatus::Expected => {}
            MountStatus::Conflict(source) => {
                return Err(format!(
                    "mount point {} is occupied by {source}; refusing the NFS request",
                    mount.target
                ));
            }
        }
    }
    Ok(())
}

fn run_root_admin_cli(request: &[u8], peer_uid: libc::uid_t) -> Result<NfsAdminReply, String> {
    let metadata = fs::symlink_metadata(ADMIN_CLI)
        .map_err(|error| format!("inspect trusted NFS admin executable: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err("trusted NFS admin executable has unsafe ownership or permissions".into());
    }
    let mut command = Command::new(ADMIN_CLI);
    command
        .args(["internal", "nfs-admin", "--peer-uid", &peer_uid.to_string()])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", "/var/root")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_child_bounded(command, request, REQUEST_TIMEOUT)?;
    let reply: NfsAdminReply = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "trusted NFS admin command returned no protocol response ({}): {} ({error})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    Ok(reply)
}

fn run_child_bounded(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("start NFS admin: {error}"))?;
    let process_group = child.id() as libc::pid_t;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "trusted NFS admin stdout was not piped".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "trusted NFS admin stderr was not piped".to_owned())?;
    let stdout_reader = thread::spawn(move || read_capped(stdout, MAX_NFS_ADMIN_REQUEST_BYTES));
    let stderr_reader = thread::spawn(move || read_capped(stderr, MAX_ADMIN_STDERR_BYTES));
    let writer = child.stdin.take().map(|mut stdin| {
        let request = input.to_vec();
        thread::spawn(move || stdin.write_all(&request))
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                terminate_child_group(process_group, &mut child);
                reap_or_detach(Some(child), stdout_reader, stderr_reader, writer);
                return Err("trusted NFS admin command timed out".into());
            }
            Err(error) => {
                terminate_child_group(process_group, &mut child);
                reap_or_detach(Some(child), stdout_reader, stderr_reader, writer);
                return Err(format!("wait for trusted NFS admin command: {error}"));
            }
        }
    };
    if !wait_for_pipe_threads(
        &stdout_reader,
        &stderr_reader,
        writer.as_ref(),
        PIPE_DRAIN_TIMEOUT,
    ) {
        signal_process_group(process_group, libc::SIGKILL);
        reap_or_detach(None, stdout_reader, stderr_reader, writer);
        return Err("trusted NFS admin child exited while subprocesses kept its pipes open".into());
    }
    let stdout = join_reader(stdout_reader, "trusted NFS admin stdout")?;
    let stderr = join_reader(stderr_reader, "trusted NFS admin stderr")?;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| "trusted NFS admin input writer panicked".to_owned())?
            .map_err(|error| format!("send NFS admin request to trusted executable: {error}"))?;
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

type PipeReader = thread::JoinHandle<io::Result<Vec<u8>>>;
type PipeWriter = thread::JoinHandle<io::Result<()>>;

fn read_capped(mut reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(kept);
        }
        let remaining = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
}

fn pipe_threads_finished(
    stdout: &PipeReader,
    stderr: &PipeReader,
    writer: Option<&PipeWriter>,
) -> bool {
    stdout.is_finished()
        && stderr.is_finished()
        && writer.is_none_or(thread::JoinHandle::is_finished)
}

fn wait_for_pipe_threads(
    stdout: &PipeReader,
    stderr: &PipeReader,
    writer: Option<&PipeWriter>,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while !pipe_threads_finished(stdout, stderr, writer) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    pipe_threads_finished(stdout, stderr, writer)
}

fn join_reader(reader: PipeReader, label: &str) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("{label} reader panicked"))?
        .map_err(|error| format!("read {label}: {error}"))
}

fn reap_or_detach(
    child: Option<std::process::Child>,
    stdout: PipeReader,
    stderr: PipeReader,
    writer: Option<PipeWriter>,
) {
    let _ = thread::Builder::new()
        .name("macluster-nfs-admin-reaper".into())
        .spawn(move || {
            if let Some(mut child) = child {
                let _ = child.wait();
            }
            let _ = stdout.join();
            let _ = stderr.join();
            if let Some(writer) = writer {
                let _ = writer.join();
            }
        });
}

fn terminate_child_group(process_group: libc::pid_t, child: &mut std::process::Child) {
    signal_process_group(process_group, libc::SIGTERM);
    let grace = Instant::now() + Duration::from_millis(150);
    while Instant::now() < grace && child.try_wait().ok().flatten().is_none() {
        thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().ok().flatten().is_none() {
        signal_process_group(process_group, libc::SIGKILL);
    }
}

fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) {
    if process_group > 1 {
        unsafe {
            libc::kill(-process_group, signal);
        }
    }
}

fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    run_child_bounded(command, &[], timeout)
}

fn read_limited(stream: &mut UnixStream, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    stream
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read NFS admin socket: {error}"))?;
    if bytes.len() > limit {
        return Err("NFS admin request or response exceeds the 1 MiB limit".into());
    }
    Ok(bytes)
}

fn write_reply(stream: &mut UnixStream, reply: NfsAdminReply) -> Result<(), String> {
    let bytes = serde_json::to_vec(&reply).map_err(|error| error.to_string())?;
    stream
        .write_all(&bytes)
        .map_err(|error| format!("write NFS admin response: {error}"))
}

fn peer_uid_for(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result =
        unsafe { libc::getpeereid(std::os::fd::AsRawFd::as_raw_fd(stream), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn authorized_peer(actual_uid: libc::uid_t, expected_uid: libc::uid_t) -> bool {
    actual_uid == expected_uid && expected_uid != 0
}

fn classify_mount(output: &str, expected_source: &str, target: &str) -> MountStatus {
    let mut found = None;
    for line in output.lines() {
        let Some((source, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mountpoint, filesystem)) = rest.split_once(" (") else {
            continue;
        };
        if mountpoint != target || !filesystem.ends_with(')') {
            continue;
        }
        if found.is_some() {
            return MountStatus::Conflict("multiple mounts at the requested path".into());
        }
        let fs_type = filesystem
            .strip_suffix(')')
            .and_then(|value| value.split(',').next())
            .map(str::trim);
        found = Some(if source == expected_source && fs_type == Some("nfs") {
            MountStatus::Expected
        } else {
            MountStatus::Conflict(source.to_owned())
        });
    }
    found.unwrap_or(MountStatus::NotMounted)
}

#[cfg(test)]
mod tests {
    use super::{MountStatus, authorized_peer, classify_mount, run_child_bounded};
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn expected_mount_requires_exact_source_target_and_nfs_filesystem() {
        let expected =
            "192.0.2.1:/Users/Shared/data on /Users/Shared/data (nfs, nodev, nosuid)\n";
        assert_eq!(
            classify_mount(
                expected,
                "192.0.2.1:/Users/Shared/data",
                "/Users/Shared/data"
            ),
            MountStatus::Expected
        );
        assert_eq!(
            classify_mount(
                "192.0.2.9:/other on /Users/Shared/data (nfs, nodev)\n",
                "192.0.2.1:/Users/Shared/data",
                "/Users/Shared/data"
            ),
            MountStatus::Conflict("192.0.2.9:/other".into())
        );
        assert_eq!(
            classify_mount(
                "/dev/disk3s5 on /Users/Shared/data (apfs, local)\n",
                "192.0.2.1:/Users/Shared/data",
                "/Users/Shared/data"
            ),
            MountStatus::Conflict("/dev/disk3s5".into())
        );
        assert_eq!(
            classify_mount("", "192.0.2.1:/Users/Shared/data", "/Users/Shared/data"),
            MountStatus::NotMounted
        );
    }

    #[test]
    fn only_the_configured_non_root_uid_can_use_the_service() {
        assert!(authorized_peer(501, 501));
        assert!(!authorized_peer(502, 501));
        assert!(!authorized_peer(0, 501));
    }

    #[test]
    fn bounded_admin_child_captures_mount_preflight_output() {
        let mut command = Command::new("/bin/echo");
        command.arg("mounted");

        let output = run_child_bounded(command, b"", Duration::from_secs(1))
            .expect("bounded command should capture its output");

        assert_eq!(output.stdout, b"mounted\n");
    }

    #[test]
    fn bounded_admin_child_does_not_wait_for_a_descendant_holding_output_pipes() {
        let pid_file = std::env::temp_dir().join(format!(
            "macluster-helper-descendant-{}.pid",
            std::process::id()
        ));
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "python3 -c 'import os, subprocess; child = subprocess.Popen([\"/bin/sleep\", \"5\"], start_new_session=True); open(os.environ[\"MACLUSTER_TEST_PID_FILE\"], \"w\").write(str(child.pid))'",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("MACLUSTER_TEST_PID_FILE", &pid_file);
        let started = Instant::now();

        let result = run_child_bounded(command, b"{}", Duration::from_millis(100));
        let elapsed = started.elapsed();
        if let Ok(pid) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid.trim().parse::<libc::pid_t>() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = std::fs::remove_file(pid_file);

        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
        assert!(
            result.is_err(),
            "an inherited pipe must not turn into success: {result:?}"
        );
    }
}
