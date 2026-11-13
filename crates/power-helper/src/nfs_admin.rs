//! Authenticated socket broker for the narrowly typed NFS administrator API.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

use super::helper_update;
use macluster_protocol::nfs_admin::{
    MAX_NFS_ADMIN_REQUEST_BYTES, NFS_ADMIN_SERVICE_VERSION, NfsAdminOperation, NfsAdminReply,
    NfsAdminRequest,
};
use serde::Serialize;
const SOCKET: &str = "/var/run/org.macluster.nfs-admin.sock";
const ADMIN_CLI: &str = "/Library/PrivilegedHelperTools/org.macluster.macluster";
const REBOOT_AUDIT_ROOT: &str = "/var/db/macluster/nfs-reboot";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_ADMIN_STDERR_BYTES: usize = 256 * 1024;
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
enum MountStatus {
    NotMounted,
    Expected,
    Conflict(String),
}

#[derive(Serialize)]
struct NfsRebootAudit<'a> {
    operation_id: &'a str,
    boot_id: &'a str,
    requested_unix_ms: u64,
}

pub fn apply_privileged_nfs_reboot(
    operation_id: &str,
    expected_boot_id: &str,
) -> Result<(), String> {
    apply_privileged_nfs_reboot_at(
        operation_id,
        expected_boot_id,
        Path::new(REBOOT_AUDIT_ROOT),
        current_boot_id,
        schedule_system_reboot,
    )
}

fn apply_privileged_nfs_reboot_at(
    operation_id: &str,
    expected_boot_id: &str,
    audit_root: &Path,
    read_current_boot_id: impl FnOnce() -> Result<String, String>,
    schedule_reboot: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let operation_id = macluster_protocol::identifiers::Id128::parse(operation_id)
        .map_err(|_| "NFS reboot operation ID is invalid".to_owned())?
        .to_string();
    if expected_boot_id.is_empty()
        || expected_boot_id.len() > 256
        || expected_boot_id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("NFS reboot boot ID is invalid".into());
    }
    let current_boot_id = read_current_boot_id()?;
    if current_boot_id != expected_boot_id {
        return Err(format!(
            "node boot identity changed; refusing to replay NFS reboot operation {operation_id}"
        ));
    }
    let audit_path = audit_root.join(format!("{operation_id}.json"));
    if audit_path.exists() {
        return Ok(());
    }
    if !audit_root.exists() {
        fs::create_dir_all(audit_root)
            .map_err(|error| format!("create NFS reboot audit directory: {error}"))?;
        fs::set_permissions(audit_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect NFS reboot audit directory: {error}"))?;
    }
    let temp = audit_path.with_extension("next");
    let requested_unix_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let audit = NfsRebootAudit {
        operation_id: &operation_id,
        boot_id: &current_boot_id,
        requested_unix_ms,
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|error| format!("open NFS reboot audit: {error}"))?;
    file.write_all(
        &serde_json::to_vec(&audit).map_err(|error| format!("encode NFS reboot audit: {error}"))?,
    )
    .and_then(|()| file.sync_all())
    .map_err(|error| format!("write NFS reboot audit: {error}"))?;
    fs::rename(&temp, &audit_path).map_err(|error| format!("commit NFS reboot audit: {error}"))?;
    if let Err(error) = schedule_reboot() {
        let _ = fs::remove_file(audit_path);
        return Err(error);
    }
    Ok(())
}

fn current_boot_id() -> Result<String, String> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.boottime"])
        .output()
        .map_err(|error| format!("read node boot identity: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read node boot identity exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let boot_id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if boot_id.is_empty() {
        return Err("node boot identity is empty".into());
    }
    Ok(boot_id)
}

fn schedule_system_reboot() -> Result<(), String> {
    let output = Command::new("/sbin/shutdown")
        .args(["-r", "+1"])
        .output()
        .map_err(|error| format!("schedule node reboot: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "schedule node reboot exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
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
                        match serve_client(&mut stream, peer_uid) {
                            Ok(true) => {
                                // The updater has replaced this executable. Let the
                                // response reach SSH before exiting; launchd KeepAlive
                                // then starts the newly installed version.
                                thread::sleep(Duration::from_millis(150));
                                std::process::exit(0);
                            }
                            Ok(false) => {}
                            Err(error) => {
                                eprintln!("macluster: NFS admin request failed: {error}");
                            }
                        }
                    }
                    Err(error) => eprintln!("macluster: accept NFS admin client: {error}"),
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

fn serve_client(stream: &mut UnixStream, peer_uid: libc::uid_t) -> Result<bool, String> {
    let actual_uid =
        peer_uid_for(stream).map_err(|error| format!("inspect socket peer: {error}"))?;
    if !authorized_peer(actual_uid, peer_uid) {
        write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, "unauthorized local user"),
        )?;
        return Ok(false);
    }
    let request_bytes = read_limited(stream, MAX_NFS_ADMIN_REQUEST_BYTES)?;
    let request: NfsAdminRequest = match serde_json::from_slice(&request_bytes) {
        Ok(request) => request,
        Err(error) => {
            write_reply(
                stream,
                NfsAdminReply::failure(
                    NFS_ADMIN_SERVICE_VERSION,
                    format!("invalid request: {error}"),
                ),
            )?;
            return Ok(false);
        }
    };
    if let Err(error) = request.validate(actual_uid) {
        write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
        )?;
        return Ok(false);
    }
    if let NfsAdminOperation::UpdateHelpers {
        manifest,
        signature,
        stage_dir,
    } = &request.operation
    {
        let result = helper_update::apply(actual_uid, manifest, signature, stage_dir);
        let reply = match &result {
            Ok(_) => NfsAdminReply::success(NFS_ADMIN_SERVICE_VERSION),
            Err(error) => NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error.clone()),
        };
        let reply_result = write_reply(stream, reply);
        return match helper_update_response_action(result, reply_result) {
            HelperUpdateResponseAction::Restart => Ok(true),
            HelperUpdateResponseAction::Continue => Ok(false),
            HelperUpdateResponseAction::Fail(error) => Err(error),
        };
    }
    if let NfsAdminOperation::ForgetClusterUpdater { cluster_id } = &request.operation {
        let result = helper_update::forget_cluster(actual_uid, cluster_id);
        let reply = match &result {
            Ok(()) => NfsAdminReply::success(NFS_ADMIN_SERVICE_VERSION),
            Err(error) => NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error.clone()),
        };
        write_reply(stream, reply)?;
        result?;
        return Ok(false);
    }
    if let Err(error) = preflight_mounts(&request) {
        write_reply(
            stream,
            NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
        )?;
        return Ok(false);
    }
    let response = match run_root_admin_cli(&request_bytes, actual_uid) {
        Ok(reply) => reply,
        Err(error) => NfsAdminReply::failure(NFS_ADMIN_SERVICE_VERSION, error),
    };
    write_reply(stream, response)?;
    Ok(false)
}

#[derive(Debug, Eq, PartialEq)]
enum HelperUpdateResponseAction {
    Continue,
    Restart,
    Fail(String),
}

fn helper_update_response_action(
    update_result: Result<bool, String>,
    reply_result: Result<(), String>,
) -> HelperUpdateResponseAction {
    match (update_result, reply_result) {
        (Ok(true), _) => HelperUpdateResponseAction::Restart,
        (Ok(false), Ok(())) => HelperUpdateResponseAction::Continue,
        (Ok(false), Err(error)) | (Err(error), Ok(())) => HelperUpdateResponseAction::Fail(error),
        (Err(update_error), Err(reply_error)) => HelperUpdateResponseAction::Fail(format!(
            "{update_error}; could not send the privileged helper update response: {reply_error}"
        )),
    }
}

fn preflight_mounts(request: &NfsAdminRequest) -> Result<(), String> {
    let mounts = match &request.operation {
        NfsAdminOperation::Mount { mounts } | NfsAdminOperation::Unmount { mounts, .. } => mounts,
        NfsAdminOperation::Ping
        | NfsAdminOperation::RemoveMarker { .. }
        | NfsAdminOperation::CheckMarker { .. }
        | NfsAdminOperation::CheckAlias { .. }
        | NfsAdminOperation::UpdateExports { .. }
        | NfsAdminOperation::RemoveExports { .. }
        | NfsAdminOperation::UpdateHelpers { .. }
        | NfsAdminOperation::ForgetClusterUpdater { .. }
        | NfsAdminOperation::RebootNode { .. } => return Ok(()),
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
    let mut matches = 0_usize;
    let mut all_expected = true;
    let mut first_source = None;
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
        matches += 1;
        first_source.get_or_insert_with(|| source.to_owned());
        let fs_type = filesystem
            .strip_suffix(')')
            .and_then(|value| value.split(',').next())
            .map(str::trim);
        all_expected &= source == expected_source && fs_type == Some("nfs");
    }
    if matches == 0 {
        MountStatus::NotMounted
    } else if all_expected {
        MountStatus::Expected
    } else if matches > 1 {
        MountStatus::Conflict("multiple mounts at the requested path".into())
    } else {
        MountStatus::Conflict(first_source.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HelperUpdateResponseAction, MountStatus, apply_privileged_nfs_reboot_at, authorized_peer,
        classify_mount, helper_update_response_action, run_child_bounded,
    };
    use std::{
        fs,
        process::{Command, Stdio},
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, Instant},
    };

    #[test]
    fn expected_mount_requires_exact_source_target_and_nfs_filesystem() {
        let expected = "192.0.2.1:/Users/Shared/data on /Users/Shared/data (nfs, nodev, nosuid)\n";
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
                concat!(
                    "192.0.2.1:/Users/Shared/data on /Users/Shared/data (nfs, nodev)\n",
                    "192.0.2.1:/Users/Shared/data on /Users/Shared/data (nfs, nodev)\n"
                ),
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
    fn privileged_nfs_reboot_requires_boot_identity_and_is_idempotent() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-reboot-{}",
            macluster_protocol::identifiers::Id128::random()
        ));
        let calls = AtomicUsize::new(0);
        let error = apply_privileged_nfs_reboot_at(
            "00000000-0000-4000-8000-000000000001",
            "stale-boot",
            &root,
            || Ok("current-boot".into()),
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("boot identity changed"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        for _ in 0..2 {
            apply_privileged_nfs_reboot_at(
                "00000000-0000-4000-8000-000000000001",
                "current-boot",
                &root,
                || Ok("current-boot".into()),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_the_configured_non_root_uid_can_use_the_service() {
        assert!(authorized_peer(501, 501));
        assert!(!authorized_peer(502, 501));
        assert!(!authorized_peer(0, 501));
    }

    #[test]
    fn committed_helper_update_restarts_even_if_the_client_disconnects_before_reply() {
        assert_eq!(
            helper_update_response_action(Ok(true), Err("broken pipe".into())),
            HelperUpdateResponseAction::Restart
        );
        assert_eq!(
            helper_update_response_action(Ok(false), Ok(())),
            HelperUpdateResponseAction::Continue
        );
        assert_eq!(
            helper_update_response_action(Ok(false), Err("broken pipe".into())),
            HelperUpdateResponseAction::Fail("broken pipe".into())
        );
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
        if let Ok(pid) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = pid.trim().parse::<libc::pid_t>()
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
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
