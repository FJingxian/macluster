mod common;

use common::macluster_command;
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::symlink,
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_cli::run_with;
use macluster_controller::wake::ControllerWake;
use macluster_core::storage::Storage;
use macluster_protocol::framing::sha256_hex;
use macluster_protocol::types::JobState;

#[test]
fn read_queries_do_not_wait_for_controller_or_remote_agents() {
    use macluster_core::service::ServiceBinding;
    use macluster_protocol::{identifiers::RequestId, types::JobSpec};
    use std::os::unix::net::UnixListener;
    let (root, shared, config) = fixture();
    let state = root.join("controller");
    let storage = Storage::open(&state).unwrap();
    let spec: JobSpec = serde_json::from_value(serde_json::json!({
        "queue":"mini01", "node":null, "name":"read-query", "cwd":shared,
        "stdout_path":shared.join("jobs/1/stdout.log"), "stderr_path":shared.join("jobs/1/stderr.log"),
        "walltime_secs":null, "snapshot":storage.stage_snapshot(b"echo done\n").unwrap(), "mode":"batch", "env":{}
    })).unwrap();
    let request_id = RequestId::random();
    let job = storage.submit_once(request_id, spec).unwrap();
    drop(storage);
    let binding = ServiceBinding::load(&config, &state).unwrap();
    binding.prepare_endpoint_dir().unwrap();
    let listener = UnixListener::bind(binding.endpoint_path()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let id = job.id.to_string();
    let request = request_id.to_string();
    for args in [
        vec!["mjob"],
        vec!["mjob", "--json"],
        vec!["mjob", "--all"],
        vec!["mjob", "--state", "Pending"],
        vec!["mjob", &id, "--json"],
        vec!["mjob", "--request-id", &request, "--json"],
        vec!["mqueue"],
        vec!["mqueue", "--json"],
        vec!["mqueue", "--jobs"],
        vec!["mqueue", "-q", "mini01", "--json"],
    ] {
        let mut command = macluster_command();
        command.env_remove("MACLUSTER_DISABLE_SERVICE_AUTOSTART");
        command
            .args([
                "--config",
                config.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
            ])
            .args(&args);
        let output = macluster_controller::transport::run_child_bounded(
            command,
            None,
            Duration::from_secs(2),
        )
        .expect("local queries must finish without waiting for the controller");
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
        if args[0] == "mqueue" && args.contains(&"--json") {
            let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(rows[0]["pending"], 1);
            assert_eq!(rows[0]["running"], 0);
        }
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    drop(listener);
    let _ = fs::remove_file(binding.endpoint_path());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn job_listing_before_first_job_does_not_create_controller_state() {
    let (root, _, config) = fixture();
    let state = root.join("controller");
    for command in ["mjob", "mqueue"] {
        let output = macluster_command()
            .args([
                "--config",
                config.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                command,
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if command == "mjob" {
            assert_eq!(value, serde_json::json!([]));
        } else {
            assert_eq!(value[0]["pending"], 0);
        }
        assert!(!state.exists());
    }
    let status = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "controller",
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(String::from_utf8_lossy(&status.stdout).contains("Pending: 0"));
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn queue_watch_observes_local_commits_without_controller() {
    use macluster_protocol::{identifiers::RequestId, types::JobSpec};
    let (root, shared, config) = fixture();
    let state = root.join("controller");
    let storage = Storage::open(&state).unwrap();
    let spec: JobSpec = serde_json::from_value(serde_json::json!({
        "queue":"mini01", "node":null, "name":"watch", "cwd":shared,
        "stdout_path":shared.join("stdout.log"), "stderr_path":shared.join("stderr.log"),
        "walltime_secs":null, "snapshot":storage.stage_snapshot(b"echo done\n").unwrap(), "mode":"batch", "env":{}
    })).unwrap();
    let job = storage.submit_once(RequestId::random(), spec).unwrap();
    let mut child = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mqueue",
            "--watch",
            "1",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        for value in serde_json::Deserializer::from_reader(stdout)
            .into_iter::<serde_json::Value>()
            .take(2)
        {
            if sender.send(value).is_err() {
                break;
            }
        }
    });
    let first = receiver.recv_timeout(Duration::from_secs(3));
    let cancellation = storage.request_cancel(job.id, false);
    let second = receiver.recv_timeout(Duration::from_secs(3));
    let _ = child.kill();
    child.wait().unwrap();
    reader.join().unwrap();
    cancellation.unwrap();
    assert_eq!(first.unwrap().unwrap()[0]["pending"], 1);
    assert_eq!(second.unwrap().unwrap()[0]["pending"], 0);
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn regression_stderr_filter_ignores_stream_markers_in_stdout_body() {
    use macluster_protocol::{
        identifiers::{NodeId, RequestId},
        types::JobSpec,
    };
    let (root, shared, config) = fixture();
    let state = root.join("controller");
    let storage = Storage::open(&state).unwrap();
    let snapshot = storage.stage_snapshot(b"echo done\n").unwrap();
    let spec: JobSpec = serde_json::from_value(serde_json::json!({
        "queue":"mini01", "node":null, "name":"filter", "cwd":shared,
        "stdout_path":shared.join("jobs/1/stdout.log"), "stderr_path":shared.join("jobs/1/stderr.log"),
        "walltime_secs":null, "snapshot":snapshot, "mode":"batch",
        "env":{"MCLUSTER_INTERNAL_VERBOSE_LOG":"1", "MCLUSTER_INTERNAL_VERBOSE_LOG_ROOT":shared}
    })).unwrap();
    let job = storage.submit_once(RequestId::random(), spec).unwrap();
    storage
        .reserve_job(job.id, NodeId::new("mini01-a").unwrap())
        .unwrap();
    storage.mark_running(job.id).unwrap();
    storage
        .finish_job(job.id, JobState::Completed, Some(0), None)
        .unwrap();
    drop(storage);
    let dir = shared.join("jobs/1");
    fs::create_dir_all(&dir).unwrap();
    let ordinary =
        "[2026-10-26T12:00:00.000+08:00 / MEM 0.01GiB / CPU 1.0%] [stdout] body ] [stderr] fake\n";
    let error = "[2026-10-26T12:00:00.000+08:00 / MEM 0.01GiB / CPU 1.0%] [stderr] actual error\n";
    let continued =
        "[2026-10-26T12:00:00.000+08:00 / MEM 0.01GiB / CPU 1.0%] [stderr:continued] tail\n";
    fs::write(
        dir.join("monitor.log"),
        format!("{ordinary}{error}{continued}"),
    )
    .unwrap();
    fs::write(dir.join("summary.json"), "{\"annotation_failed\":null}").unwrap();
    let result = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mjob",
            "--log",
            "1",
            "--stderr",
        ])
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        format!("{error}{continued}")
    );
}

#[test]
fn capabilities_report_primary_storage_source_support() {
    let output = macluster_command()
        .args(["internal", "capabilities", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "config.primary-storage-source.v1")
    );
}

#[test]
fn standalone_binary_includes_its_power_helper() {
    let (root, _shared, _config) = fixture();
    let standalone = root.join("download");
    fs::create_dir(&standalone).unwrap();
    let binary = standalone.join("macluster");
    fs::copy(env!("CARGO_BIN_EXE_macluster"), &binary).unwrap();
    assert!(!standalone.join("macluster-power").exists());
    let output = Command::new(&binary)
        .args(["internal", "power-helper", "--version"])
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("macluster-power {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn enrollment_config_commit_honors_controller_lock_and_original_digest() {
    use macluster_core::maintenance::MaintenanceLock;
    let (root, _shared, config) = fixture();
    let before = fs::read(&config).unwrap();
    let baseline = sha256_hex(&before).unwrap();
    let candidate = [before.as_slice(), b"\n# refreshed enrollment\n"].concat();
    let staged = root.join("staged-config.toml");
    fs::write(&staged, &candidate).unwrap();
    let commit = |baseline: &str| {
        macluster_command()
            .args(["internal", "commit-enrollment-config", "--destination"])
            .arg(&config)
            .arg("--staged")
            .arg(&staged)
            .arg("--baseline")
            .arg(baseline)
            .output()
            .unwrap()
    };
    let lock = MaintenanceLock::shared(&config).unwrap();
    let blocked = commit(&baseline);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("in use by a controller"));
    assert_eq!(fs::read(&config).unwrap(), before);
    drop(lock);
    let modified = [before.as_slice(), b"\n# concurrent edit\n"].concat();
    fs::write(&config, &modified).unwrap();
    let blocked = commit(&baseline);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("changed during enrollment"));
    assert_eq!(fs::read(&config).unwrap(), modified);
    assert!(staged.is_file());
    let success = commit(&sha256_hex(&modified).unwrap());
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    assert_eq!(fs::read(&config).unwrap(), candidate);
    assert!(!staged.exists());
    // A malformed internal request must never delete the active config.
    let same = macluster_command()
        .args(["internal", "commit-enrollment-config", "--destination"])
        .arg(&config)
        .arg("--staged")
        .arg(&config)
        .arg("--baseline")
        .arg(sha256_hex(&candidate).unwrap())
        .output()
        .unwrap();
    assert!(!same.status.success());
    assert_eq!(fs::read(&config).unwrap(), candidate);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn user_installer_accepts_only_the_main_binary() {
    let (root, _shared, _config) = fixture();
    let download = root.join("download");
    fs::create_dir(&download).unwrap();
    let binary = download.join("macluster");
    fs::copy(env!("CARGO_BIN_EXE_macluster"), &binary).unwrap();
    let prefix = root.join("installed");
    let installer =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/scripts/install-user.sh");
    let output = Command::new("/bin/sh")
        .arg(installer)
        .arg(&binary)
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!prefix.join("macluster-power").exists());
    for alias in ["msub", "mjob", "mqueue", "mkill", "mtop", "mnode"] {
        assert_eq!(
            fs::read_link(prefix.join(alias)).unwrap(),
            PathBuf::from("macluster")
        );
    }
    let output = Command::new(prefix.join("macluster"))
        .args(["internal", "power-helper", "--version"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn init_refuses_to_overwrite_an_existing_config_without_reset() {
    let (root, _shared, config) = fixture();
    let original = fs::read(&config).unwrap();
    let state = root.join("controller");
    let status = run_with(
        "macluster",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "init".into(),
            "--name".into(),
            "replacement".into(),
        ],
    );

    assert_ne!(status, 0);
    assert_eq!(fs::read(&config).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn init_help_is_available_without_a_cluster_config() {
    let output = macluster_command()
        .args(["init", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("macluster init"));
    assert!(stdout.contains("--primary-nfs"));
    assert!(!stdout.contains("--reset"));
    assert!(stdout.contains("--force"));
    assert!(stdout.contains("existing cluster"));
    assert!(stdout.contains("unsynchronized output may be unavailable"));
}

#[test]
fn first_top_can_decline_setup_without_creating_or_resetting_state() {
    let (root, shared, config) = fixture();
    fs::remove_file(&config).unwrap();
    let state = root.join("controller");
    fs::write(shared.join("keep.txt"), "user data").unwrap();
    let (status, output) = command_in_pty_with_args(&config, &state, "mtop", &[], b"n\n");
    assert!(status.success(), "{output}");
    assert!(output.contains("Configure this Mac now?"), "{output}");
    assert!(!output.contains("Reset existing cluster"), "{output}");
    assert!(!config.exists());
    assert!(!state.exists());
    assert_eq!(
        fs::read_to_string(shared.join("keep.txt")).unwrap(),
        "user data"
    );
    for (args, success) in [
        (vec!["mtop", "--help"], true),
        (vec!["mtop", "--once"], false),
    ] {
        let output = macluster_command()
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.success(), success);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Configure this Mac now?"));
        assert!(!config.exists());
        assert!(!state.exists());
    }
    fs::remove_dir_all(root).unwrap();
}

fn init_in_pty(
    config: &std::path::Path,
    state: &std::path::Path,
    input: &[u8],
) -> (std::process::ExitStatus, String) {
    init_in_pty_with_args(config, state, &[], input)
}

fn init_in_pty_with_args(
    config: &std::path::Path,
    state: &std::path::Path,
    args: &[String],
    input: &[u8],
) -> (std::process::ExitStatus, String) {
    command_in_pty_with_args(config, state, "init", args, input)
}

fn command_in_pty_with_args(
    config: &std::path::Path,
    state: &std::path::Path,
    command: &str,
    args: &[String],
    input: &[u8],
) -> (std::process::ExitStatus, String) {
    let (mut master, slave) = open_pty();
    let mut child = macluster_command()
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(state)
        .arg(command)
        .args(args)
        .env_remove("MAMBA_ROOT_PREFIX")
        .env_remove("CONDA_PREFIX")
        .env_remove("VIRTUAL_ENV")
        .env_remove("HOMEBREW_PREFIX")
        .env_remove("CARGO_HOME")
        .env_remove("RUSTUP_HOME")
        .env_remove("JAVA_HOME")
        .env_remove("VCPKG_ROOT")
        .env_remove("OPENSSL_DIR")
        .env_remove("CUDA_HOME")
        .env_remove("LLVM_ROOT")
        .env_remove("CMAKE_PREFIX_PATH")
        .env_remove("CC")
        .env_remove("CXX")
        .env_remove("FC")
        .env_remove("CMAKE_C_COMPILER")
        .env_remove("CMAKE_CXX_COMPILER")
        .env("MACLUSTER_DISABLE_SERVICE_AUTOSTART", "1")
        .env("PATH", "/usr/bin:/bin:/sbin")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .unwrap();
    drop(slave);
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    master.write_all(input).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut output = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(error) => panic!("PTY read failed: {error}"),
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            // Drain any bytes written between the last read and process exit.
            while let Ok(n) = master.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                output.extend_from_slice(&buffer[..n]);
            }
            return (status, String::from_utf8_lossy(&output).into_owned());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("init stalled: {}", String::from_utf8_lossy(&output));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[cfg(target_os = "macos")]
fn dangling_config_symlink_is_rejected_before_creating_the_primary_marker() {
    let root = std::env::temp_dir().join(format!(
        "macluster-init-dangling-config-{}",
        macluster_protocol::identifiers::Id128::random()
    ));
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let config = root.join("config.toml");
    let state = root.join("controller");
    let shared = root.join("shared");
    symlink(root.join("missing-config.toml"), &config).unwrap();
    let interfaces = Command::new("/sbin/ifconfig").output().unwrap();
    let host = String::from_utf8_lossy(&interfaces.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .expect("test host needs a local cluster interface");
    let args = vec![
        "--name".into(),
        "dangling-test".into(),
        "--queue".into(),
        "q".into(),
        "--host".into(),
        host.to_string(),
        "--shared-root".into(),
        shared.display().to_string(),
    ];

    let (status, output) = init_in_pty_with_args(&config, &state, &args, b"Y\n");

    assert!(!status.success(), "{output}");
    assert!(
        output.contains("config path") || output.contains("config destination"),
        "{output}"
    );
    assert!(
        fs::symlink_metadata(&config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        !shared.join(".macluster-share-id").exists(),
        "a failed init must not leave a primary marker"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn existing_init_offers_reset_and_declining_preserves_the_cluster() {
    for input in [b"n\n".as_slice(), b"N\n".as_slice(), b"\n".as_slice()] {
        let (root, shared, config) = fixture();
        let before = fs::read(&config).unwrap();
        fs::write(shared.join("keep.txt"), "existing files").unwrap();
        let (status, output) = init_in_pty(&config, &root.join("controller"), input);
        assert!(!status.success());
        assert!(output.contains("Reset existing cluster"), "{output}");
        assert!(output.contains("Y/N"), "{output}");
        assert_eq!(fs::read(&config).unwrap(), before);
        assert_eq!(
            fs::read_to_string(shared.join("keep.txt")).unwrap(),
            "existing files"
        );
        assert!(
            !config
                .with_file_name("config.toml.macluster-reset.json")
                .exists()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(target_os = "macos")]
fn broken_address_migration_fixture() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let (root, shared, config) = fixture();
    let identity = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .unwrap();
    assert!(identity.status.success());
    let text = String::from_utf8(identity.stdout).unwrap();
    let uuid = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .unwrap()
        .rsplit_once('=')
        .unwrap()
        .1
        .trim()
        .trim_matches('"')
        .to_owned();
    let source = fs::read_to_string(&config).unwrap();
    let source = source.replace(
        "transport = \"ssh\"",
        &format!(
            "transport = \"local\"\nmachine_uuid = \"{uuid}\"\nexecution_uid = {}",
            unsafe { libc::geteuid() }
        ),
    );
    fs::write(&config, source).unwrap();
    let state = root.join("controller");
    fs::create_dir_all(&state).unwrap();
    let journal = state.join("node-address-migration.json");
    fs::write(&journal, b"{interrupted address migration").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    (root, shared, config, state)
}

#[test]
#[cfg(target_os = "macos")]
fn broken_address_migration_keeps_status_and_pending_cancellation_available() {
    use macluster_protocol::identifiers::RequestId;
    let (root, shared, config, state) = broken_address_migration_fixture();
    let storage = Storage::open(&state).unwrap();
    let snapshot = storage.stage_snapshot(b"echo queued\n").unwrap();
    let spec = serde_json::from_value(serde_json::json!({
        "queue":"mini01", "node":null, "name":"recovery", "cwd":shared,
        "stdout_path":"", "stderr_path":"", "walltime_secs":null,
        "env":{}, "snapshot":snapshot, "mode":"batch"
    }))
    .unwrap();
    let job = storage.submit_once(RequestId::random(), spec).unwrap();
    for args in [
        vec!["mjob", "--json"],
        vec!["mqueue", "--json"],
        vec!["mnode", "-l"],
        vec!["mtop", "--json"],
        vec!["mkill", "1"],
    ] {
        let output = macluster_command()
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        storage.get_job(job.id).unwrap().unwrap().state,
        JobState::Cancelled
    );
    assert_eq!(
        fs::read(state.join("node-address-migration.json")).unwrap(),
        b"{interrupted address migration"
    );
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(target_os = "macos")]
fn broken_address_migration_does_not_block_init_confirmation_or_allow_submission() {
    let (root, _shared, config, state) = broken_address_migration_fixture();
    let before = fs::read(&config).unwrap();
    let (status, output) = init_in_pty(&config, &state, b"n\n");
    assert!(!status.success());
    assert!(output.contains("Reset existing cluster"), "{output}");
    assert!(output.contains("cluster reset cancelled"), "{output}");
    assert_eq!(fs::read(&config).unwrap(), before);
    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&state)
        .args(["msub", "echo blocked"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid address recovery record"));
    let storage = Storage::open(&state).unwrap();
    let snapshot = storage.stage_snapshot(b"sleep 60\n").unwrap();
    let spec = serde_json::from_value(serde_json::json!({
        "queue":"mini01", "node":null, "name":"active recovery blocker", "cwd":root.join("shared"),
        "stdout_path":"", "stderr_path":"", "walltime_secs":null,
        "env":{}, "snapshot":snapshot, "mode":"batch"
    }))
    .unwrap();
    let job = storage
        .submit_once(macluster_protocol::identifiers::RequestId::random(), spec)
        .unwrap();
    storage
        .reserve_job(
            job.id,
            macluster_protocol::identifiers::NodeId::new("mini01-a").unwrap(),
        )
        .unwrap();
    storage.mark_running(job.id).unwrap();
    let (status, output) = init_in_pty_with_args(&config, &state, &["--force".into()], b"y\n");
    assert!(!status.success());
    assert!(output.contains("reset is paused because jobs"), "{output}");
    assert_eq!(
        storage.get_job(job.id).unwrap().unwrap().state,
        JobState::Running
    );
    assert_eq!(fs::read(&config).unwrap(), before);
    assert_eq!(
        fs::read(state.join("node-address-migration.json")).unwrap(),
        b"{interrupted address migration"
    );
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(target_os = "macos")]
fn stale_address_migration_keeps_queries_and_init_available() {
    let (root, _shared, config, state) = broken_address_migration_fixture();
    let source = fs::read_to_string(&config).unwrap();
    let record = serde_json::json!({
        "operation_id":"11111111-1111-4111-8111-111111111111",
        "config_path":config.canonicalize().unwrap(), "state_dir":state.canonicalize().unwrap(),
        "old_source":source, "candidate_source":source, "phase":"PLANNED", "completed":[]
    });
    let journal = state.join("node-address-migration.json");
    fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
    fs::write(
        &config,
        format!("{source}\n# changed after migration planning\n"),
    )
    .unwrap();
    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&state)
        .args(["mqueue", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (status, output) = init_in_pty(&config, &state, b"n\n");
    assert!(!status.success());
    assert!(output.contains("Reset existing cluster"), "{output}");
    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&state)
        .args(["msub", "echo blocked"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cluster config changed during node address migration")
    );
    assert_eq!(
        fs::read(&journal).unwrap(),
        serde_json::to_vec(&record).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn confirming_reset_from_init_still_blocks_on_active_jobs() {
    for input in [b"y\n".as_slice(), b"Y\n".as_slice()] {
        let (root, shared, config) = fixture();
        let state = root.join("controller");
        let storage = Storage::open(&state).unwrap();
        let snapshot = storage.stage_snapshot(b"sleep 1\n").unwrap();
        let spec = serde_json::from_value(serde_json::json!({
            "queue":"mini01", "node":null, "name":"pending job", "cwd":shared,
            "stdout_path":"", "stderr_path":"", "walltime_secs":null,
            "env":{}, "snapshot":snapshot, "mode":"batch"
        }))
        .unwrap();
        let job = storage
            .submit_once(macluster_protocol::identifiers::RequestId::random(), spec)
            .unwrap();
        drop(storage);
        let before = fs::read(&config).unwrap();
        let (status, output) = init_in_pty(&config, &state, input);
        assert!(!status.success());
        assert!(output.contains("reset is paused"), "{output}");
        assert!(
            output.contains(&format!("job {} is Pending", job.id)),
            "{output}"
        );
        assert_eq!(fs::read(&config).unwrap(), before);
        assert!(
            !config
                .with_file_name("config.toml.macluster-reset.json")
                .exists()
        );
        assert_eq!(
            Storage::open(&state)
                .unwrap()
                .get_job(job.id)
                .unwrap()
                .unwrap()
                .state,
            JobState::Pending
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[cfg(target_os = "macos")]
fn init_resumes_cleanup_and_creates_the_new_cluster_in_the_same_invocation() {
    let (root, shared, config) = fixture();
    let root = root.canonicalize().unwrap();
    let config = config.canonicalize().unwrap();
    let state = root.join("controller");
    let agent = root.join("old-agent");
    let archive = root.join("archive");
    let new_shared = root.join("new-shared");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&agent).unwrap();
    fs::write(state.join("old-state.txt"), "archive me").unwrap();
    fs::write(shared.join("keep.txt"), "shared user data").unwrap();
    let interfaces = Command::new("/sbin/ifconfig").output().unwrap();
    let host = String::from_utf8_lossy(&interfaces.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .expect("init needs a local cluster interface");
    let original = fs::read(&config).unwrap();
    let journal_path = config.with_file_name("config.toml.macluster-reset.json");
    let journal = serde_json::json!({
        "version":1, "id":"resume-and-initialize", "phase":"ARCHIVING",
        "config_path":config, "state_dir":state,
        "old_config":String::from_utf8(original.clone()).unwrap(),
        "old_config_sha256":macluster_protocol::framing::sha256_hex(&original).unwrap(),
        "local_agent_state":agent, "mode":"clear_to_uninitialized",
        "target_config":"", "target_options":{
            "help":false, "reset":true, "name":"new-cluster", "queue":"fresh",
            "shared_root":new_shared, "primary_nfs":null, "host":host
        },
        "target_context":null, "archive_dir":archive,
        "completed_steps":["log-sync-stopped:local"], "detail":null
    });
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let (status, output) = init_in_pty(&config, &state, b"N\nY\n");
    assert!(status.success(), "{output}");
    assert!(
        output.contains("Cluster 'new-cluster' initialized."),
        "{output}"
    );
    assert!(
        !output.contains("Reset existing cluster"),
        "resume must use saved confirmation: {output}"
    );
    let fresh = macluster_core::config::ClusterConfig::parse(&fs::read_to_string(&config).unwrap())
        .unwrap();
    assert_eq!(fresh.name, "new-cluster");
    assert_eq!(fresh.default_queue.as_str(), "fresh");
    assert!(fresh.queues["fresh"].nodes.is_empty());
    assert_eq!(fresh.nodes.len(), 1);
    assert_ne!(fresh.share_uuid, "00000000-0000-4000-8000-000000000001");
    assert_eq!(fs::read(archive.join("config.toml")).unwrap(), original);
    assert_eq!(
        fs::read_to_string(archive.join("controller/old-state.txt")).unwrap(),
        "archive me"
    );
    assert_eq!(
        fs::read_to_string(shared.join("keep.txt")).unwrap(),
        "shared user data"
    );
    assert!(!journal_path.exists());
    assert!(new_shared.join(".macluster-share-id").is_file());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn job_queue_and_kill_help_are_available_without_cluster_state() {
    for command in ["mjob", "mqueue", "mkill"] {
        let output = macluster_command()
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Usage"),
            "{command} help output missing usage"
        );
    }
}

#[test]
fn top_level_web_rejects_non_loopback_before_loading_cluster_state() {
    let output = macluster_command()
        .args(["--web", "192.0.2.10:8080"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only supports 127.0.0.1"), "{stderr}");
}

#[test]
fn noninteractive_init_requires_explicit_terminal_confirmation() {
    let root = std::env::temp_dir().join(format!(
        "macluster-init-no-tty-{}",
        macluster_protocol::identifiers::Id128::random()
    ));
    fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    let interfaces = Command::new("/sbin/ifconfig").output().unwrap();
    let host = String::from_utf8_lossy(&interfaces.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|value| value.parse::<std::net::Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .expect("init needs a local cluster interface");
    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(root.join("state"))
        .args([
            "init",
            "--name",
            "no-tty",
            "--queue",
            "q",
            "--host",
            &host.to_string(),
            "--shared-root",
        ])
        .arg(root.join("shared"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("terminal confirmation"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !config.exists(),
        "noninteractive init must not create cluster config"
    );
    assert!(
        !root.join("shared").exists(),
        "noninteractive init must not create shared storage"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn init_force_requires_an_existing_cluster_or_recovery_record() {
    let root = std::env::temp_dir().join(format!(
        "macluster-init-force-{}",
        macluster_protocol::identifiers::Id128::random()
    ));
    fs::create_dir_all(&root).unwrap();
    let config = root.join("config.toml");
    let state = root.join("state");
    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&state)
        .args(["init", "--force"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires an existing cluster"));
    assert!(!config.exists());
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn msub_is_blocked_by_a_reset_recovery_journal() {
    let (root, _shared, config) = fixture();
    let journal = config.with_file_name(format!(
        "{}.macluster-reset.json",
        config.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&journal, b"invalid journal").unwrap();
    let state = root.join("controller");
    let status = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "--wrap".into(),
            "true".into(),
        ],
    );

    assert_ne!(status, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn msub_is_blocked_while_node_maintenance_is_draining() {
    let (root, _shared, config) = fixture();
    let config = config.canonicalize().unwrap();
    let state = root.join("controller");
    let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
    fs::write(
        &barrier,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "config_path": config,
            "state_dir": state,
            "owner_pid": 1234
        }))
        .unwrap(),
    )
    .unwrap();
    let barrier_owner = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&barrier)
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(barrier_owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );

    let output = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&state)
        .args(["msub", "--wrap", "true"])
        .output()
        .unwrap();
    drop(barrier_owner);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("node maintenance is draining"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.join("controller.sqlite3").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn controller_start_is_blocked_by_a_reset_recovery_journal() {
    let (root, _shared, config) = fixture();
    let journal = config.with_file_name(format!(
        "{}.macluster-reset.json",
        config.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&journal, b"invalid journal").unwrap();
    let state = root.join("controller");
    let status = run_with(
        "macluster",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "controller".into(),
            "run".into(),
            "--once".into(),
        ],
    );

    assert_ne!(status, 0);
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}

fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "macluster-cli-{}-{nonce}-{fixture_id}",
        std::process::id()
    ));
    let shared = root.join("shared");
    let projects = shared.join("projects");
    fs::create_dir_all(&projects).unwrap();
    let config = root.join("config.toml");
    let test_binary = PathBuf::from(env!("CARGO_BIN_EXE_macluster"));
    let test_digest = sha256_hex(&fs::read(test_binary).unwrap()).unwrap();
    fs::write(
        &config,
        format!(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "mini01-a"
protocol_version = 1

[queues.mini01]
nodes = ["mini01-a"]
scheduler = "fifo"

[nodes.mini01-a]
host = "192.168.2.1"
transport = "ssh"
remote_binary = "/Users/macluster/.local/share/macluster/bin/{test_digest}/macluster"
"#,
            shared.display()
        ),
    )
    .unwrap();
    (root, shared, config)
}

fn use_cli_binary_build(config: &PathBuf) {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_macluster"));
    let digest = sha256_hex(&fs::read(binary).unwrap()).unwrap();
    let text = fs::read_to_string(config).unwrap();
    let updated = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("remote_binary = ") {
                format!(
                    "remote_binary = \"/Users/macluster/.local/share/macluster/bin/{digest}/macluster\""
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(config, updated + "\n").unwrap();
}

#[test]
fn msub_commits_locally_and_request_id_replay_uses_cached_script() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let request_id = "00000000-0000-4000-8000-000000000001";
    let first = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "--request-id".into(),
            request_id.into(),
            "-q".into(),
            "mini01".into(),
            "--cwd".into(),
            root.join("shared/projects").display().to_string(),
            "--wrap".into(),
            "echo first".into(),
        ],
    );
    assert_eq!(first, 0);

    let storage = Storage::open(&state).unwrap();
    let submitted = storage.list_jobs(None).unwrap().remove(0);
    let snapshot_path = storage.snapshot_path(submitted.spec.snapshot.as_ref().unwrap());
    fs::remove_file(&snapshot_path).unwrap();
    drop(storage);

    let replay = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "--request-id".into(),
            request_id.into(),
        ],
    );
    assert_eq!(replay, 0);

    let storage = Storage::open(&state).unwrap();
    let jobs = storage.list_jobs(None).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].spec.name, "wrap");
    assert!(jobs[0].snapshot_sync_pending);
    assert!(
        snapshot_path.exists(),
        "cached replay must restore its durable snapshot"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn msub_preserves_named_share_cwd_and_translates_server_alias() {
    let (root, _, config) = fixture();
    let source = root.join("JanusX");
    let project = source.join("project");
    fs::create_dir_all(&project).unwrap();
    let mount = root.join("client-JanusX");
    let mut text = fs::read_to_string(&config)
        .unwrap()
        .replace("transport = \"ssh\"", "transport = \"local\"\nmachine_uuid=\"00000000-0000-4000-8000-000000000099\"\nexecution_uid=501");
    text.push_str(&format!("\n[shares.janusx]\nserver=\"mini01-a\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"00000000-0000-4000-8000-000000000009\"\n", source.display(), mount.display()));
    fs::write(&config, text).unwrap();
    // Exercise default cwd and explicit --cwd, using a subprocess so tests
    // never change the test harness's process-wide working directory.
    for explicit in [false, true] {
        let state = root.join("controller");
        let mut command = macluster_command();
        command
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(["msub", "--wrap", "pwd"]);
        if explicit {
            command
                .arg("--cwd")
                .arg(&project)
                .args(["--output", "task.log"]);
        }
        let output = command.current_dir(&project).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let job = Storage::open(&state)
            .unwrap()
            .get_job(if explicit { 2 } else { 1 })
            .unwrap()
            .unwrap();
        assert_eq!(job.spec.cwd, mount.join("project").to_string_lossy());
        if explicit {
            assert_eq!(
                job.spec.stdout_path,
                mount.join("project/task.log").to_string_lossy()
            );
        }
    }

    // Inline commands from outside all registered shares default to primary root.
    let fallback_state = root.join("controller");
    let fallback = macluster_command()
        .arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(&fallback_state)
        .args(["msub", "--wrap", "pwd"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        fallback.status.success(),
        "{}",
        String::from_utf8_lossy(&fallback.stderr)
    );
    let fallback_job = Storage::open(&fallback_state)
        .unwrap()
        .get_job(3)
        .unwrap()
        .unwrap();
    assert_eq!(PathBuf::from(&fallback_job.spec.cwd), root.join("shared"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn msub_remaps_submitter_environment_into_compute_share_paths() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let source = root.join("analysis-source");
    fs::create_dir_all(source.join("bin")).unwrap();
    fs::create_dir_all(source.join("lib")).unwrap();
    let mount = root.join("analysis-client");
    let config_text = fs::read_to_string(&config)
        .unwrap()
        .replace(
            "transport = \"ssh\"",
            "transport = \"local\"\nmachine_uuid=\"00000000-0000-4000-8000-000000000099\"\nexecution_uid=501",
        );
    fs::write(
        &config,
        format!(
            "{config_text}\n[shares.analysis]\nserver=\"mini01-a\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"00000000-0000-4000-8000-000000000009\"\n",
            source.display(),
            mount.display()
        ),
    )
    .unwrap();
    let submit_path = format!("{}/bin:/usr/bin:/bin", source.display());
    let output = macluster_command()
        .args(["--config", config.to_str().unwrap()])
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["msub", "--wrap", "true"])
        .env("PATH", &submit_path)
        .env("MACLUSTER_TEST_LOGIN_ENV", "inherited-from-login")
        .env("CONDA_EXE", source.join("bin/conda"))
        .env("PYTHONPATH", source.join("lib"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let jobs = Storage::open(&state).unwrap().list_jobs(None).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].spec.env.get("PATH"),
        Some(&format!("{}/bin:/usr/bin:/bin", mount.display()))
    );
    assert_eq!(
        jobs[0].spec.env.get("MACLUSTER_TEST_LOGIN_ENV"),
        Some(&"inherited-from-login".to_owned())
    );
    assert_eq!(
        jobs[0].spec.env.get("CONDA_EXE"),
        Some(&mount.join("bin/conda").to_string_lossy().to_string())
    );
    assert_eq!(
        jobs[0].spec.env.get("PYTHONPATH"),
        Some(&mount.join("lib").to_string_lossy().to_string())
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn submit_does_not_consume_task_help_or_global_flags() {
    let (root, shared, config) = fixture();
    let state = root.join("controller");
    let project = shared.join("projects");
    let status = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "-q".into(),
            "mini01".into(),
            "--cwd".into(),
            project.display().to_string(),
            "echo".into(),
            "--help".into(),
            "--config".into(),
            "task-config".into(),
            "--state-dir".into(),
            "task-state".into(),
            "--node".into(),
            "task-node".into(),
            "--env".into(),
            "FOO=bar".into(),
        ],
    );

    assert_eq!(status, 0);
    let storage = Storage::open(&state).unwrap();
    let job = storage.get_job(1).unwrap().unwrap();
    let snapshot = storage.snapshot_path(job.spec.snapshot.as_ref().unwrap());
    let script = fs::read_to_string(snapshot).unwrap();
    assert_eq!(
        script,
        "#!/bin/bash\n'echo' '--help' '--config' 'task-config' '--state-dir' 'task-state' '--node' 'task-node' '--env' 'FOO=bar'\n"
    );
    assert_eq!(job.spec.queue.as_str(), "mini01");
    assert_eq!(job.spec.node, None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn submit_still_accepts_leading_global_options() {
    let (root, shared, config) = fixture();
    let state = root.join("controller");
    let project = shared.join("projects");
    let status = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "-q".into(),
            "mini01".into(),
            "--cwd".into(),
            project.display().to_string(),
            "echo".into(),
            "ok".into(),
        ],
    );

    assert_eq!(status, 0);
    let storage = Storage::open(&state).unwrap();
    let job = storage.get_job(1).unwrap().unwrap();
    assert_eq!(job.spec.queue.as_str(), "mini01");
    assert_eq!(
        fs::read_to_string(storage.snapshot_path(job.spec.snapshot.as_ref().unwrap())).unwrap(),
        "#!/bin/bash\n'echo' 'ok'\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cached_interactive_shell_submission_replays_without_snapshot() {
    let (root, shared, config) = fixture();
    use_cli_binary_build(&config);
    let state = root.join("controller");
    let request_id = "00000000-0000-4000-8000-000000000002";
    let cache = state.join("client-submissions");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join(format!("{request_id}.script")), b"").unwrap();
    fs::write(
        cache.join(format!("{request_id}.json")),
        serde_json::to_vec(&serde_json::json!({
            "spec": {
                "queue": "mini01",
                "node": null,
                "name": "interactive-shell",
                "cwd": shared.join("projects").display().to_string(),
                "stdout_path": shared.join("jobs/%j/stdout.log").display().to_string(),
                "stderr_path": shared.join("jobs/%j/stderr.log").display().to_string(),
                "walltime_secs": null,
                "env": {},
                "mode": "interactive",
                "snapshot": null
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let (mut master, slave) = open_pty();
    let mut child = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "msub",
            "--request-id",
            request_id,
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let job = loop {
        if let Ok(storage) = Storage::open(&state)
            && let Ok(jobs) = storage.list_jobs(None)
            && let Some(job) = jobs.first()
        {
            break job.clone();
        }
        assert!(
            Instant::now() < deadline,
            "cached interactive job was not submitted"
        );
        thread::sleep(Duration::from_millis(20));
    };
    master.write_all(b"\x03").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(130));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cached interactive replay did not stop"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let storage = Storage::open(&state).unwrap();
    let job = storage.get_job(job.id).unwrap().unwrap();
    assert_eq!(job.spec.name, "interactive-shell");
    assert_eq!(job.state, JobState::Cancelled);
    assert_eq!(
        serde_json::to_value(job.spec).unwrap()["snapshot"],
        serde_json::Value::Null
    );
    assert!(!job.snapshot_sync_pending);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interactive_submission_without_tty_does_not_create_job() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let result = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "msub",
            "-Is",
            "--wrap",
            "echo should-not-run",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("requires terminal"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!state.exists(), "non-terminal invocation created state");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupt_while_pending_cancels_job() {
    let (root, _shared, config) = fixture();
    use_cli_binary_build(&config);
    let state = root.join("controller");
    let (mut master, slave) = open_pty();
    let original = terminal_attributes(slave.as_raw_fd());
    let mut child = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "msub",
            "-Is",
            "-q",
            "mini01",
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let job = loop {
        if let Ok(storage) = Storage::open(&state)
            && let Ok(jobs) = storage.list_jobs(None)
            && let Some(job) = jobs.first()
        {
            break job.clone();
        }
        assert!(
            Instant::now() < deadline,
            "interactive job was not submitted"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(job.state, JobState::Pending);
    master.write_all(b"\x03").unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "msub did not cancel the pending job"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    let storage = Storage::open(&state).unwrap();
    assert_eq!(
        storage.get_job(job.id).unwrap().unwrap().state,
        JobState::Cancelled
    );
    let restored = terminal_attributes(slave.as_raw_fd());
    assert_eq!(restored.c_lflag, original.c_lflag);
    fs::remove_dir_all(root).unwrap();
}

fn open_pty() -> (fs::File, fs::File) {
    let mut master = -1;
    let mut slave = -1;
    let mut window = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut window,
            )
        },
        0
    );
    unsafe { (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave)) }
}

fn terminal_attributes(fd: i32) -> libc::termios {
    let mut attributes = unsafe { std::mem::zeroed::<libc::termios>() };
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut attributes) }, 0);
    attributes
}

#[test]
fn mjob_details_display_controller_waiting_reason() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let storage = Storage::open(&state).unwrap();
    let snapshot = storage.stage_snapshot(b"echo queued\n").unwrap();
    let job = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId(
                macluster_protocol::identifiers::Id128::random(),
            ),
            macluster_protocol::types::JobSpec {
                storage_namespace: None,
                queue: macluster_protocol::identifiers::QueueName::new("mini01").unwrap(),
                node: None,
                name: "waiting".into(),
                cwd: root.join("shared/projects").display().to_string(),
                stdout_path: root.join("shared/jobs/%j/stdout.log").display().to_string(),
                stderr_path: root.join("shared/jobs/%j/stderr.log").display().to_string(),
                walltime_secs: None,
                env: Default::default(),
                mode: macluster_protocol::types::JobMode::Batch,
                snapshot: Some(snapshot),
            },
        )
        .unwrap();
    storage
        .set_waiting_reason(
            job.id,
            Some("retry the requested command to trigger an Agent update".into()),
        )
        .unwrap();
    drop(storage);

    let output = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mjob",
            &job.id.to_string(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Waiting reason: retry the requested command")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_core_request_is_a_cli_validation_error_without_a_job() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let code = run_with(
        "msub",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "-q".into(),
            "mini01".into(),
            "-n".into(),
            "4".into(),
            "--wrap".into(),
            "echo forbidden".into(),
        ],
    );
    assert_eq!(code, 2);
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_cli_submissions_initialize_controller_storage_once() {
    let (root, _shared, config) = fixture();
    use_cli_binary_build(&config);
    let state = root.join("controller");
    let handles: Vec<_> = (0..12)
        .map(|_| {
            let config = config.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                macluster_command()
                    .arg("--config")
                    .arg(config)
                    .arg("--state-dir")
                    .arg(state)
                    .args(["msub", "--wrap", "true"])
                    .output()
                    .unwrap()
            })
        })
        .collect();
    let outputs: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    let failures: Vec<_> = outputs
        .iter()
        .filter(|output| !output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
        .collect();
    assert!(
        failures.is_empty(),
        "concurrent submissions failed: {failures:?}"
    );

    let storage = Storage::open(&state).unwrap();
    assert_eq!(storage.list_jobs(None).unwrap().len(), outputs.len());
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mjob_mqueue_and_mkill_read_and_mutate_the_persistent_queue() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let wake = ControllerWake::bind(&state).unwrap();
    assert_eq!(
        run_with(
            "msub",
            &[
                "--config".into(),
                config.display().to_string(),
                "--state-dir".into(),
                state.display().to_string(),
                "--cwd".into(),
                root.join("shared/projects").display().to_string(),
                "--wrap".into(),
                "echo queued".into(),
            ]
        ),
        0
    );
    assert!(wake.wait(Duration::ZERO).unwrap());

    assert_eq!(
        run_with(
            "mjob",
            &[
                "--state-dir".into(),
                state.display().to_string(),
                "--json".into()
            ]
        ),
        0
    );
    assert_eq!(
        run_with(
            "mqueue",
            &[
                "--config".into(),
                config.display().to_string(),
                "--state-dir".into(),
                state.display().to_string(),
                "--json".into(),
            ]
        ),
        0
    );
    assert_eq!(
        run_with(
            "mkill",
            &[
                "--state-dir".into(),
                state.display().to_string(),
                "1".into()
            ]
        ),
        0
    );
    assert!(wake.wait(Duration::ZERO).unwrap());

    let storage = Storage::open(&state).unwrap();
    assert_eq!(
        storage.get_job(1).unwrap().unwrap().state,
        JobState::Cancelled
    );
    drop(wake);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn standalone_mupdate_and_update_commands_are_removed() {
    for command in ["mupdate", "update"] {
        let output = macluster_command()
            .args([command, "--help"])
            .output()
            .expect("check removed update command");
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unknown command"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let help = macluster_command().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(!help.contains("mupdate"));
    assert!(!help.contains("<submit|job|queue|kill|top|node|update"));

    let (root, _, _) = fixture();
    let stale_alias = root.join("mupdate");
    symlink(env!("CARGO_BIN_EXE_macluster"), &stale_alias).unwrap();
    let output = Command::new(&stale_alias).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command alias"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_capabilities_advertise_runtime_features() {
    let output = macluster_command()
        .args(["internal", "capabilities", "--json"])
        .output()
        .expect("query Agent capabilities");

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "metrics.cpu-temperature.v1")
    );
    assert!(
        report["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "metrics.fan-speed.v1")
    );
    assert!(
        report["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "agent.interactive-pty.v1")
    );
}

#[test]
fn operational_command_does_not_skip_preflight_for_an_invalid_existing_config() {
    let (root, _shared, config) = fixture();
    fs::write(&config, "[cluster]\nname = \"broken\"\n").unwrap();
    let state = root.join("controller");

    let output = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mjob",
            "--json",
        ])
        .output()
        .expect("run mjob with an invalid existing cluster config");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cannot check Agent builds because the cluster config is invalid"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !state.exists(),
        "preflight must stop before opening job state"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_agent_update_is_blocked_by_active_work_before_any_prompt_or_submission() {
    let (root, shared, config) = fixture();
    let stale = "f".repeat(64);
    let text = fs::read_to_string(&config).unwrap();
    let updated = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("remote_binary = ") {
                format!(
                    "remote_binary = \"/Users/macluster/.local/share/macluster/bin/{stale}/macluster\""
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&config, updated + "\n").unwrap();
    let state = root.join("controller");
    let storage = Storage::open(&state).unwrap();
    let snapshot = storage.stage_snapshot(b"sleep 60\n").unwrap();
    let active = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId::random(),
            serde_json::from_value(serde_json::json!({
                "queue":"mini01",
                "node":null,
                "name":"already-running",
                "cwd":shared,
                "stdout_path":"",
                "stderr_path":"",
                "walltime_secs":null,
                "env":{},
                "snapshot":snapshot,
                "mode":"batch"
            }))
            .unwrap(),
        )
        .unwrap();
    storage
        .reserve_job(
            active.id,
            macluster_protocol::identifiers::NodeId::new("mini01-a").unwrap(),
        )
        .unwrap();
    storage.mark_running(active.id).unwrap();
    drop(storage);

    let alias = root.join("msub");
    symlink(env!("CARGO_BIN_EXE_macluster"), &alias).unwrap();
    let output = Command::new(&alias)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--wrap",
            "echo should-not-submit",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("active jobs or output sync remain before Agent update"),
        "{stderr}"
    );
    assert!(!stderr.contains("Stop it for Agent update"), "{stderr}");

    let inspection = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mjob",
        ])
        .output()
        .expect("run mjob while the stale Agent update is blocked by an active job");
    assert!(
        inspection.status.success(),
        "{}",
        String::from_utf8_lossy(&inspection.stderr)
    );
    assert!(
        String::from_utf8_lossy(&inspection.stderr).contains("Agent update is deferred"),
        "{}",
        String::from_utf8_lossy(&inspection.stderr)
    );
    let listing = String::from_utf8_lossy(&inspection.stdout);
    assert!(listing.contains("JOBID"), "{listing}");
    assert!(listing.contains("Running"), "{listing}");

    let storage = Storage::open(&state).unwrap();
    let jobs = storage.list_jobs(None).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, active.id);
    assert_eq!(jobs[0].state, JobState::Running);
    assert_eq!(fs::read_dir(state.join("snapshots")).unwrap().count(), 1);
    assert!(!state.join("client-submissions").exists());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn operational_command_updates_a_stale_local_agent_before_dispatch() {
    let (root, shared, config) = fixture();
    let stale_binary = root.join("old-macluster");
    fs::write(&stale_binary, b"stale agent build").unwrap();
    let identity = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .expect("read local machine identity");
    assert!(identity.status.success());
    let machine_uuid = String::from_utf8_lossy(&identity.stdout)
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
        .map(|value| value.trim_matches('"').trim().to_owned())
        .expect("IOPlatformUUID is present");
    let execution_uid = unsafe { libc::geteuid() };
    fs::write(
        &config,
        format!(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
login_node = "login"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "login"
protocol_version = 1

[queues.mini01]
nodes = ["login"]
scheduler = "fifo"

[nodes.login]
host = "127.0.0.1"
transport = "local"
remote_binary = "{}"
machine_uuid = "{}"
execution_uid = {}
"#,
            shared.display(),
            stale_binary.display(),
            machine_uuid,
            execution_uid
        ),
    )
    .unwrap();
    let state = root.join("controller");

    let output = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "mjob",
            "--json",
        ])
        .output()
        .expect("run mjob through the global Agent preflight");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Updated Agent on 1 configured node(s)."),
        "{stdout}"
    );
    assert!(stdout.contains("[]"), "{stdout}");
    let updated = fs::read_to_string(&config).unwrap();
    assert!(updated.contains("remote_binary = \""));
    assert!(updated.contains("machine_uuid = \""));
    assert!(updated.contains("execution_uid = "));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unfinished_enrollment_is_not_listed_as_a_node_and_errors_remain_available() {
    let (root, _shared, config) = fixture();
    let source = fs::read_to_string(&config)
        .unwrap()
        .replace("transport = \"ssh\"", &format!("transport = \"local\"\nmachine_uuid = \"00000000-0000-4000-8000-000000000099\"\nexecution_uid = {}", unsafe { libc::geteuid() }));
    let source = source
        .lines()
        .map(|line| {
            if line.starts_with("remote_binary =") {
                "remote_binary = \"/bin/false\""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&config, source).unwrap();
    let state = root.join("controller");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("node-admin.json"), serde_json::to_vec(&serde_json::json!({
        "version":1, "config_path":config.canonicalize().unwrap(), "state_dir":state.canonicalize().unwrap(),
        "reserved_node_ids":["draft-001"], "machine_uuids":{}, "operations":{
            "add:operator@192.0.2.50:22": {
                "id":"test-draft", "action":"add", "node_id":"draft-001",
                "endpoint":"operator@192.0.2.50:22", "machine_uuid":null,
                "phase":"SETUP_PENDING", "old_config_sha256":null, "candidate_config_sha256":null,
                "managed_export":false, "detail":"mount path already contains user files"
            }
        }
    })).unwrap()).unwrap();
    let original_journal = fs::read(state.join("node-admin.json")).unwrap();
    for option in ["-l", "--failed"] {
        let output = macluster_command()
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(["mnode", option])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        if option == "-l" {
            assert!(!text.contains("draft-001"), "{text}");
            assert!(!text.contains("SETUP_PENDING"), "{text}");
            assert!(!text.contains("PHASE"), "{text}");
            assert!(
                text.contains("mini01-a") && text.contains("OFFLINE"),
                "{text}"
            );
        } else {
            assert!(
                text.contains("draft-001")
                    && text.contains("mount path already contains user files"),
                "{text}"
            );
        }
    }
    assert_eq!(
        fs::read(state.join("node-admin.json")).unwrap(),
        original_journal
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mnode_reports_online_when_agent_answers_but_share_health_fails() {
    let (root, shared, _config) = fixture();
    let identity = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .unwrap();
    assert!(identity.status.success());
    let machine_uuid = String::from_utf8_lossy(&identity.stdout)
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .unwrap()
        .rsplit_once('=')
        .unwrap()
        .1
        .trim()
        .trim_matches('"')
        .to_owned();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_macluster"));

    let config = root.join("config.toml");
    fs::write(
        &config,
        format!(
            r#"[cluster]
name = "test"
default_queue = "compute"
login_node = "login-01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "login-01"
protocol_version = 1

[queues.compute]
nodes = ["login-01"]
scheduler = "fifo"

[nodes.login-01]
host = "127.0.0.1"
transport = "local"
remote_binary = "{}"
machine_uuid = "{}"
execution_uid = {}
"#,
            shared.display(),
            binary.display(),
            machine_uuid,
            unsafe { libc::geteuid() }
        ),
    )
    .unwrap();

    let output = macluster_command()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--state-dir",
            root.join("controller").to_str().unwrap(),
            "mnode",
            "-l",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("login-01") && text.contains("ONLINE"),
        "{text}"
    );
    assert!(!text.contains("OFFLINE"), "{text}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn operational_command_attempts_orphaned_agent_update_recovery() {
    let (root, _shared, config) = fixture();
    use_cli_binary_build(&config);
    let state = root.join("controller");
    fs::create_dir_all(&state).unwrap();
    let config = config.canonicalize().unwrap();
    let state = state.canonicalize().unwrap();
    fs::write(
        state.join("node-admin.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "config_path": config,
            "state_dir": state,
            "reserved_node_ids": [],
            "machine_uuids": {},
            "operations": {
                "update:all": {
                    "id": "test-update",
                    "action": "update",
                    "node_id": "all",
                    "endpoint": "cluster",
                    "machine_uuid": null,
                    "phase": "SYNC_PENDING",
                    "old_config_sha256": "old-config",
                    "candidate_config_sha256": "candidate-config",
                    "managed_export": false,
                    "managed_shares": [],
                    "detail": null
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
    fs::write(
        &barrier,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "config_path": config,
            "state_dir": state,
            "owner_pid": 99999999
        }))
        .unwrap(),
    )
    .unwrap();

    for args in [
        vec!["mtop", "--once"],
        vec!["msub", "--wrap", "echo must-not-submit"],
    ] {
        let output = macluster_command()
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("all-node update"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!state.join("client-submissions").exists());
    assert!(
        !barrier.exists(),
        "preflight must release its recovery barrier"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn macluster_accepts_global_options_before_the_subcommand() {
    let (root, _shared, config) = fixture();
    let state = root.join("controller");
    let code = run_with(
        "macluster",
        &[
            "--config".into(),
            config.display().to_string(),
            "--state-dir".into(),
            state.display().to_string(),
            "queue".into(),
            "--json".into(),
        ],
    );
    assert_eq!(code, 0);
    fs::remove_dir_all(root).unwrap();
}
