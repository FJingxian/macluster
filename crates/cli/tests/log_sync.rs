//! Real agent subprocesses with a deliberately blocked log source. No live NFS
//! exports, running cluster state, or administrator permissions are needed.
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    os::unix::{
        fs::OpenOptionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::transport::run_child_bounded;
use macluster_protocol::{
    framing::{read_frame, write_frame},
    identifiers::{Id128, RequestId},
    types::{Operation, PROTOCOL_VERSION, Request, Response, ResponseBody},
};
use serde_json::{Value, json};

const SHARE_ID: &str = "00000000-0000-4000-8000-000000000001";

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    shared: PathBuf,
    config: PathBuf,
    token: String,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("macluster-async-logs-{}", Id128::random()));
        let state = root.join("agent");
        let shared = root.join("shared");
        fs::create_dir_all(state.join("jobs/1")).unwrap();
        fs::create_dir_all(&shared).unwrap();
        let shared = shared.canonicalize().unwrap();
        fs::write(shared.join(".macluster-share-id"), SHARE_ID).unwrap();
        fs::write(state.join("jobs/1/stderr.log"), b"stderr\n").unwrap();
        let source = state.join("jobs/1/stdout.log");
        let path = CString::new(source.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let token = Id128::random().to_string();
        let controller = json!({"controller_uuid": Id128::random().to_string(), "epoch": 1});
        let record = json!({
            "controller": controller, "start_token": token, "job_id": 1, "node_id": "worker",
            "shared_root": shared, "tool_paths": [],
            "spec": {"queue":"test", "node":null, "name":"async-test", "cwd": shared,
                "stdout_path":"jobs/%j/stdout.log", "stderr_path":"jobs/%j/stderr.log",
                "walltime_secs":null, "env":{}, "mode":"batch", "snapshot":null},
            "phase":"IDLE", "authorized":true, "runner_pid":null, "runner_start_id":null,
            "child_pid":null, "child_start_id":null, "task_start_gated":true,
            "share_uuid":SHARE_ID, "storage_node_id":"worker", "storage_host":"127.0.0.1",
            "storage_source_root":shared, "terminal_state":"COMPLETED", "termination_cause":null,
            "exit_code":0, "end_reason":null, "cancel_requested":false, "force_cancel":false,
            "boot_id":"test-boot", "log_sync_pending":true, "log_sync_retry_after_unix_ms":null,
            "started_unix_ms":1
        });
        fs::write(
            state.join("agent-state.json"),
            serde_json::to_vec(&json!({
                "controller":controller, "active":record, "tombstones":[]
            }))
            .unwrap(),
        )
        .unwrap();
        let config = root.join("config.toml");
        fs::write(&config, format!(
            "[cluster]\nname=\"test\"\ndefault_queue=\"test\"\nshared_root=\"{}\"\nshare_uuid=\"{SHARE_ID}\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.test]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"127.0.0.1\"\ntransport=\"ssh\"\n", shared.display()
        )).unwrap();
        Self {
            root,
            state,
            shared,
            config,
            token,
        }
    }

    fn record(&self) -> Value {
        serde_json::from_slice::<Value>(&fs::read(self.state.join("agent-state.json")).unwrap())
            .unwrap()["active"]
            .clone()
    }

    fn status(&self) -> Result<Response, String> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_macluster"));
        command
            .arg("--config")
            .arg(&self.config)
            .arg("--state-dir")
            .arg(&self.state)
            .args(["internal", "agent-stdio", "--node", "worker"]);
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &Request {
                protocol_version: PROTOCOL_VERSION,
                request_id: RequestId(Id128::random()),
                operation: Operation::Status,
            },
        )
        .unwrap();
        let output = run_child_bounded(command, Some(input), Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        read_frame(&mut Cursor::new(output.stdout))
            .map_err(|e| e.to_string())?
            .ok_or("empty response".into())
    }

    fn worker(&self, idle_timeout_ms: u64) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_macluster"));
        command
            .arg("--state-dir")
            .arg(&self.state)
            .args(["internal", "log-sync", "--job-id", "1", "--start-token"])
            .arg(&self.token)
            .arg("--idle-timeout-ms")
            .arg(idle_timeout_ms.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    fn feed(&self, chunks: usize, delay: Duration) -> bool {
        let Some(mut writer) = self.fifo_writer() else {
            return false;
        };
        for _ in 0..chunks {
            if writer.write_all(b"delayed output\n").is_err() {
                return false;
            }
            thread::sleep(delay);
        }
        true
    }

    fn fifo_writer(&self) -> Option<File> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(self.state.join("jobs/1/stdout.log"))
            {
                Ok(file) => return Some(file),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(_) => return None,
            }
        }
    }

    fn wait_synced(&self) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.record()["log_sync_pending"] != false {
            assert!(
                Instant::now() < deadline,
                "publication never completed: {}",
                self.record()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Release a blocked fixture reader even when an assertion failed.
        let _ = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(self.state.join("jobs/1/stdout.log"));
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn wait_worker(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("worker did not terminate within its idle deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn status_returns_while_publication_is_blocked_and_worker_survives_agent_exit() {
    let fixture = Fixture::new();
    let began = Instant::now();
    let response = fixture.status();
    let elapsed = began.elapsed();
    let fed = fixture.feed(1, Duration::ZERO);
    let response = response.expect("blocked publication must not block Status");
    assert!(elapsed < Duration::from_secs(1), "Status took {elapsed:?}");
    let Ok(ResponseBody::Execution(status)) = response.result else {
        panic!("expected execution status");
    };
    assert!(status.log_sync_pending);
    assert!(fed, "agent did not start an independent log worker");
    fixture.wait_synced();
    assert_eq!(
        fs::read(fixture.shared.join("jobs/1/stdout.log")).unwrap(),
        b"delayed output\n"
    );
}

#[test]
fn stalled_worker_times_out_and_retains_retryable_state() {
    let fixture = Fixture::new();
    let mut worker = fixture.worker(200);
    let result = wait_worker(&mut worker);
    assert_eq!(result.signal(), Some(libc::SIGKILL));
    assert_eq!(fixture.record()["log_sync_pending"], true);
    assert!(
        fixture.record()["log_sync_retry_after_unix_ms"]
            .as_u64()
            .is_some()
    );
    // Restore storage and make the retry due without sleeping through the
    // production five-second backoff. The timed-out worker has been reaped.
    fs::remove_file(fixture.state.join("jobs/1/stdout.log")).unwrap();
    fs::write(
        fixture.state.join("jobs/1/stdout.log"),
        b"recovered output\n",
    )
    .unwrap();
    let path = fixture.state.join("agent-state.json");
    let mut store: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    store["active"]["log_sync_retry_after_unix_ms"] = json!(0);
    fs::write(path, serde_json::to_vec(&store).unwrap()).unwrap();
    assert!(fixture.status().unwrap().result.is_ok());
    fixture.wait_synced();
    assert_eq!(
        fs::read(fixture.shared.join("jobs/1/stdout.log")).unwrap(),
        b"recovered output\n"
    );
}

#[test]
fn duplicate_worker_exits_before_share_verification_and_status_stays_responsive() {
    let fixture = Fixture::new();
    let mut first = fixture.worker(3_000);
    // Opening the FIFO writer confirms the first worker already validated
    // the share and is now waiting for log bytes while holding the job lock.
    let mut writer = fixture
        .fifo_writer()
        .expect("first worker did not begin publication");
    fs::remove_file(fixture.shared.join(".macluster-share-id")).unwrap();
    let mut duplicate = fixture.worker(500);
    let duplicate_status = wait_worker(&mut duplicate);
    let mut stderr = String::new();
    duplicate
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(duplicate_status.code(), Some(1));
    assert!(
        stderr.contains("another process is synchronizing"),
        "duplicate touched the share before locking: {stderr}"
    );
    for _ in 0..3 {
        let start = Instant::now();
        let response = fixture.status().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(response.result.is_ok());
    }
    fs::write(fixture.shared.join(".macluster-share-id"), SHARE_ID).unwrap();
    writer.write_all(b"single publisher\n").unwrap();
    drop(writer);
    assert!(wait_worker(&mut first).success());
    fixture.wait_synced();
    assert_eq!(
        fs::read(fixture.shared.join("jobs/1/stdout.log")).unwrap(),
        b"single publisher\n"
    );
}

#[test]
fn ongoing_byte_progress_allows_a_transfer_longer_than_the_idle_timeout() {
    let fixture = Fixture::new();
    let mut worker = fixture.worker(250);
    let fed = fixture.feed(16, Duration::from_millis(50));
    let result = wait_worker(&mut worker);
    assert!(fed, "worker did not read the slow source");
    assert!(
        result.success(),
        "progressing transfer was terminated: {result}"
    );
    fixture.wait_synced();
    assert_eq!(
        fs::read(fixture.shared.join("jobs/1/stdout.log"))
            .unwrap()
            .len(),
        16 * b"delayed output\n".len()
    );
}

#[test]
fn reset_stops_blocked_publishers_and_prevents_delayed_workers_after_archive() {
    let fixture = Fixture::new();
    let mut worker = fixture.worker(10_000);
    let writer = fixture
        .fifo_writer()
        .expect("worker did not enter publication");
    let reset_id = Id128::random().to_string();
    let stopped = Command::new(env!("CARGO_BIN_EXE_macluster"))
        .arg("--state-dir")
        .arg(&fixture.state)
        .args([
            "internal",
            "stop-log-sync",
            "--share-id",
            SHARE_ID,
            "--reset-id",
        ])
        .arg(&reset_id)
        .output()
        .unwrap();
    if !stopped.status.success() {
        let _ = worker.kill();
        let _ = worker.wait();
    }
    assert!(
        stopped.status.success(),
        "reset did not quiesce publishers: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(wait_worker(&mut worker).signal(), Some(libc::SIGKILL));
    let mut delayed = fixture.worker(200);
    assert_eq!(wait_worker(&mut delayed).code(), Some(1));
    assert!(fixture.status().unwrap().result.is_ok());
    let archive = fixture.root.join("archived-agent");
    fs::rename(&fixture.state, &archive).unwrap();
    drop(writer);
    thread::sleep(Duration::from_millis(100));
    assert!(
        !fixture.state.exists(),
        "old publisher recreated reset state"
    );
}
