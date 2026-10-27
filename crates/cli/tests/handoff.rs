#![cfg(target_os = "macos")]

use macluster_controller::transport::run_child_bounded;
use macluster_protocol::{
    framing::{read_frame, sha256_hex, write_frame},
    identifiers::{ControllerUuid, Id128, RequestId, StartToken},
    types::{
        ControllerEpoch, JobSpec, JobState, Operation, PROTOCOL_VERSION, ProtocolError, Request,
        Response, ResponseBody,
    },
};
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    shared: PathBuf,
    state: PathBuf,
    uuid: String,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("macluster-handoff-flow-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let output = Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
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
        let shared = root.join("shared");
        fs::create_dir(&shared).unwrap();
        Self {
            state: root.join("agent"),
            root,
            shared,
            uuid,
        }
    }
    fn config(&self, namespace: Id128) -> PathBuf {
        let path = self.root.join(format!("{namespace}.toml"));
        fs::write(&path,format!("[cluster]\nname=\"handoff\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"{namespace}\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"{}\"\nmachine_uuid=\"{}\"\nexecution_uid={}\n",self.shared.display(),env!("CARGO_BIN_EXE_macluster"),self.uuid,unsafe{libc::geteuid()})).unwrap();
        path
    }
    fn rpc(&self, config: &Path, operation: Operation) -> Result<ResponseBody, ProtocolError> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_macluster"));
        cmd.arg("--config")
            .arg(config)
            .arg("--state-dir")
            .arg(&self.state)
            .args(["internal", "agent-stdio", "--node", "worker"]);
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &Request {
                protocol_version: PROTOCOL_VERSION,
                request_id: RequestId::random(),
                operation,
            },
        )
        .unwrap();
        let output = run_child_bounded(cmd, Some(bytes), Duration::from_secs(5)).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        read_frame::<_, Response>(&mut Cursor::new(output.stdout))
            .unwrap()
            .unwrap()
            .result
    }
    fn claim(&self, config: &Path, controller: ControllerEpoch) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_macluster"))
            .arg("--config")
            .arg(config)
            .arg("--state-dir")
            .arg(&self.state)
            .args([
                "internal",
                "claim-agent",
                "--node",
                "worker",
                "--controller",
                &controller.controller_uuid.to_string(),
                "--epoch",
                &controller.epoch.to_string(),
            ])
            .output()
            .unwrap()
    }
    fn archive(&self, namespace: Id128) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_macluster"))
            .arg("--state-dir")
            .arg(&self.state)
            .args([
                "internal",
                "archive-agent-state",
                "--share-id",
                &namespace.to_string(),
                "--archive",
            ])
            .arg(self.root.join("reset-archive"))
            .output()
            .unwrap()
    }
    fn start(&self, config: &Path, namespace: Id128, controller: ControllerEpoch, script: &str) {
        fs::write(
            self.shared.join(".macluster-share-id"),
            namespace.to_string(),
        )
        .unwrap();
        let spec:JobSpec=serde_json::from_value(serde_json::json!({
            "storage_namespace":namespace,"queue":"q","node":null,"name":"handoff smoke","cwd":self.shared,
            "stdout_path":self.shared.join(format!("jobs/{namespace}/%j/stdout.log")),"stderr_path":self.shared.join(format!("jobs/{namespace}/%j/stderr.log")),
            "walltime_secs":10,"env":{"PATH":"/usr/bin:/bin"},"mode":"batch","snapshot":{"sha256":sha256_hex(script.as_bytes()).unwrap(),"size_bytes":script.len()}
        })).unwrap();
        let directory = spec.shared_job_dir(&self.shared, 1);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("script.sh"), script).unwrap();
        assert!(matches!(
            self.rpc(
                config,
                Operation::StartJob {
                    controller,
                    start_token: StartToken::random(),
                    job_id: 1,
                    spec
                }
            ),
            Ok(ResponseBody::Started(_))
        ));
    }
    fn finish(&self, config: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let Ok(ResponseBody::Execution(status)) = self.rpc(config, Operation::Status) else {
                panic!("missing execution status")
            };
            if let Some(terminal) = status.terminal_state {
                assert_eq!(terminal, JobState::Completed, "{:?}", status.end_reason);
                if !status.log_sync_pending {
                    return;
                }
            }
            assert!(Instant::now() < deadline, "task did not finish/sync");
            thread::sleep(Duration::from_millis(30));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn busy_foreign_reset_and_idle_handoff_preserve_previous_job_one() {
    let f = Fixture::new();
    let a = Id128::random();
    let b = Id128::random();
    let cfg_a = f.config(a);
    let cfg_b = f.config(b);
    let owner_a = ControllerEpoch {
        controller_uuid: ControllerUuid::random(),
        epoch: 1,
    };
    let owner_b = ControllerEpoch {
        controller_uuid: ControllerUuid::random(),
        epoch: 1,
    };
    assert!(matches!(
        f.rpc(
            &cfg_a,
            Operation::Fence {
                controller: owner_a
            }
        ),
        Ok(ResponseBody::Ack)
    ));
    let release = f.root.join("release-A");
    let script = format!(
        "#!/bin/sh\nprintf 'from-A\\n'\nwhile [ ! -e '{}' ]; do /bin/sleep 0.05; done\n",
        release.display()
    );
    f.start(&cfg_a, a, owner_a, &script);
    let busy = f.claim(&cfg_b, owner_b);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("active job"));
    let preserved = f.archive(b);
    assert!(
        preserved.status.success(),
        "{}",
        String::from_utf8_lossy(&preserved.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&preserved.stdout).trim(),
        "\"preserved_foreign\""
    );
    assert!(!f.root.join("reset-archive").exists());
    fs::write(&release, b"release").unwrap();
    f.finish(&cfg_a);
    let claimed = f.claim(&cfg_b, owner_b);
    assert!(
        claimed.status.success(),
        "{}",
        String::from_utf8_lossy(&claimed.stderr)
    );
    assert!(
        f.rpc(
            &cfg_a,
            Operation::Fence {
                controller: owner_a
            }
        )
        .is_err()
    );
    assert!(matches!(
        f.rpc(
            &cfg_b,
            Operation::Fence {
                controller: owner_b
            }
        ),
        Ok(ResponseBody::Ack)
    ));
    f.start(&cfg_b, b, owner_b, "#!/bin/sh\nprintf 'from-B\\n'\n");
    f.finish(&cfg_b);
    assert_eq!(
        fs::read_to_string(f.shared.join(format!("jobs/{a}/1/stdout.log"))).unwrap(),
        "from-A\n"
    );
    assert_eq!(
        fs::read_to_string(f.shared.join(format!("jobs/{b}/1/stdout.log"))).unwrap(),
        "from-B\n"
    );
    // Handoff must also retain the node-local A output despite B reusing ID 1.
    let history = f.root.join("agent-history");
    let retained = fs::read_dir(history).unwrap().any(|entry| {
        fs::read_to_string(entry.unwrap().path().join("jobs/1/stdout.log"))
            .is_ok_and(|data| data == "from-A\n")
    });
    assert!(
        retained,
        "old local output was overwritten instead of preserved"
    );
    let archived = f.archive(b);
    assert!(
        archived.status.success(),
        "{}",
        String::from_utf8_lossy(&archived.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&archived.stdout).trim(),
        "\"archived\""
    );
    assert!(
        f.rpc(
            &cfg_a,
            Operation::Fence {
                controller: owner_a
            }
        )
        .is_err()
    );
    assert!(
        f.rpc(
            &cfg_b,
            Operation::Fence {
                controller: owner_b
            }
        )
        .is_err()
    );
}
