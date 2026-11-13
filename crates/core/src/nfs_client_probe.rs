use crate::{config::ClusterConfig, storage_uri::StorageProtocol};
use macluster_protocol::types::{NfsClientDiagnosis, NfsProbeState, NfsShareProbe};
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

pub fn diagnose_nfs_client(
    config: &ClusterConfig,
    node_id: &str,
    timeout: Duration,
) -> Result<NfsClientDiagnosis, String> {
    if !config.nodes.contains_key(node_id) {
        return Err(format!("node '{node_id}' is not registered"));
    }
    let mut probes = Vec::new();
    if config.storage_server.as_str() != node_id {
        let marker_target = &config.shared_root;
        probes.push(probe_share(
            "primary",
            marker_target,
            &config.share_uuid,
            timeout,
        ));
    }
    for (share_id, share) in &config.shares {
        if share.protocol != StorageProtocol::Nfs || share.server.as_str() == node_id {
            continue;
        }
        probes.push(probe_share(
            share_id,
            &share.mount_root,
            &share.share_uuid,
            timeout,
        ));
    }
    Ok(NfsClientDiagnosis {
        node_id: node_id.to_owned(),
        wedged: probes
            .iter()
            .any(|probe| probe.state == NfsProbeState::Wedged),
        probes,
    })
}

fn probe_share(
    share_id: &str,
    target: &Path,
    expected_uuid: &str,
    timeout: Duration,
) -> NfsShareProbe {
    let marker = target.join(".macluster-share-id");
    let mut command = Command::new("/bin/cat");
    command
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match run_bounded_probe_command(command, timeout) {
        Ok(output) => {
            let state = classify_probe_result(
                output.status.success(),
                &output.stdout,
                &output.stderr,
                expected_uuid,
            );
            let error = (!output.stderr.is_empty())
                .then(|| bounded_text(&output.stderr))
                .filter(|value| !value.is_empty());
            NfsShareProbe {
                share_id: share_id.to_owned(),
                target: target.to_string_lossy().into_owned(),
                state,
                error,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => NfsShareProbe {
            share_id: share_id.to_owned(),
            target: target.to_string_lossy().into_owned(),
            state: NfsProbeState::TimedOut,
            error: Some(format!(
                "NFS marker read timed out after {} ms",
                timeout.as_millis()
            )),
        },
        Err(error) => NfsShareProbe {
            share_id: share_id.to_owned(),
            target: target.to_string_lossy().into_owned(),
            state: NfsProbeState::Unavailable,
            error: Some(error.to_string()),
        },
    }
}

fn classify_probe_result(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    expected_uuid: &str,
) -> NfsProbeState {
    if success {
        return if String::from_utf8_lossy(stdout).trim() == expected_uuid {
            NfsProbeState::Healthy
        } else {
            NfsProbeState::Unavailable
        };
    }
    let error = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if error.contains("interrupted system call")
        || error.contains("errno 4")
        || error.contains("eintr")
    {
        NfsProbeState::Wedged
    } else {
        NfsProbeState::Unavailable
    }
}

fn bounded_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars().take(1024).collect()
}

fn run_bounded_probe_command(mut command: Command, timeout: Duration) -> io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.process_group(0);
    let mut child = command.spawn()?;
    let process_group = child.id() as libc::pid_t;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("probe stderr was not piped"))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "NFS probe command timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("probe stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("probe stderr reader panicked"))??;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_capped(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(kept);
        }
        let remaining = MAX_PROBE_OUTPUT_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ClusterConfig;
    use macluster_protocol::types::NfsProbeState;

    use super::{classify_probe_result, diagnose_nfs_client, run_bounded_probe_command};
    use std::{fs, process::Command, time::Duration};

    #[test]
    fn nfs_probe_classifier_marks_only_eintr_as_wedged() {
        let expected = "00000000-0000-4000-8000-000000000001";
        assert_eq!(
            classify_probe_result(true, expected.as_bytes(), &[], expected,),
            NfsProbeState::Healthy
        );
        assert_eq!(
            classify_probe_result(
                false,
                &[],
                b"cat: marker: Interrupted system call",
                expected,
            ),
            NfsProbeState::Wedged
        );
        assert_eq!(
            classify_probe_result(
                false,
                &[],
                b"cat: marker: No such file or directory",
                expected,
            ),
            NfsProbeState::Unavailable
        );
        assert_eq!(
            classify_probe_result(false, &[], b"cat: marker: Permission denied", expected,),
            NfsProbeState::Unavailable
        );
    }

    #[test]
    fn nfs_probe_runner_kills_a_stalled_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        let started = std::time::Instant::now();
        let error = run_bounded_probe_command(command, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn nfs_diagnosis_probes_primary_and_each_remote_nfs_share() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-probe-{}",
            macluster_protocol::identifiers::Id128::random()
        ));
        let primary = root.join("primary");
        let tools = root.join("tools");
        fs::create_dir_all(&primary).unwrap();
        fs::create_dir_all(&tools).unwrap();
        let primary_uuid = "00000000-0000-4000-8000-000000000001";
        let tools_uuid = "00000000-0000-4000-8000-000000000002";
        fs::write(primary.join(".macluster-share-id"), primary_uuid).unwrap();
        fs::write(tools.join(".macluster-share-id"), tools_uuid).unwrap();
        let source = format!(
            "[cluster]\nname=\"test\"\ndefault_queue=\"compute\"\nlogin_node=\"login\"\nshared_root=\"{}\"\nshare_uuid=\"{}\"\nstorage_server=\"login\"\nprotocol_version=1\n\n[queues.compute]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/bin/true\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n\n[nodes.worker]\nhost=\"192.0.2.2\"\ntransport=\"ssh\"\nremote_binary=\"/bin/true\"\nssh_user=\"test\"\n\n[shares.tools]\nprotocol=\"nfs\"\nserver=\"login\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"{}\"\n",
            primary.display(),
            primary_uuid,
            tools.display(),
            tools.display(),
            tools_uuid,
        );
        let config = ClusterConfig::parse(&source).unwrap();

        let diagnosis = diagnose_nfs_client(&config, "worker", Duration::from_millis(500))
            .expect("configured NFS probes");

        assert!(!diagnosis.wedged);
        assert_eq!(diagnosis.probes.len(), 2);
        assert!(
            diagnosis
                .probes
                .iter()
                .all(|probe| probe.state == NfsProbeState::Healthy)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
