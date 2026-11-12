use crate::node_admin::{AppResult, remote_execution_status};
use macluster_controller::transport::{ClusterTransport, NodeTransport};
use macluster_core::{config::ClusterConfig, storage::Storage, storage_uri::StorageProtocol};
use macluster_protocol::{
    identifiers::NodeId,
    types::{
        ExecutionStatus, JobRecord, NfsClientDiagnosis, NfsProbeState, NodeHealth, Operation,
        ResponseBody, RuntimePhase,
    },
};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const DIAGNOSIS_TIMEOUT: Duration = Duration::from_secs(20);
const REBOOT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(180);
const REBOOT_POLL_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn repair_nfs_client(
    config_path: &Path,
    state_dir: &Path,
    node_id: &NodeId,
    assume_yes: bool,
) -> AppResult<()> {
    let source = fs::read_to_string(config_path).map_err(|error| {
        (
            1,
            format!(
                "cannot read cluster config {}: {error}",
                config_path.display()
            ),
        )
    })?;
    let config = ClusterConfig::parse(&source)
        .map_err(|error| (2, format!("invalid cluster config: {error}")))?;
    let node = config
        .nodes
        .get(node_id.as_str())
        .ok_or_else(|| (2, format!("node '{}' is not registered", node_id.as_str())))?;
    if config.is_login_node(node_id.as_str())
        || config.storage_server.as_str() == node_id.as_str()
        || node.transport == macluster_core::config::Transport::Local
        || !config.is_compute_node(node_id.as_str())
    {
        return Err((
            2,
            "NFS client reboot recovery is limited to non-login SSH compute nodes".into(),
        ));
    }

    let mut transport =
        ClusterTransport::new_with_namespace(config_path.to_path_buf(), config.share_uuid.clone());
    transport.timeout = DIAGNOSIS_TIMEOUT;
    let diagnosis = diagnose(&transport, &config, node_id)?;
    let storage = Storage::open(state_dir)
        .map_err(|error| (1, format!("cannot read controller job state: {error}")))?;
    let jobs = storage
        .list_active_jobs()
        .map_err(|error| (1, format!("cannot inspect active jobs: {error}")))?;
    let status = remote_execution_status(node, node_id.as_str(), config_path)
        .map_err(|(code, error)| (code, format!("cannot inspect remote idle state: {error}")))?;
    nfs_repair_eligible(&diagnosis, &jobs, status.as_ref()).map_err(|error| (1, error))?;

    let wedged = diagnosis
        .probes
        .iter()
        .find(|probe| probe.state == NfsProbeState::Wedged);
    if let Some(probe) = wedged {
        eprintln!(
            "NFS client wedge detected on {}: {}{}",
            node_id.as_str(),
            probe.target,
            probe
                .error
                .as_deref()
                .map(|error| format!(" ({error})"))
                .unwrap_or_default()
        );
    }
    let confirmed = authorize_nfs_repair(io::stdin().is_terminal(), assume_yes, || {
        eprint!("The node is idle. Reboot {} now? [y/N]: ", node_id.as_str());
        io::stderr().flush().map_err(|error| error.to_string())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?;
        Ok(crate::node_admin::shutdown_confirmation_accepted(&answer))
    })
    .map_err(|error| (2, error))?;
    if !confirmed {
        println!("NFS client reboot cancelled.");
        return Ok(());
    }

    let controller = storage
        .current_controller_epoch()
        .map_err(|error| (1, format!("cannot read controller epoch: {error}")))?
        .ok_or_else(|| (1, "the controller has no active epoch".into()))?;
    match transport.call(node_id, node, Operation::RebootForNfsRepair { controller }) {
        Ok(ResponseBody::Ack) => {}
        Ok(other) => {
            return Err((
                1,
                format!("node Agent returned an unexpected reboot response: {other:?}"),
            ));
        }
        Err(error) => return Err((1, format!("cannot request NFS client reboot: {error}"))),
    }
    println!(
        "Reboot scheduled for {}. Waiting up to 180s for reconnect and NFS recovery…",
        node_id.as_str()
    );
    wait_for_nfs_recovery(&transport, &config, node_id, node).map_err(|error| (1, error))?;
    println!(
        "NFS client recovery complete on {}; all configured NFS markers are readable.",
        node_id.as_str()
    );
    Ok(())
}

fn diagnose(
    transport: &ClusterTransport,
    config: &ClusterConfig,
    node_id: &NodeId,
) -> AppResult<NfsClientDiagnosis> {
    let node = config
        .nodes
        .get(node_id.as_str())
        .ok_or_else(|| (2, format!("node '{}' is not registered", node_id.as_str())))?;
    match transport.call(node_id, node, Operation::DiagnoseNfs) {
        Ok(ResponseBody::NfsDiagnosis(diagnosis)) => Ok(diagnosis),
        Ok(other) => Err((
            1,
            format!("node Agent returned an unexpected diagnosis response: {other:?}"),
        )),
        Err(error) => Err((1, format!("cannot diagnose NFS client state: {error}"))),
    }
}

fn wait_for_nfs_recovery(
    transport: &ClusterTransport,
    config: &ClusterConfig,
    node_id: &NodeId,
    node: &macluster_core::config::NodeConfig,
) -> Result<(), String> {
    let deadline = Instant::now() + REBOOT_RECONNECT_TIMEOUT;
    let mut disconnected = false;
    let mut last_status = "waiting for reboot to begin".to_owned();
    while Instant::now() < deadline {
        thread::sleep(REBOOT_POLL_INTERVAL);
        let health = match transport.call(node_id, node, Operation::Health) {
            Ok(ResponseBody::Health(health)) => health,
            Ok(other) => {
                last_status = format!("unexpected health response: {other:?}");
                continue;
            }
            Err(error) => {
                if !disconnected {
                    println!(
                        "Node {} disconnected; waiting for reboot.",
                        node_id.as_str()
                    );
                }
                disconnected = true;
                last_status = error.to_string();
                continue;
            }
        };
        if !disconnected {
            last_status = "node has not rebooted yet".into();
            continue;
        }
        if !nfs_health_ready(config, node_id.as_str(), &health) {
            last_status = "node reconnected, but configured NFS mounts are not ready".into();
            continue;
        }
        match diagnose(transport, config, node_id) {
            Ok(diagnosis)
                if !diagnosis.wedged
                    && diagnosis
                        .probes
                        .iter()
                        .all(|probe| probe.state == NfsProbeState::Healthy) =>
            {
                return Ok(());
            }
            Ok(diagnosis) => {
                last_status = format!("NFS probes have not recovered: {diagnosis:?}");
            }
            Err((_, error)) => last_status = error,
        }
    }
    Err(format!(
        "node {} did not complete NFS recovery within 180s: {last_status}",
        node_id.as_str()
    ))
}

fn nfs_health_ready(config: &ClusterConfig, node_id: &str, health: &NodeHealth) -> bool {
    if health.build_id.as_deref() != Some(macluster_protocol::BUILD_ID)
        || health.execution_digest != config.execution_digest().unwrap_or_else(|_| String::new())
        || config
            .nodes
            .get(node_id)
            .and_then(|node| node.machine_uuid.as_deref())
            .is_some_and(|uuid| !uuid.eq_ignore_ascii_case(&health.machine_uuid))
    {
        return false;
    }
    if config.storage_server.as_str() != node_id && !health.primary_share_ready {
        return false;
    }
    config.shares.iter().all(|(share_id, share)| {
        share.protocol != StorageProtocol::Nfs
            || share.server.as_str() == node_id
            || health.shares.get(share_id).copied() == Some(true)
    })
}

fn nfs_repair_eligible(
    diagnosis: &NfsClientDiagnosis,
    active_jobs: &[JobRecord],
    status: Option<&ExecutionStatus>,
) -> Result<(), String> {
    if !diagnosis.wedged {
        if diagnosis
            .probes
            .iter()
            .any(|probe| probe.state == NfsProbeState::TimedOut)
        {
            return Err(
                "NFS read probe timed out; timeout alone does not qualify for automatic reboot"
                    .into(),
            );
        }
        return Err("no macOS NFS client EINTR wedge was detected".into());
    }
    if active_jobs.iter().any(|job| {
        let targets_node = job
            .spec
            .node
            .as_ref()
            .is_some_and(|node| node.as_str() == diagnosis.node_id)
            || job
                .node
                .as_ref()
                .is_some_and(|node| node.as_str() == diagnosis.node_id);
        targets_node
            && (!job.state.is_terminal() || job.snapshot_sync_pending || job.log_sync_pending)
    }) {
        return Err(format!(
            "node {} still has an active job or pending output synchronization",
            diagnosis.node_id
        ));
    }
    if let Some(status) = status
        && (status.phase != RuntimePhase::Idle || status.log_sync_pending)
    {
        return Err(format!(
            "node {} remote execution state is {:?} with log_sync_pending={}",
            diagnosis.node_id, status.phase, status.log_sync_pending
        ));
    }
    Ok(())
}

fn authorize_nfs_repair(
    stdin_is_terminal: bool,
    assume_yes: bool,
    prompt: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    if assume_yes {
        return Ok(true);
    }
    if !stdin_is_terminal {
        return Err(
            "NFS reboot confirmation requires a terminal; pass --yes only when reboot is explicitly intended"
                .into(),
        );
    }
    prompt()
}

#[cfg(test)]
mod tests {
    use super::{authorize_nfs_repair, nfs_repair_eligible};
    use macluster_protocol::{
        identifiers::{Id128, StartToken},
        types::{
            ExecutionStatus, JobRecord, JobState, NfsClientDiagnosis, NfsProbeState, NfsShareProbe,
            RuntimePhase,
        },
    };
    use serde_json::json;

    fn diagnosis(state: NfsProbeState) -> NfsClientDiagnosis {
        NfsClientDiagnosis {
            node_id: "worker".into(),
            wedged: state == NfsProbeState::Wedged,
            probes: vec![NfsShareProbe {
                share_id: "primary".into(),
                target: "/shared".into(),
                state,
                error: (state != NfsProbeState::Healthy).then(|| state_name(state).into()),
            }],
        }
    }

    fn state_name(state: NfsProbeState) -> &'static str {
        match state {
            NfsProbeState::Healthy => "healthy",
            NfsProbeState::Wedged => "wedged",
            NfsProbeState::TimedOut => "timed out",
            NfsProbeState::Unavailable => "unavailable",
        }
    }

    fn job(state: JobState, log_sync_pending: bool) -> JobRecord {
        serde_json::from_value(json!({
            "id": 1,
            "spec": {
                "queue": "compute",
                "node": "worker",
                "name": "job",
                "cwd": "/shared",
                "stdout_path": "/shared/out",
                "stderr_path": "/shared/err",
                "walltime_secs": null,
                "env": {}
            },
            "state": state,
            "node": "worker",
            "created_unix_ms": 1,
            "snapshot_sync_pending": false,
            "log_sync_pending": log_sync_pending
        }))
        .unwrap()
    }

    fn status(phase: RuntimePhase, log_sync_pending: bool) -> ExecutionStatus {
        ExecutionStatus {
            start_token: StartToken(Id128::random()),
            job_id: 1,
            phase,
            terminal_state: None,
            boot_id: "boot".into(),
            runner_pid: None,
            child_pid: None,
            exit_code: None,
            end_reason: None,
            log_sync_pending,
        }
    }

    #[test]
    fn repair_nfs_eligibility_requires_wedge_idle_and_no_pending_output() {
        assert!(nfs_repair_eligible(&diagnosis(NfsProbeState::Healthy), &[], None).is_err());
        assert!(nfs_repair_eligible(&diagnosis(NfsProbeState::TimedOut), &[], None).is_err());
        assert!(
            nfs_repair_eligible(
                &diagnosis(NfsProbeState::Wedged),
                &[job(JobState::Running, false)],
                None,
            )
            .is_err()
        );
        assert!(
            nfs_repair_eligible(
                &diagnosis(NfsProbeState::Wedged),
                &[job(JobState::Completed, true)],
                None,
            )
            .is_err()
        );
        assert!(
            nfs_repair_eligible(
                &diagnosis(NfsProbeState::Wedged),
                &[],
                Some(&status(RuntimePhase::Running, false)),
            )
            .is_err()
        );
        assert!(
            nfs_repair_eligible(
                &diagnosis(NfsProbeState::Wedged),
                &[],
                Some(&status(RuntimePhase::Idle, false)),
            )
            .is_ok()
        );
    }

    #[test]
    fn repair_nfs_confirmation_requires_tty_or_explicit_yes() {
        assert!(authorize_nfs_repair(false, false, || Ok(true)).is_err());
        assert_eq!(
            authorize_nfs_repair(false, true, || Ok(false)).unwrap(),
            true
        );
        assert_eq!(
            authorize_nfs_repair(true, false, || Ok(false)).unwrap(),
            false
        );
        assert_eq!(
            authorize_nfs_repair(true, false, || Ok(true)).unwrap(),
            true
        );
    }
}
