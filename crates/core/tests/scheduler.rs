use std::collections::BTreeMap;

use macluster_core::{
    config::QueueConfig,
    scheduler::{NodeEligibility, next_dispatch},
};
use macluster_protocol::{
    identifiers::{NodeId, QueueName},
    types::{JobMode, JobRecord, JobSpec, JobState, SchedulerKind, SnapshotRef},
};

fn job(id: u64, queue: &str, pin: Option<&str>, state: JobState) -> JobRecord {
    JobRecord {
        id,
        spec: JobSpec {
            storage_namespace: None,
            queue: QueueName::new(queue).unwrap(),
            node: pin.map(|node| NodeId::new(node).unwrap()),
            name: format!("job-{id}"),
            cwd: "/share/projects".into(),
            stdout_path: "/share/jobs/%j/out".into(),
            stderr_path: "/share/jobs/%j/err".into(),
            walltime_secs: None,
            env: BTreeMap::new(),
            mode: JobMode::Batch,
            snapshot: Some(SnapshotRef {
                sha256: "a".repeat(64),
                size_bytes: 1,
            }),
        },
        state,
        node: None,
        start_token: None,
        cancel_force: false,
        created_unix_ms: id,
        started_unix_ms: None,
        finished_unix_ms: None,
        exit_code: None,
        end_reason: None,
        snapshot_sync_pending: false,
        log_sync_pending: false,
        waiting_reason: None,
    }
}

fn nodes() -> Vec<NodeEligibility> {
    vec![
        NodeEligibility {
            id: NodeId::new("mini01-a").unwrap(),
            idle_since_unix_ms: 10,
            online: true,
            storage_ready: true,
            drain_requested: false,
            occupied: false,
            interactive_pty: false,
            namespaced_jobs: true,
        },
        NodeEligibility {
            id: NodeId::new("mini01-b").unwrap(),
            idle_since_unix_ms: 20,
            online: true,
            storage_ready: true,
            drain_requested: false,
            occupied: false,
            interactive_pty: false,
            namespaced_jobs: true,
        },
    ]
}

#[test]
fn namespaced_jobs_wait_for_an_agent_with_matching_storage_support() {
    let mut job = job(1, "mini01", None, JobState::Pending);
    job.spec.storage_namespace = Some(macluster_protocol::identifiers::Id128::random());
    let mut nodes = nodes();
    for node in &mut nodes {
        node.namespaced_jobs = false;
    }
    let queue = QueueName::new("mini01").unwrap();
    assert!(next_dispatch(&queue, &queue_config(), &[job.clone()], &nodes).is_none());
    nodes[0].namespaced_jobs = true;
    assert_eq!(
        next_dispatch(&queue, &queue_config(), &[job], &nodes)
            .unwrap()
            .node_id,
        nodes[0].id
    );
}

fn queue_config() -> QueueConfig {
    QueueConfig {
        nodes: vec!["mini01-a".into(), "mini01-b".into()],
        scheduler: SchedulerKind::Fifo,
    }
}

#[test]
fn fifo_head_blocks_later_pinned_job_without_backfill() {
    let queue = QueueName::new("mini01").unwrap();
    let jobs = vec![
        job(9, "mini01", Some("mini01-a"), JobState::Pending),
        job(10, "mini01", Some("mini01-b"), JobState::Pending),
    ];
    let availability = vec![nodes()[1].clone()];
    assert_eq!(
        next_dispatch(&queue, &queue_config(), &jobs, &availability),
        None
    );
}

#[test]
fn scheduler_chooses_longest_idle_eligible_node_and_respects_exclusivity() {
    let queue = QueueName::new("mini01").unwrap();
    let jobs = vec![
        job(2, "mini01", None, JobState::Pending),
        job(1, "mini01", None, JobState::Pending),
    ];
    let mut availability = nodes();
    availability[1].occupied = true;
    let dispatch = next_dispatch(&queue, &queue_config(), &jobs, &availability).unwrap();
    assert_eq!(dispatch.job_id, 1);
    assert_eq!(dispatch.node_id.as_str(), "mini01-a");
}

#[test]
fn drain_and_storage_health_exclude_nodes_from_dispatch() {
    let queue = QueueName::new("mini01").unwrap();
    let jobs = vec![job(1, "mini01", None, JobState::Pending)];
    let mut availability = nodes();
    for node in &mut availability {
        node.drain_requested = true;
    }
    assert_eq!(
        next_dispatch(&queue, &queue_config(), &jobs, &availability),
        None
    );
    for node in &mut availability {
        node.drain_requested = false;
        node.storage_ready = false;
    }
    assert_eq!(
        next_dispatch(&queue, &queue_config(), &jobs, &availability),
        None
    );
}

#[test]
fn interactive_job_skips_nodes_without_pty_capability() {
    let queue = QueueName::new("mini01").unwrap();
    let mut interactive = job(1, "mini01", None, JobState::Pending);
    interactive.spec.mode = JobMode::Interactive;
    let mut availability = nodes();
    availability[1].interactive_pty = true;

    let dispatch = next_dispatch(
        &queue,
        &queue_config(),
        &[interactive.clone()],
        &availability,
    )
    .unwrap();
    assert_eq!(dispatch.node_id.as_str(), "mini01-b");

    assert_eq!(
        next_dispatch(&queue, &queue_config(), &[interactive], &availability[..1]),
        None
    );
}

#[test]
fn batch_job_remains_eligible_on_node_without_pty_capability() {
    let queue = QueueName::new("mini01").unwrap();
    let availability = nodes();

    let dispatch = next_dispatch(
        &queue,
        &queue_config(),
        &[job(1, "mini01", None, JobState::Pending)],
        &availability[..1],
    )
    .unwrap();

    assert_eq!(dispatch.node_id.as_str(), "mini01-a");
}
