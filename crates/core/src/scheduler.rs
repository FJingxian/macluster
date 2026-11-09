//! Deterministic whole-node FIFO selection with node-local backfill.

use std::collections::BTreeSet;

use macluster_protocol::{
    identifiers::{NodeId, QueueName},
    types::{JobMode, JobRecord, JobState},
};

use crate::config::QueueConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeEligibility {
    pub id: NodeId,
    pub logical_cpus: Option<u32>,
    pub idle_since_unix_ms: u64,
    pub online: bool,
    pub agent_current: bool,
    /// Primary job storage is available. Named shares are checked per job.
    pub storage_ready: bool,
    pub configured_shares: BTreeSet<String>,
    pub ready_shares: BTreeSet<String>,
    pub drain_requested: bool,
    pub occupied: bool,
    pub interactive_pty: bool,
    pub namespaced_jobs: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispatch {
    pub job_id: u64,
    pub node_id: NodeId,
}

pub fn next_dispatch(
    queue: &QueueName,
    queue_config: &QueueConfig,
    jobs: &[JobRecord],
    nodes: &[NodeEligibility],
) -> Option<Dispatch> {
    let mut pending: Vec<_> = jobs
        .iter()
        .filter(|job| job.state == JobState::Pending && job.spec.queue == *queue)
        .collect();
    pending.sort_by_key(|job| job.id);
    let mut eligible_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| {
            queue_config
                .nodes
                .iter()
                .any(|member| member == node.id.as_str())
                && node.online
                && node.agent_current
                && node.storage_ready
                && !node.drain_requested
                && !node.occupied
        })
        .collect();
    eligible_nodes.sort_by(|left, right| {
        right
            .logical_cpus
            .unwrap_or_default()
            .cmp(&left.logical_cpus.unwrap_or_default())
            .then_with(|| right.idle_since_unix_ms.cmp(&left.idle_since_unix_ms))
            .then_with(|| left.id.cmp(&right.id))
    });

    // Preserve FIFO among runnable jobs, while allowing independent nodes to
    // backfill around an older job pinned to a busy or unreachable node. A
    // pending snapshot belongs to one job and must not stall the whole queue.
    for job in pending {
        if job.snapshot_sync_pending {
            continue;
        }
        let Some(node) = eligible_nodes.iter().find(|node| {
            (job.spec.mode != JobMode::Interactive || node.interactive_pty)
                && (job.spec.storage_namespace.is_none() || node.namespaced_jobs)
                && match &job.spec.required_shares {
                    Some(shares) => shares.iter().all(|share| node.ready_shares.contains(share)),
                    None => node.configured_shares.is_subset(&node.ready_shares),
                }
                && job
                    .spec
                    .node
                    .as_ref()
                    .is_none_or(|pinned| pinned == &node.id)
        }) else {
            continue;
        };
        return Some(Dispatch {
            job_id: job.id,
            node_id: node.id.clone(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use macluster_protocol::{
        identifiers::{NodeId, QueueName},
        types::{JobMode, JobRecord, JobSpec, JobState, SchedulerKind},
    };

    use super::{NodeEligibility, next_dispatch};
    use crate::config::QueueConfig;

    fn job(id: u64, pinned_node: Option<&str>) -> JobRecord {
        JobRecord {
            id,
            spec: JobSpec {
                storage_namespace: None,
                required_shares: Some(Vec::new()),
                queue: QueueName::new("default").unwrap(),
                node: pinned_node.map(|node| NodeId::new(node).unwrap()),
                name: format!("job-{id}"),
                cwd: "/shared".into(),
                stdout_path: "/shared/out".into(),
                stderr_path: "/shared/err".into(),
                walltime_secs: None,
                env: BTreeMap::new(),
                mode: JobMode::Interactive,
                snapshot: None,
            },
            state: JobState::Pending,
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

    fn node(id: &str, online: bool) -> NodeEligibility {
        NodeEligibility {
            id: NodeId::new(id).unwrap(),
            logical_cpus: Some(8),
            idle_since_unix_ms: 0,
            online,
            agent_current: true,
            storage_ready: true,
            configured_shares: BTreeSet::new(),
            ready_shares: BTreeSet::new(),
            drain_requested: false,
            occupied: false,
            interactive_pty: true,
            namespaced_jobs: true,
        }
    }

    fn queue() -> (QueueName, QueueConfig) {
        (
            QueueName::new("default").unwrap(),
            QueueConfig {
                nodes: vec!["default-001".into(), "default-003".into()],
                scheduler: SchedulerKind::Fifo,
            },
        )
    }

    #[test]
    fn dispatch_requires_only_the_shares_referenced_by_the_job() {
        let (queue, config) = queue();
        let mut task = job(1, Some("default-001"));
        task.spec.required_shares = Some(vec!["data".into(), "project".into()]);
        let mut compute = node("default-001", true);
        compute.configured_shares =
            BTreeSet::from(["data".into(), "project".into(), "unrelated".into()]);
        compute.ready_shares = BTreeSet::from(["data".into(), "project".into()]);

        assert_eq!(
            next_dispatch(&queue, &config, &[task.clone()], &[compute.clone()])
                .map(|dispatch| dispatch.node_id.to_string()),
            Some("default-001".into()),
            "an unrelated unavailable share must not hold this node's job back"
        );

        compute.ready_shares.remove("data");
        assert_eq!(
            next_dispatch(&queue, &config, &[task], &[compute]),
            None,
            "a share referenced by the job must be mounted before dispatch"
        );
    }

    #[test]
    fn unavailable_pinned_job_does_not_block_another_node() {
        let (queue_id, queue_config) = queue();
        let jobs = vec![job(639, Some("default-003")), job(640, None)];
        let nodes = [node("default-001", true), node("default-003", false)];

        let dispatch = next_dispatch(&queue_id, &queue_config, &jobs, &nodes)
            .expect("the eligible node should receive the next runnable job");

        assert_eq!(dispatch.job_id, 640);
        assert_eq!(dispatch.node_id.as_str(), "default-001");
    }

    #[test]
    fn unpublished_snapshot_does_not_block_another_ready_job() {
        let (queue_id, queue_config) = queue();
        let mut head = job(639, Some("default-003"));
        head.snapshot_sync_pending = true;
        let jobs = vec![head, job(640, None)];
        let nodes = [node("default-001", true), node("default-003", true)];

        let dispatch = next_dispatch(&queue_id, &queue_config, &jobs, &nodes)
            .expect("an independent ready job should bypass a pending snapshot");

        assert_eq!(dispatch.job_id, 640);
        assert_eq!(dispatch.node_id.as_str(), "default-001");
    }

    #[test]
    fn available_pinned_job_keeps_fifo_priority() {
        let (queue_id, queue_config) = queue();
        let jobs = vec![job(639, Some("default-003")), job(640, None)];
        let nodes = [node("default-001", true), node("default-003", true)];

        let dispatch = next_dispatch(&queue_id, &queue_config, &jobs, &nodes)
            .expect("the oldest runnable job should dispatch first");

        assert_eq!(dispatch.job_id, 639);
        assert_eq!(dispatch.node_id.as_str(), "default-003");
    }
}
