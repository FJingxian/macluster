//! Deterministic whole-node FIFO selection.

use macluster_protocol::{
    identifiers::{NodeId, QueueName},
    types::{JobMode, JobRecord, JobState},
};

use crate::config::QueueConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeEligibility {
    pub id: NodeId,
    pub idle_since_unix_ms: u64,
    pub online: bool,
    pub storage_ready: bool,
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
    let head = pending.first()?;
    if head.snapshot_sync_pending {
        return None;
    }
    let mut eligible: Vec<_> = nodes
        .iter()
        .filter(|node| {
            queue_config
                .nodes
                .iter()
                .any(|member| member == node.id.as_str())
                && node.online
                && node.storage_ready
                && !node.drain_requested
                && !node.occupied
                && (head.spec.mode != JobMode::Interactive || node.interactive_pty)
                && (head.spec.storage_namespace.is_none() || node.namespaced_jobs)
                && head
                    .spec
                    .node
                    .as_ref()
                    .is_none_or(|pinned| pinned == &node.id)
        })
        .collect();
    eligible.sort_by(|left, right| {
        right
            .idle_since_unix_ms
            .cmp(&left.idle_since_unix_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    eligible.first().map(|node| Dispatch {
        job_id: head.id,
        node_id: node.id.clone(),
    })
}
