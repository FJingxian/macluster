//! Submission admission shared by online controller requests and offline batch fallback.

use std::path::{Component, Path};

use macluster_protocol::{
    identifiers::RequestId,
    types::{JobRecord, JobSpec},
};
use thiserror::Error;

use crate::{
    config::ClusterConfig,
    storage::{Storage, SubmitError},
};

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("submission uses a different shared-storage namespace")]
    StorageNamespace,
    #[error("queue '{0}' is not configured")]
    UnknownQueue(String),
    #[error("login node '{0}' cannot accept jobs; select a compute node")]
    LoginNode(String),
    #[error("node '{node}' is not a member of queue '{queue}'")]
    NodeNotInQueue { node: String, queue: String },
    #[error("job {field} path must be absolute and inside a configured shared path")]
    InvalidSharedPath { field: &'static str },
    #[error("submission storage error: {0}")]
    Storage(#[from] SubmitError),
}

/// Validate controller-owned scheduling/storage invariants before durable admission.
/// The CLI still performs richer filesystem/canonical-path checks for the submitter's
/// environment; the controller repeats the invariants that can be checked from config.
pub fn admit_submission(
    storage: &Storage,
    config: &ClusterConfig,
    request_id: RequestId,
    spec: JobSpec,
) -> Result<JobRecord, AdmissionError> {
    let expected_namespace = macluster_protocol::identifiers::Id128::parse(&config.share_uuid)
        .expect("ClusterConfig validates share_uuid");
    if spec.storage_namespace != Some(expected_namespace) {
        return Err(AdmissionError::StorageNamespace);
    }

    let queue = config
        .queue_for_dispatch(spec.queue.as_str())
        .ok_or_else(|| AdmissionError::UnknownQueue(spec.queue.to_string()))?;
    if let Some(node) = &spec.node {
        if config.is_login_node(node.as_str()) {
            return Err(AdmissionError::LoginNode(node.to_string()));
        }
        if !queue.nodes.iter().any(|member| member == node.as_str()) {
            return Err(AdmissionError::NodeNotInQueue {
                node: node.to_string(),
                queue: spec.queue.to_string(),
            });
        }
    }

    for (field, path) in [
        ("working directory", spec.cwd.as_str()),
        ("stdout", spec.stdout_path.as_str()),
        ("stderr", spec.stderr_path.as_str()),
    ] {
        if !is_configured_shared_path(config, Path::new(path)) {
            return Err(AdmissionError::InvalidSharedPath { field });
        }
    }

    Ok(storage.submit_once(request_id, spec)?)
}

fn is_configured_shared_path(config: &ClusterConfig, path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return false;
    }
    path.starts_with(&config.shared_root)
        || config
            .shares
            .values()
            .any(|share| path.starts_with(&share.mount_root))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use macluster_protocol::{
        identifiers::{Id128, NodeId, QueueName, RequestId},
        types::{JobMode, JobSpec},
    };

    use crate::{config::ClusterConfig, storage::Storage};

    use super::{AdmissionError, admit_submission};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("macluster-admission-{}", Id128::random()));
            fs::create_dir_all(root.join("state")).unwrap();
            fs::create_dir_all(root.join("shared")).unwrap();
            let config = format!(
                "[cluster]\nname=\"admission\"\nlogin_node=\"login\"\ndefault_queue=\"cpu\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.cpu]\nnodes=[\"compute\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.compute]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\n",
                root.join("shared").display(),
                unsafe { libc::geteuid() }
            );
            fs::write(root.join("config.toml"), config).unwrap();
            Self(root)
        }

        fn config(&self) -> ClusterConfig {
            ClusterConfig::parse(&fs::read_to_string(self.0.join("config.toml")).unwrap()).unwrap()
        }

        fn spec(&self) -> JobSpec {
            let shared = self.0.join("shared");
            JobSpec {
                storage_namespace: Some(
                    Id128::parse("240edfcc-0fe5-4fa8-83a2-29c6ede02b42").unwrap(),
                ),
                queue: QueueName::new("cpu").unwrap(),
                node: Some(NodeId::new("compute").unwrap()),
                name: "test".into(),
                cwd: shared.display().to_string(),
                stdout_path: shared.join("jobs/%j/out").display().to_string(),
                stderr_path: shared.join("jobs/%j/err").display().to_string(),
                walltime_secs: None,
                env: Default::default(),
                mode: JobMode::Interactive,
                snapshot: None,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn admission_requires_shared_namespace_and_compute_queue_membership() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let storage = Storage::open(fixture.0.join("state")).unwrap();
        let mut spec = fixture.spec();
        spec.node = Some(NodeId::new("login").unwrap());
        assert!(matches!(
            admit_submission(&storage, &config, RequestId::random(), spec),
            Err(AdmissionError::LoginNode(_))
        ));

        let mut spec = fixture.spec();
        spec.storage_namespace = None;
        assert!(matches!(
            admit_submission(&storage, &config, RequestId::random(), spec),
            Err(AdmissionError::StorageNamespace)
        ));
    }

    #[test]
    fn admission_rejects_paths_that_escape_registered_shares() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let storage = Storage::open(fixture.0.join("state")).unwrap();
        let mut spec = fixture.spec();
        spec.cwd = "/Users/private".into();
        assert!(matches!(
            admit_submission(&storage, &config, RequestId::random(), spec),
            Err(AdmissionError::InvalidSharedPath {
                field: "working directory"
            })
        ));
    }
}
