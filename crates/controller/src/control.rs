//! Serialized controller admission and query operations for local IPC clients.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use macluster_core::{
    config::ClusterConfig,
    storage::{Storage, SubmitError},
    submission::{AdmissionError, admit_submission},
};
use macluster_protocol::{
    control::{
        ControlCommand, ControlError, ControlErrorCode, ControlPayload, ControlRequest,
        ControllerHello, ControllerLifecycle, JobPage, MAX_CONTROL_JOB_PAGE,
        MAX_CONTROL_SNAPSHOT_CHUNK_BYTES, QueueSummary,
    },
    framing::{ChunkAssembler, MAX_SNAPSHOT_BYTES},
    identifiers::Id128,
};

const MAX_ACTIVE_UPLOADS: usize = 4;
const SNAPSHOT_UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

struct SnapshotUpload {
    assembler: ChunkAssembler,
    expires_at: Instant,
}

/// Controller-owned API state. It processes all durable writes on the runtime
/// thread and drops unfinished uploads when the authenticated client disconnects.
pub struct ControlApi {
    config: ClusterConfig,
    storage: Storage,
    hello: ControllerHello,
    uploads: HashMap<(Id128, Id128), SnapshotUpload>,
}

impl ControlApi {
    pub fn new(config: ClusterConfig, storage: Storage, hello: ControllerHello) -> Self {
        Self {
            config,
            storage,
            hello,
            uploads: HashMap::new(),
        }
    }

    pub fn set_lifecycle(&mut self, lifecycle: ControllerLifecycle) {
        self.hello.lifecycle = lifecycle;
    }

    pub fn handle(
        &mut self,
        client_session: Id128,
        request: ControlRequest,
    ) -> Result<ControlPayload, ControlError> {
        self.expire_uploads();
        match request.command {
            ControlCommand::Status => Ok(ControlPayload::Status(self.hello.clone())),
            ControlCommand::BeginSnapshot {
                upload_id,
                size_bytes,
                sha256,
            } => {
                self.require_ready()?;
                if size_bytes > MAX_SNAPSHOT_BYTES {
                    return Err(invalid_request("script exceeds the 8 MiB limit"));
                }
                if self
                    .uploads
                    .keys()
                    .any(|(session, _)| *session == client_session)
                {
                    return Err(conflict(
                        "a snapshot upload is already active on this connection",
                    ));
                }
                if self.uploads.len() >= MAX_ACTIVE_UPLOADS {
                    return Err(ControlError {
                        code: ControlErrorCode::Busy,
                        message: "controller is handling the maximum number of script uploads"
                            .into(),
                    });
                }
                let assembler = ChunkAssembler::new(size_bytes, &sha256)
                    .map_err(|error| invalid_request(error.to_string()))?;
                self.uploads.insert(
                    (client_session, upload_id),
                    SnapshotUpload {
                        assembler,
                        expires_at: Instant::now() + SNAPSHOT_UPLOAD_TTL,
                    },
                );
                Ok(ControlPayload::SnapshotProgress { offset: 0 })
            }
            ControlCommand::PutSnapshotChunk {
                upload_id,
                offset,
                bytes,
            } => {
                self.require_ready()?;
                if bytes.len() > MAX_CONTROL_SNAPSHOT_CHUNK_BYTES {
                    return Err(invalid_request("script chunk exceeds 256 KiB"));
                }
                let upload = self
                    .uploads
                    .get_mut(&(client_session, upload_id))
                    .ok_or_else(|| invalid_request("script upload is absent or expired"))?;
                let offset = upload
                    .assembler
                    .push(offset, &bytes)
                    .map_err(|error| invalid_request(error.to_string()))?;
                upload.expires_at = Instant::now() + SNAPSHOT_UPLOAD_TTL;
                Ok(ControlPayload::SnapshotProgress { offset })
            }
            ControlCommand::FinishSnapshot { upload_id } => {
                self.require_ready()?;
                let upload = self
                    .uploads
                    .remove(&(client_session, upload_id))
                    .ok_or_else(|| invalid_request("script upload is absent or expired"))?;
                let bytes = upload
                    .assembler
                    .finish()
                    .map_err(|error| invalid_request(error.to_string()))?;
                let snapshot = self.storage.stage_snapshot(&bytes).map_err(storage_error)?;
                Ok(ControlPayload::SnapshotFinished(snapshot))
            }
            ControlCommand::AbortSnapshot { upload_id } => {
                self.uploads.remove(&(client_session, upload_id));
                Ok(ControlPayload::SnapshotProgress { offset: 0 })
            }
            ControlCommand::Submit { request_id, spec } => {
                self.require_ready()?;
                let record = admit_submission(&self.storage, &self.config, request_id, spec)
                    .map_err(admission_error)?;
                Ok(ControlPayload::Submission(record))
            }
            ControlCommand::LookupRequest { request_id } => self
                .storage
                .get_job_by_request_id(request_id)
                .map(ControlPayload::Lookup)
                .map_err(storage_error),
            ControlCommand::LookupJob { job_id } => self
                .storage
                .get_job(job_id)
                .map(|job| {
                    job.map(ControlPayload::Job)
                        .ok_or_else(|| invalid_request(format!("job {job_id} was not found")))
                })
                .map_err(storage_error)?,
            ControlCommand::QueryJobs {
                offset,
                limit,
                state,
                active_only,
            } => {
                if limit == 0 || limit > MAX_CONTROL_JOB_PAGE {
                    return Err(invalid_request(
                        "job query page size must be between 1 and 256",
                    ));
                }
                let jobs = if active_only {
                    self.storage
                        .list_active_jobs_page(offset, limit)
                        .map_err(storage_error)?
                } else {
                    self.storage
                        .list_jobs_page(state, offset, limit)
                        .map_err(storage_error)?
                };
                let next_offset =
                    (jobs.len() == limit).then_some(offset.saturating_add(jobs.len()));
                Ok(ControlPayload::Jobs(JobPage { jobs, next_offset }))
            }
            ControlCommand::QueryQueues => {
                let counts = self
                    .storage
                    .queue_job_counts()
                    .map_err(storage_error)?
                    .into_iter()
                    .map(|counts| (counts.queue.clone(), counts))
                    .collect::<HashMap<_, _>>();
                let queues = self
                    .config
                    .queues
                    .keys()
                    .map(|name| {
                        let counts = counts.get(name);
                        QueueSummary {
                            name: name.clone(),
                            nodes: self.config.queue_compute_nodes(name),
                            pending: counts.map_or(0, |counts| counts.pending),
                            running: counts.map_or(0, |counts| counts.running),
                            completed: counts.map_or(0, |counts| counts.completed),
                            failed: counts.map_or(0, |counts| counts.failed),
                        }
                    })
                    .collect();
                Ok(ControlPayload::Queues(queues))
            }
            ControlCommand::CancelJob { job_id, force } => self
                .storage
                .request_cancel(job_id, force)
                .map(ControlPayload::Job)
                .map_err(storage_error),
        }
    }

    pub fn disconnect(&mut self, client_session: Id128) {
        self.uploads
            .retain(|(session, _), _| *session != client_session);
    }

    fn require_ready(&self) -> Result<(), ControlError> {
        if self.hello.lifecycle == ControllerLifecycle::Ready {
            Ok(())
        } else {
            Err(ControlError {
                code: ControlErrorCode::Maintenance,
                message: format!(
                    "controller is {:?}; retry after recovery or maintenance completes",
                    self.hello.lifecycle
                ),
            })
        }
    }

    fn expire_uploads(&mut self) {
        let now = Instant::now();
        self.uploads.retain(|_, upload| upload.expires_at > now);
    }
}

fn invalid_request(message: impl Into<String>) -> ControlError {
    ControlError {
        code: ControlErrorCode::InvalidRequest,
        message: message.into(),
    }
}

fn conflict(message: impl Into<String>) -> ControlError {
    ControlError {
        code: ControlErrorCode::Conflict,
        message: message.into(),
    }
}

fn admission_error(error: AdmissionError) -> ControlError {
    let code = match &error {
        AdmissionError::Storage(SubmitError::RequestConflict) => ControlErrorCode::Conflict,
        AdmissionError::Storage(_) => ControlErrorCode::Unavailable,
        AdmissionError::StorageNamespace
        | AdmissionError::UnknownQueue(_)
        | AdmissionError::LoginNode(_)
        | AdmissionError::NodeNotInQueue { .. }
        | AdmissionError::InvalidSharedPath { .. } => ControlErrorCode::InvalidRequest,
    };
    ControlError {
        code,
        message: error.to_string(),
    }
}

fn storage_error(error: SubmitError) -> ControlError {
    let code = match &error {
        SubmitError::RequestConflict => ControlErrorCode::Conflict,
        SubmitError::NotFound(_) => ControlErrorCode::InvalidRequest,
        SubmitError::SnapshotTooLarge
        | SubmitError::SnapshotMismatch
        | SubmitError::MissingSnapshot
        | SubmitError::InvalidPageSize => ControlErrorCode::InvalidRequest,
        _ => ControlErrorCode::Unavailable,
    };
    ControlError {
        code,
        message: error.to_string(),
    }
}
