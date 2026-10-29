//! Local, durable controller state. SQLite work is kept separate from NFS and
//! process operations; callers perform those operations only after a commit.

use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_protocol::{
    framing::{MAX_SNAPSHOT_BYTES, sha256_hex},
    identifiers::{ControllerUuid, Id128, RequestId, StartToken},
    types::{ControllerEpoch, JobMode, JobRecord, JobSpec, JobState, SnapshotRef},
};
use thiserror::Error;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READONLY: c_int = 0x0000_0001;
const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;
const SNAPSHOT_RETAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[repr(C)]
struct sqlite3 {
    _private: [u8; 0],
}
#[repr(C)]
struct sqlite3_stmt {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        database: *mut *mut sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close_v2(database: *mut sqlite3) -> c_int;
    fn sqlite3_exec(
        database: *mut sqlite3,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
        >,
        argument: *mut c_void,
        error: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(pointer: *mut c_void);
    fn sqlite3_prepare_v2(
        database: *mut sqlite3,
        sql: *const c_char,
        bytes: c_int,
        statement: *mut *mut sqlite3_stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_bind_text(
        statement: *mut sqlite3_stmt,
        index: c_int,
        value: *const c_char,
        bytes: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn sqlite3_bind_int64(statement: *mut sqlite3_stmt, index: c_int, value: i64) -> c_int;
    fn sqlite3_step(statement: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_finalize(statement: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_column_text(statement: *mut sqlite3_stmt, column: c_int) -> *const u8;
    fn sqlite3_column_bytes(statement: *mut sqlite3_stmt, column: c_int) -> c_int;
    fn sqlite3_column_int64(statement: *mut sqlite3_stmt, column: c_int) -> i64;
    fn sqlite3_last_insert_rowid(database: *mut sqlite3) -> i64;
    fn sqlite3_busy_timeout(database: *mut sqlite3, milliseconds: c_int) -> c_int;
    fn sqlite3_errmsg(database: *mut sqlite3) -> *const c_char;
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("database error: {0}")]
    Database(String),
    #[error("filesystem error: {0}")]
    Io(#[from] io::Error),
    #[error("snapshot exceeds the 8 MiB limit")]
    SnapshotTooLarge,
    #[error("snapshot digest or length does not match the job record")]
    SnapshotMismatch,
    #[error("batch job is missing its script snapshot")]
    MissingSnapshot,
    #[error("request ID was already used for different submission content")]
    RequestConflict,
    #[error("job {0} was not found")]
    NotFound(u64),
    #[error("job {0} is already terminal")]
    AlreadyTerminal(u64),
    #[error("node '{0}' already has an active job")]
    NodeBusy(String),
    #[error("job {0} cannot transition from {1} to {2}")]
    InvalidTransition(u64, String, String),
    #[error("job page size must be between 1 and 256")]
    InvalidPageSize,
    #[error("invalid stored job record: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueJobCounts {
    pub queue: String,
    pub pending: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JobStorageLimitReport {
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub pruned_job_ids: Vec<u64>,
    pub over_limit_bytes: u64,
}

/// A bounded, read-only view of persisted job records for monitor clients.
///
/// Opening this type never creates the state directory/database and never
/// runs migrations. It intentionally exposes only job reads.
pub struct ReadOnlyJobStore {
    connection: Connection,
    schema_version: u32,
}

impl ReadOnlyJobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SubmitError> {
        let database = root.as_ref().join("controller.sqlite3");
        let connection = Connection::open_read_only(&database, 500)?;
        let version = connection.query_text(
            "SELECT value FROM schema_meta WHERE key='schema_version'",
            None,
        )?;
        let schema_version = match version.as_deref() {
            Some("2") => 2,
            Some("3") => 3,
            value => {
                return Err(SubmitError::Database(format!(
                    "monitor cannot read controller schema version {}",
                    value.unwrap_or("unknown")
                )));
            }
        };
        Ok(Self {
            connection,
            schema_version,
        })
    }

    pub fn list_jobs(&self, state: Option<JobState>) -> Result<Vec<JobRecord>, SubmitError> {
        let sql = match state {
            Some(_) => "SELECT payload_json FROM jobs WHERE state=?1 ORDER BY id DESC",
            None => "SELECT payload_json FROM jobs ORDER BY id DESC",
        };
        self.connection
            .query_texts(sql, state.map(job_state_name))?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Read one bounded page without materializing the full job history.
    pub fn list_jobs_page(
        &self,
        state: Option<JobState>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<JobRecord>, SubmitError> {
        if limit == 0 || limit > 256 {
            return Err(SubmitError::InvalidPageSize);
        }
        let sql = match state {
            Some(_) => format!(
                "SELECT payload_json FROM jobs WHERE state=?1 ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
            ),
            None => format!(
                "SELECT payload_json FROM jobs ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
            ),
        };
        self.connection
            .query_texts(&sql, state.map(job_state_name))?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Return only pending and active jobs for live monitor displays. This
    /// keeps polling bounded even when terminal history grows over time.
    pub fn list_monitor_jobs(&self) -> Result<Vec<JobRecord>, SubmitError> {
        let sql = if self.schema_version >= 3 {
            "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR log_sync_pending=1 ORDER BY id DESC"
        } else {
            "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') ORDER BY id DESC"
        };
        self.connection
            .query_texts(sql, None)?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Include terminal jobs whose output has not finished synchronizing.
    pub fn list_active_jobs(&self) -> Result<Vec<JobRecord>, SubmitError> {
        if self.schema_version < 3 {
            return self.list_monitor_jobs();
        }
        self.connection
            .query_texts(
                "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR snapshot_sync_pending=1 OR log_sync_pending=1 ORDER BY id DESC",
                None,
            )?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    pub fn get_job(&self, job_id: u64) -> Result<Option<JobRecord>, SubmitError> {
        self.connection
            .query_text(
                "SELECT payload_json FROM jobs WHERE id=?1",
                Some(job_id.to_string()),
            )?
            .map(|payload| decode_job(&payload))
            .transpose()
    }

    pub fn get_job_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<JobRecord>, SubmitError> {
        self.connection
            .query_text(
                "SELECT payload_json FROM jobs WHERE request_id=?1",
                Some(request_id.to_string()),
            )?
            .map(|payload| decode_job(&payload))
            .transpose()
    }

    pub fn queue_job_counts(&self) -> Result<Vec<QueueJobCounts>, SubmitError> {
        if self.schema_version >= 3 {
            return self.connection.query_queue_job_counts();
        }
        let mut counts = std::collections::BTreeMap::new();
        for job in self.list_jobs(None)? {
            let row = counts
                .entry(job.spec.queue.to_string())
                .or_insert_with(|| QueueJobCounts {
                    queue: job.spec.queue.to_string(),
                    pending: 0,
                    running: 0,
                    completed: 0,
                    failed: 0,
                });
            match job.state {
                JobState::Pending => row.pending += 1,
                JobState::Starting | JobState::Running | JobState::Cancelling => row.running += 1,
                JobState::Completed => row.completed += 1,
                JobState::Failed => row.failed += 1,
                _ => {}
            }
        }
        Ok(counts.into_values().collect())
    }

    /// Return whether cluster maintenance must wait for active jobs or output
    /// synchronization. This existence query does not load or deserialize
    /// terminal job history.
    pub fn has_maintenance_work(&self) -> Result<bool, SubmitError> {
        let sql = if self.schema_version >= 3 {
            "SELECT state FROM jobs WHERE state IN ('STARTING','RUNNING','CANCELLING') OR snapshot_sync_pending=1 OR log_sync_pending=1 LIMIT 1"
        } else {
            "SELECT state FROM jobs WHERE state IN ('STARTING','RUNNING','CANCELLING') LIMIT 1"
        };
        Ok(!self.connection.query_texts(sql, None)?.is_empty())
    }
}

/// A single SQLite connection. The controller owns it behind its serialized
/// mutation path; filesystem and SSH work must happen outside transactions.
pub struct Storage {
    connection: Connection,
    root: PathBuf,
}

impl Storage {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SubmitError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let snapshots = root.join("snapshots");
        fs::create_dir_all(&snapshots)?;
        fs::set_permissions(&snapshots, fs::Permissions::from_mode(0o700))?;

        // SQLite serializes writers, but changing journal mode happens before
        // the schema transaction and can still race between fresh openers.
        // This local lock covers WAL setup plus schema discovery/migration.
        let schema_lock = lock_schema_initialization(&root)?;
        let db_path = root.join("controller.sqlite3");
        let connection = Connection::open(&db_path)?;
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;
        connection
            .exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        // Serialize schema discovery with creation and migrations. A caller
        // waiting here will inspect the committed schema after the first
        // opener finishes instead of racing to create it from a stale view.
        connection.exec("BEGIN IMMEDIATE")?;
        let has_schema = connection
            .query_text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta'",
                None,
            )?
            .is_some();
        let has_jobs = connection
            .query_text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='jobs'",
                None,
            )?
            .is_some();
        let mut version = if has_schema {
            connection.query_text(
                "SELECT value FROM schema_meta WHERE key='schema_version'",
                None,
            )?
        } else if has_jobs {
            return Err(SubmitError::Database(
                "controller database has jobs but no schema version; refusing to alter it".into(),
            ));
        } else {
            None
        };
        if let Some(value) = version.as_deref()
            && !matches!(value, "1" | "2" | "3")
        {
            return Err(SubmitError::Database(format!(
                "unsupported schema version {value:?}"
            )));
        }
        if has_schema && version.is_none() {
            return Err(SubmitError::Database(
                "controller schema metadata has no schema_version; refusing to alter it".into(),
            ));
        }

        if version.is_none() {
            connection.exec(
                "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO schema_meta(key, value) VALUES ('schema_version', '3');
                 CREATE TABLE jobs (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   request_id TEXT NOT NULL UNIQUE,
                   request_digest TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   state TEXT NOT NULL,
                   cancel_requested INTEGER NOT NULL DEFAULT 0,
                   assigned_node TEXT,
                   created_unix_ms INTEGER NOT NULL,
                   queue TEXT NOT NULL,
                   snapshot_sync_pending INTEGER NOT NULL DEFAULT 0,
                   log_sync_pending INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE state_events (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   job_id INTEGER NOT NULL REFERENCES jobs(id),
                   state TEXT NOT NULL,
                   at_unix_ms INTEGER NOT NULL,
                   reason TEXT
                 );",
            )?;
            version = Some("3".to_owned());
        } else {
            connection.exec(
                "CREATE TABLE IF NOT EXISTS state_events (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   job_id INTEGER NOT NULL REFERENCES jobs(id),
                   state TEXT NOT NULL,
                   at_unix_ms INTEGER NOT NULL,
                   reason TEXT
                 );
                 CREATE INDEX IF NOT EXISTS jobs_state_created ON jobs(state, created_unix_ms, id);"
            )?;
        }

        if version.as_deref() == Some("1") {
            let migration = (|| {
                let columns = connection.query_texts_column("PRAGMA table_info(jobs)", 1)?;
                if !columns.iter().any(|name| name == "assigned_node") {
                    connection.exec("ALTER TABLE jobs ADD COLUMN assigned_node TEXT;")?;
                }
                connection.exec("UPDATE schema_meta SET value='2' WHERE key='schema_version';")
            })();
            match migration {
                Ok(()) => {}
                Err(error) => return Err(error),
            }
            version = Some("2".to_owned());
        }
        if version.as_deref() == Some("2") {
            let migration = (|| {
                connection.exec(
                    "ALTER TABLE jobs ADD COLUMN queue TEXT;
                     ALTER TABLE jobs ADD COLUMN snapshot_sync_pending INTEGER NOT NULL DEFAULT 0;
                     ALTER TABLE jobs ADD COLUMN log_sync_pending INTEGER NOT NULL DEFAULT 0;",
                )?;
                for (id, payload) in connection.query_text_pairs(
                    "SELECT CAST(id AS TEXT), payload_json FROM jobs ORDER BY id",
                )? {
                    let id = id.parse::<i64>().map_err(|error| {
                        SubmitError::Database(format!("invalid job id during migration: {error}"))
                    })?;
                    let job = decode_job(&payload)?;
                    connection.update_job_index_fields(
                        id,
                        job.spec.queue.as_str(),
                        job.snapshot_sync_pending,
                        job.log_sync_pending,
                    )?;
                }
                connection.exec(
                    "CREATE INDEX jobs_queue_state ON jobs(queue, state);
                     CREATE INDEX jobs_queue_work ON jobs(queue, id) WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR log_sync_pending=1;
                     UPDATE schema_meta SET value='3' WHERE key='schema_version';"
                )
            })();
            match migration {
                Ok(()) => {}
                Err(error) => return Err(error),
            }
        }
        connection.exec(
            "CREATE INDEX IF NOT EXISTS jobs_state_created ON jobs(state, created_unix_ms, id);
             CREATE INDEX IF NOT EXISTS jobs_state_id ON jobs(state, id DESC);
             CREATE INDEX IF NOT EXISTS jobs_queue_state ON jobs(queue, state);
             CREATE INDEX IF NOT EXISTS jobs_queue_work ON jobs(queue, id) WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR log_sync_pending=1;"
        )?;
        connection.exec("CREATE UNIQUE INDEX IF NOT EXISTS active_node_occupation ON jobs(assigned_node) WHERE assigned_node IS NOT NULL AND state IN ('STARTING','RUNNING','CANCELLING');")?;
        connection.exec("COMMIT")?;
        drop(schema_lock);
        Ok(Self { connection, root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes and flushes immutable bytes before a job can reference them.
    pub fn stage_snapshot(&self, bytes: &[u8]) -> Result<SnapshotRef, SubmitError> {
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(SubmitError::SnapshotTooLarge);
        }
        let digest = sha256_hex(bytes).map_err(|error| SubmitError::Database(error.to_string()))?;
        let target = self.root.join("snapshots").join(format!("{digest}.sh"));
        if target.exists() {
            self.verify_snapshot_file(&target, &digest, bytes.len() as u64)?;
            File::open(&target)?.set_modified(SystemTime::now())?;
            return Ok(SnapshotRef {
                sha256: digest,
                size_bytes: bytes.len() as u64,
            });
        }

        let temporary =
            self.root
                .join("snapshots")
                .join(format!(".{}.{}.tmp", digest, RequestId::random()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let write_result = (|| -> io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::hard_link(&temporary, &target)?;
            File::open(target.parent().expect("snapshot directory exists"))?.sync_all()?;
            Ok(())
        })();
        drop(file);
        let _ = fs::remove_file(&temporary);
        match write_result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.verify_snapshot_file(&target, &digest, bytes.len() as u64)?;
            }
            Err(error) => return Err(error.into()),
        }
        File::open(&target)?.set_modified(SystemTime::now())?;
        Ok(SnapshotRef {
            sha256: digest,
            size_bytes: bytes.len() as u64,
        })
    }

    pub fn snapshot_path(&self, snapshot: &SnapshotRef) -> PathBuf {
        self.root
            .join("snapshots")
            .join(format!("{}.sh", snapshot.sha256))
    }

    /// Commits one submission. Identical retries return the original job;
    /// reusing the same request ID for changed content returns a conflict.
    pub fn submit_once(
        &self,
        request_id: RequestId,
        spec: JobSpec,
    ) -> Result<JobRecord, SubmitError> {
        if spec.mode == JobMode::Batch && spec.snapshot.is_none() {
            return Err(SubmitError::MissingSnapshot);
        }
        if let Some(snapshot) = spec.snapshot.as_ref() {
            let snapshot_path = self.snapshot_path(snapshot);
            self.verify_snapshot_file(&snapshot_path, &snapshot.sha256, snapshot.size_bytes)?;
        }
        let snapshot_sync_pending = spec.snapshot.is_some();
        let spec_json = serde_json::to_vec(&spec)
            .map_err(|error| SubmitError::Serialization(error.to_string()))?;
        let request_digest =
            sha256_hex(&spec_json).map_err(|error| SubmitError::Database(error.to_string()))?;
        let request_id = request_id.to_string();

        self.connection.exec("BEGIN IMMEDIATE")?;
        let result = (|| {
            if let Some((existing_digest, payload)) = self.connection.query_pair(
                "SELECT request_digest, payload_json FROM jobs WHERE request_id=?1",
                &request_id,
            )? {
                if existing_digest != request_digest {
                    return Err(SubmitError::RequestConflict);
                }
                return decode_job(&payload);
            }

            let created_unix_ms = now_unix_ms();
            self.connection.insert_job(
                &request_id,
                &request_digest,
                created_unix_ms as i64,
                spec.queue.as_str(),
                snapshot_sync_pending,
            )?;
            let id = unsafe { sqlite3_last_insert_rowid(self.connection.raw) } as u64;
            let record = JobRecord {
                id,
                spec,
                state: JobState::Pending,
                node: None,
                start_token: None,
                cancel_force: false,
                created_unix_ms,
                started_unix_ms: None,
                finished_unix_ms: None,
                exit_code: None,
                end_reason: None,
                snapshot_sync_pending,
                log_sync_pending: false,
                waiting_reason: None,
            };
            let payload = serde_json::to_string(&record)
                .map_err(|error| SubmitError::Serialization(error.to_string()))?;
            self.connection.update_job_record(&record, &payload)?;
            self.connection.execute_integer_text_integer(
                "INSERT INTO state_events(job_id,state,at_unix_ms) VALUES (?1,?2,?3)",
                id as i64,
                "PENDING",
                created_unix_ms as i64,
            )?;
            Ok(record)
        })();

        match result {
            Ok(record) => {
                self.connection.exec("COMMIT")?;
                Ok(record)
            }
            Err(error) => {
                let _ = self.connection.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn get_job(&self, job_id: u64) -> Result<Option<JobRecord>, SubmitError> {
        self.connection
            .query_text(
                "SELECT payload_json FROM jobs WHERE id=?1",
                Some(job_id.to_string()),
            )?
            .map(|payload| decode_job(&payload))
            .transpose()
    }

    pub fn get_job_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<JobRecord>, SubmitError> {
        self.connection
            .query_text(
                "SELECT payload_json FROM jobs WHERE request_id=?1",
                Some(request_id.to_string()),
            )?
            .map(|payload| decode_job(&payload))
            .transpose()
    }

    /// Persist and return the next fencing epoch before any node is contacted.
    pub fn begin_controller_epoch(&self) -> Result<ControllerEpoch, SubmitError> {
        self.connection.exec("BEGIN IMMEDIATE")?;
        let result = (|| {
            let uuid = match self.connection.query_text(
                "SELECT value FROM schema_meta WHERE key='controller_uuid'",
                None,
            )? {
                Some(value) => ControllerUuid(
                    Id128::parse(&value)
                        .map_err(|error| SubmitError::Database(error.to_string()))?,
                ),
                None => {
                    let uuid = ControllerUuid::random();
                    self.connection.exec(&format!(
                        "INSERT INTO schema_meta(key,value) VALUES ('controller_uuid','{uuid}')"
                    ))?;
                    uuid
                }
            };
            let epoch = match self.connection.query_text(
                "SELECT value FROM schema_meta WHERE key='controller_epoch'",
                None,
            )? {
                Some(value) => value
                    .parse::<u64>()
                    .map_err(|error| SubmitError::Database(error.to_string()))?,
                None => 0,
            };
            let epoch = epoch
                .checked_add(1)
                .ok_or_else(|| SubmitError::Database("controller epoch exhausted".into()))?;
            self.connection.exec(&format!(
                "INSERT OR REPLACE INTO schema_meta(key,value) VALUES ('controller_epoch','{epoch}')"
            ))?;
            Ok(ControllerEpoch {
                controller_uuid: uuid,
                epoch,
            })
        })();
        match result {
            Ok(epoch) => {
                self.connection.exec("COMMIT")?;
                Ok(epoch)
            }
            Err(error) => {
                let _ = self.connection.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Read the active controller identity without advancing its fencing
    /// epoch. Idle maintenance performed by a live controller must keep using
    /// the epoch already held by that controller.
    pub fn current_controller_epoch(&self) -> Result<Option<ControllerEpoch>, SubmitError> {
        let uuid = self.connection.query_text(
            "SELECT value FROM schema_meta WHERE key='controller_uuid'",
            None,
        )?;
        let epoch = self.connection.query_text(
            "SELECT value FROM schema_meta WHERE key='controller_epoch'",
            None,
        )?;
        match (uuid, epoch) {
            (None, None) => Ok(None),
            (Some(uuid), Some(epoch)) => Ok(Some(ControllerEpoch {
                controller_uuid: ControllerUuid(
                    Id128::parse(&uuid)
                        .map_err(|error| SubmitError::Database(error.to_string()))?,
                ),
                epoch: epoch
                    .parse::<u64>()
                    .map_err(|error| SubmitError::Database(error.to_string()))?,
            })),
            _ => Err(SubmitError::Database(
                "controller identity and fencing epoch are inconsistent".into(),
            )),
        }
    }

    pub fn list_jobs(&self, state: Option<JobState>) -> Result<Vec<JobRecord>, SubmitError> {
        let sql = match state {
            Some(_) => "SELECT payload_json FROM jobs WHERE state=?1 ORDER BY id DESC",
            None => "SELECT payload_json FROM jobs ORDER BY id DESC",
        };
        self.connection
            .query_texts(sql, state.map(job_state_name))?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Read a bounded page without loading all persisted job history.
    pub fn list_jobs_page(
        &self,
        state: Option<JobState>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<JobRecord>, SubmitError> {
        if limit == 0 || limit > 256 {
            return Err(SubmitError::InvalidPageSize);
        }
        let sql = match state {
            Some(_) => format!(
                "SELECT payload_json FROM jobs WHERE state=?1 ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
            ),
            None => format!(
                "SELECT payload_json FROM jobs ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
            ),
        };
        self.connection
            .query_texts(&sql, state.map(job_state_name))?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Read a bounded page of nonterminal jobs and jobs with pending sync work.
    pub fn list_active_jobs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<JobRecord>, SubmitError> {
        if limit == 0 || limit > 256 {
            return Err(SubmitError::InvalidPageSize);
        }
        let sql = format!(
            "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR snapshot_sync_pending=1 OR log_sync_pending=1 ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
        );
        self.connection
            .query_texts(&sql, None)?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    pub fn list_active_jobs(&self) -> Result<Vec<JobRecord>, SubmitError> {
        self.connection
            .query_texts(
                "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR snapshot_sync_pending=1 OR log_sync_pending=1 ORDER BY id DESC",
                None,
            )?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    /// Return pending and active tasks for live monitor displays without
    /// loading terminal job history or unrelated output synchronization rows.
    pub fn list_monitor_jobs(&self) -> Result<Vec<JobRecord>, SubmitError> {
        self.connection
            .query_texts(
                "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') ORDER BY id DESC",
                None,
            )?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    pub fn list_reconcile_jobs(&self) -> Result<Vec<JobRecord>, SubmitError> {
        self.connection
            .query_texts(
                "SELECT payload_json FROM jobs WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR log_sync_pending=1 ORDER BY id DESC",
                None,
            )?
            .into_iter()
            .map(|payload| decode_job(&payload))
            .collect()
    }

    pub fn queue_job_counts(&self) -> Result<Vec<QueueJobCounts>, SubmitError> {
        self.connection.query_queue_job_counts()
    }

    /// Keep the cluster-managed job log tree and its controller records below
    /// a byte limit. Only terminal jobs whose output synchronization finished
    /// are eligible for removal; user result files outside each managed job
    /// directory are never touched.
    pub fn enforce_job_storage_limit(
        &self,
        shared_root: &Path,
        namespace: Id128,
        limit_bytes: u64,
    ) -> Result<JobStorageLimitReport, SubmitError> {
        let shared_root = shared_root.canonicalize()?;
        let jobs = self.list_jobs(None)?;
        let mut report = JobStorageLimitReport::default();
        let mut bytes = self.job_storage_bytes(&shared_root, namespace, &jobs)?;
        report.bytes_before = bytes;
        if bytes <= limit_bytes {
            report.bytes_after = bytes;
            return Ok(report);
        }

        let mut snapshot_references = HashMap::<String, usize>::new();
        for job in &jobs {
            if let Some(snapshot) = &job.spec.snapshot {
                *snapshot_references
                    .entry(snapshot.sha256.clone())
                    .or_default() += 1;
            }
        }
        let mut removed_snapshot_bytes = self.prune_unreferenced_snapshots(&snapshot_references)?;
        bytes = bytes.saturating_sub(removed_snapshot_bytes);

        let mut candidates = jobs
            .into_iter()
            .filter(|job| {
                (job.spec.storage_namespace.is_none()
                    || job.spec.storage_namespace == Some(namespace))
                    && job.state.is_terminal()
                    && !job.snapshot_sync_pending
                    && !job.log_sync_pending
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|job| (job.created_unix_ms, job.id));

        for job in candidates {
            if bytes <= limit_bytes {
                break;
            }
            let job_dir = job.spec.shared_job_dir(&shared_root, job.id);
            let job_bytes = safe_tree_size(&shared_root, &job_dir)?;
            safe_remove_tree(&shared_root, &job_dir)?;

            // Keep the historical row if another actor changed its status or
            // synchronization flags while this maintenance pass was running.
            let Some(removed) = self.delete_prunable_job(job.id)? else {
                continue;
            };
            bytes = bytes.saturating_sub(job_bytes);
            if let Some(snapshot) = removed.spec.snapshot.as_ref() {
                let references = snapshot_references
                    .entry(snapshot.sha256.clone())
                    .or_default();
                *references = references.saturating_sub(1);
            }
            report.pruned_job_ids.push(job.id);
        }
        let second_snapshot_sweep = self.prune_unreferenced_snapshots(&snapshot_references)?;
        removed_snapshot_bytes = removed_snapshot_bytes.saturating_add(second_snapshot_sweep);

        let compacted_size =
            self.job_storage_bytes(&shared_root, namespace, &self.list_jobs(None)?)?;
        if (!report.pruned_job_ids.is_empty() || removed_snapshot_bytes > 0)
            && compacted_size > limit_bytes
        {
            // DELETE reuses SQLite pages but does not release them to APFS.
            // Measure the database file itself after pruning, then compact
            // only when the managed storage is still over budget.
            self.connection
                .exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
        }
        bytes = self.job_storage_bytes(&shared_root, namespace, &self.list_jobs(None)?)?;
        report.bytes_after = bytes;
        report.over_limit_bytes = bytes.saturating_sub(limit_bytes);
        Ok(report)
    }

    fn job_storage_bytes(
        &self,
        shared_root: &Path,
        namespace: Id128,
        jobs: &[JobRecord],
    ) -> Result<u64, SubmitError> {
        let state_root = self.root.canonicalize()?;
        let managed_root = shared_root.join("jobs").join(namespace.to_string());
        let mut bytes = safe_tree_size(shared_root, &managed_root)?;
        for job in jobs {
            if job
                .spec
                .storage_namespace
                .is_some_and(|value| value != namespace)
            {
                continue;
            }
            if job.spec.storage_namespace.is_none() {
                let legacy = shared_root.join("jobs").join(job.id.to_string());
                bytes = bytes.saturating_add(safe_tree_size(shared_root, &legacy)?);
            }
        }
        bytes = bytes.saturating_add(safe_tree_size(&state_root, &state_root.join("snapshots"))?);
        for suffix in ["", "-wal", "-shm"] {
            let path = state_root.join(format!("controller.sqlite3{suffix}"));
            bytes = bytes.saturating_add(file_size_if_present(&path)?);
        }
        Ok(bytes)
    }

    fn prune_unreferenced_snapshots(
        &self,
        references: &HashMap<String, usize>,
    ) -> Result<u64, SubmitError> {
        let state_root = self.root.canonicalize()?;
        let snapshot_root = state_root.join("snapshots");
        let entries = match fs::read_dir(&snapshot_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let now = SystemTime::now();
        let mut freed = 0_u64;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("sh") {
                continue;
            }
            let Some(digest) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                || references.get(digest).copied().unwrap_or(0) > 0
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                continue;
            }
            let recent = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_none_or(|age| age < SNAPSHOT_RETAIN_GRACE);
            if recent {
                continue;
            }
            let size = safe_file_size(&snapshot_root, &path)?;
            safe_remove_file(&snapshot_root, &path)?;
            freed = freed.saturating_add(size);
        }
        Ok(freed)
    }

    fn delete_prunable_job(&self, job_id: u64) -> Result<Option<JobRecord>, SubmitError> {
        self.transaction(|| {
            let Some(record) = self.get_job(job_id)? else {
                return Ok(None);
            };
            if !record.state.is_terminal()
                || record.snapshot_sync_pending
                || record.log_sync_pending
            {
                return Ok(None);
            }
            self.connection.execute_integer(
                "DELETE FROM state_events WHERE job_id=?1",
                job_id as i64,
            )?;
            self.connection.execute_integer(
                "DELETE FROM jobs WHERE id=?1 AND state IN ('COMPLETED','FAILED','CANCELLED','TIMEOUT','NODE_LOST') AND snapshot_sync_pending=0 AND log_sync_pending=0",
                job_id as i64,
            )?;
            Ok(Some(record))
        })
    }

    fn has_active_node_job(
        &self,
        node: &macluster_protocol::identifiers::NodeId,
    ) -> Result<bool, SubmitError> {
        Ok(self
            .connection
            .query_text(
                "SELECT CASE WHEN EXISTS (SELECT 1 FROM jobs WHERE assigned_node=?1 AND state IN ('STARTING','RUNNING','CANCELLING')) THEN '1' ELSE '0' END",
                Some(node.to_string()),
            )?
            .as_deref()
            == Some("1"))
    }

    pub fn node_execution_to_reconcile(
        &self,
        node: &macluster_protocol::identifiers::NodeId,
    ) -> Result<Option<JobRecord>, SubmitError> {
        self.connection.query_text(
            "SELECT payload_json FROM jobs WHERE assigned_node=?1 AND (state IN ('STARTING','RUNNING','CANCELLING') OR log_sync_pending=1) ORDER BY CASE WHEN state IN ('STARTING','RUNNING','CANCELLING') THEN 0 ELSE 1 END,id DESC LIMIT 1",
            Some(node.to_string()),
        )?.map(|payload| decode_job(&payload)).transpose()
    }

    pub fn set_waiting_reason(
        &self,
        job_id: u64,
        reason: Option<String>,
    ) -> Result<JobRecord, SubmitError> {
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            if (record.state.is_terminal() && !record.log_sync_pending)
                || record.waiting_reason == reason
            {
                return Ok(record);
            }
            record.waiting_reason = reason;
            self.persist_record(&record, None)?;
            Ok(record)
        })
    }

    /// Return jobs whose state or placement means a node cannot yet be safely
    /// removed from the scheduler configuration.
    pub fn jobs_preventing_node_removal(
        &self,
        node_id: &str,
    ) -> Result<Vec<JobRecord>, SubmitError> {
        Ok(self
            .list_jobs(None)?
            .into_iter()
            .filter(|job| {
                let references_node = job
                    .node
                    .as_ref()
                    .is_some_and(|node| node.as_str() == node_id)
                    || job
                        .spec
                        .node
                        .as_ref()
                        .is_some_and(|node| node.as_str() == node_id);
                references_node
                    && (matches!(
                        job.state,
                        JobState::Starting | JobState::Running | JobState::Cancelling
                    ) || (job.state == JobState::Pending && job.spec.node.is_some())
                        || job.log_sync_pending)
            })
            .collect())
    }

    pub fn request_cancel(&self, job_id: u64, force: bool) -> Result<JobRecord, SubmitError> {
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            if record.state.is_terminal() {
                if record.state == JobState::Cancelled
                    && record.end_reason.as_deref() == Some("cancelled before dispatch")
                {
                    if record.snapshot_sync_pending {
                        record.snapshot_sync_pending = false;
                        self.persist_record(&record, None)?;
                    }
                    return Ok(record);
                }
                return Err(SubmitError::AlreadyTerminal(job_id));
            }
            let event_time = now_unix_ms();
            if record.state == JobState::Pending {
                record.state = JobState::Cancelled;
                record.finished_unix_ms = Some(event_time);
                record.end_reason = Some("cancelled before dispatch".into());
                record.snapshot_sync_pending = false;
                record.waiting_reason = None;
            } else {
                record.state = JobState::Cancelling;
                record.cancel_force |= force;
            }
            self.persist_record(&record, Some(event_time))?;
            Ok(record)
        })
    }

    pub fn reserve_job(
        &self,
        job_id: u64,
        node: macluster_protocol::identifiers::NodeId,
    ) -> Result<JobRecord, SubmitError> {
        self.connection.exec("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            if record.state != JobState::Pending {
                return Err(SubmitError::InvalidTransition(
                    job_id,
                    job_state_name(record.state).into(),
                    "STARTING".into(),
                ));
            }
            if self.has_active_node_job(&node)? {
                return Err(SubmitError::NodeBusy(node.to_string()));
            }
            record.node = Some(node);
            record.state = JobState::Starting;
            record.started_unix_ms = Some(now_unix_ms());
            record.start_token = Some(StartToken(Id128::random()));
            self.persist_record(&record, record.started_unix_ms)?;
            Ok(record)
        })();
        match result {
            Ok(record) => {
                self.connection.exec("COMMIT")?;
                Ok(record)
            }
            Err(error) => {
                let _ = self.connection.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn mark_running(&self, job_id: u64) -> Result<JobRecord, SubmitError> {
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            if record.state != JobState::Starting {
                return Err(SubmitError::InvalidTransition(
                    job_id,
                    job_state_name(record.state).into(),
                    "RUNNING".into(),
                ));
            }
            record.state = JobState::Running;
            self.persist_record(&record, Some(now_unix_ms()))?;
            Ok(record)
        })
    }

    pub fn finish_job(
        &self,
        job_id: u64,
        state: JobState,
        exit_code: Option<i32>,
        reason: Option<String>,
    ) -> Result<JobRecord, SubmitError> {
        if !state.is_terminal() {
            return Err(SubmitError::InvalidTransition(
                job_id,
                "ACTIVE".into(),
                job_state_name(state).into(),
            ));
        }
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            if !matches!(
                record.state,
                JobState::Starting | JobState::Running | JobState::Cancelling
            ) {
                return Err(SubmitError::InvalidTransition(
                    job_id,
                    job_state_name(record.state).into(),
                    job_state_name(state).into(),
                ));
            }
            let finished = now_unix_ms();
            record.state = state;
            record.finished_unix_ms = Some(finished);
            record.exit_code = exit_code;
            record.end_reason = reason;
            self.persist_record(&record, Some(finished))?;
            Ok(record)
        })
    }

    pub fn set_log_sync_pending(
        &self,
        job_id: u64,
        pending: bool,
    ) -> Result<JobRecord, SubmitError> {
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            record.log_sync_pending = pending;
            self.persist_record(&record, None)?;
            Ok(record)
        })
    }

    fn set_snapshot_sync_pending(&self, job_id: u64, pending: bool) -> Result<(), SubmitError> {
        self.transaction(|| {
            let mut record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
            record.snapshot_sync_pending = pending;
            self.persist_record(&record, None)
        })
    }

    /// Publish a committed local snapshot through a temporary file and rename.
    /// This method is intentionally called outside SQLite transactions.
    pub fn publish_snapshot(&self, job_id: u64, shared_root: &Path) -> Result<(), SubmitError> {
        let record = self.get_job(job_id)?.ok_or(SubmitError::NotFound(job_id))?;
        let snapshot = record
            .spec
            .snapshot
            .as_ref()
            .ok_or(SubmitError::MissingSnapshot)?;
        let source = self.snapshot_path(snapshot);
        self.verify_snapshot_file(&source, &snapshot.sha256, snapshot.size_bytes)?;
        let job_dir = record.spec.shared_job_dir(shared_root, job_id);
        fs::create_dir_all(&job_dir)?;
        let destination = job_dir.join("script.sh");
        if destination.exists() {
            self.verify_snapshot_file(&destination, &snapshot.sha256, snapshot.size_bytes)?;
        } else {
            let temp = job_dir.join(format!(".script-{}.tmp", RequestId::random()));
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            let copy_result = (|| -> io::Result<()> {
                io::copy(&mut File::open(source)?, &mut output)?;
                output.sync_all()?;
                fs::rename(&temp, &destination)?;
                File::open(&job_dir)?.sync_all()?;
                Ok(())
            })();
            drop(output);
            if copy_result.is_err() {
                let _ = fs::remove_file(&temp);
            }
            copy_result?;
        }
        self.set_snapshot_sync_pending(job_id, false)
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce() -> Result<T, SubmitError>,
    ) -> Result<T, SubmitError> {
        self.connection.exec("BEGIN IMMEDIATE")?;
        match operation() {
            Ok(value) => {
                self.connection.exec("COMMIT")?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.connection.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    fn persist_record(
        &self,
        record: &JobRecord,
        event_time: Option<u64>,
    ) -> Result<(), SubmitError> {
        let payload = serde_json::to_string(record)
            .map_err(|error| SubmitError::Serialization(error.to_string()))?;
        self.connection.update_job_record(record, &payload)?;
        if let Some(at) = event_time {
            self.connection.execute_integer_text_integer(
                "INSERT INTO state_events(job_id,state,at_unix_ms) VALUES (?1,?2,?3)",
                record.id as i64,
                job_state_name(record.state),
                at as i64,
            )?;
        }
        Ok(())
    }

    fn verify_snapshot_file(
        &self,
        path: &Path,
        expected_digest: &str,
        expected_size: u64,
    ) -> Result<(), SubmitError> {
        let metadata = fs::metadata(path)?;
        if metadata.len() != expected_size || metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err(SubmitError::SnapshotMismatch);
        }
        let bytes = fs::read(path)?;
        let digest =
            sha256_hex(&bytes).map_err(|error| SubmitError::Database(error.to_string()))?;
        if digest != expected_digest {
            return Err(SubmitError::SnapshotMismatch);
        }
        Ok(())
    }
}

fn decode_job(payload: &str) -> Result<JobRecord, SubmitError> {
    serde_json::from_str(payload).map_err(|error| SubmitError::Serialization(error.to_string()))
}

fn lock_schema_initialization(root: &Path) -> Result<File, SubmitError> {
    let path = root.join(".controller-schema.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    fs::set_permissions(
        root.join(".controller-schema.lock"),
        fs::Permissions::from_mode(0o600),
    )?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Pending => "PENDING",
        JobState::Starting => "STARTING",
        JobState::Running => "RUNNING",
        JobState::Cancelling => "CANCELLING",
        JobState::Completed => "COMPLETED",
        JobState::Failed => "FAILED",
        JobState::Cancelled => "CANCELLED",
        JobState::Timeout => "TIMEOUT",
        JobState::NodeLost => "NODE_LOST",
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct Connection {
    raw: *mut sqlite3,
}

impl Connection {
    fn open(path: &Path) -> Result<Self, SubmitError> {
        Self::open_with_flags(
            path,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            5_000,
        )
    }

    fn open_read_only(path: &Path, busy_timeout_ms: u32) -> Result<Self, SubmitError> {
        Self::open_with_flags(
            path,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            busy_timeout_ms,
        )
    }

    fn open_with_flags(
        path: &Path,
        flags: c_int,
        busy_timeout_ms: u32,
    ) -> Result<Self, SubmitError> {
        let path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| SubmitError::Database("database path contains NUL".into()))?;
        let mut raw = ptr::null_mut();
        let code = unsafe { sqlite3_open_v2(path.as_ptr(), &mut raw, flags, ptr::null()) };
        if code != SQLITE_OK {
            let message = if raw.is_null() {
                format!("sqlite open error {code}")
            } else {
                unsafe { CStr::from_ptr(sqlite3_errmsg(raw)) }
                    .to_string_lossy()
                    .into_owned()
            };
            if !raw.is_null() {
                unsafe {
                    sqlite3_close_v2(raw);
                }
            }
            return Err(SubmitError::Database(message));
        }
        unsafe {
            sqlite3_busy_timeout(raw, busy_timeout_ms as c_int);
        }
        Ok(Self { raw })
    }

    fn exec(&self, sql: &str) -> Result<(), SubmitError> {
        let sql =
            CString::new(sql).map_err(|_| SubmitError::Database("SQL contains NUL".into()))?;
        let mut error = ptr::null_mut();
        let code =
            unsafe { sqlite3_exec(self.raw, sql.as_ptr(), None, ptr::null_mut(), &mut error) };
        if code == SQLITE_OK {
            return Ok(());
        }
        let message = if error.is_null() {
            self.error_message()
        } else {
            let message = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe {
                sqlite3_free(error.cast());
            }
            message
        };
        Err(SubmitError::Database(message))
    }

    fn prepare(&self, sql: &str) -> Result<*mut sqlite3_stmt, SubmitError> {
        let sql =
            CString::new(sql).map_err(|_| SubmitError::Database("SQL contains NUL".into()))?;
        let mut statement = ptr::null_mut();
        let code = unsafe {
            sqlite3_prepare_v2(self.raw, sql.as_ptr(), -1, &mut statement, ptr::null_mut())
        };
        if code != SQLITE_OK {
            return Err(SubmitError::Database(self.error_message()));
        }
        Ok(statement)
    }

    fn query_text(
        &self,
        sql: &str,
        parameter: Option<String>,
    ) -> Result<Option<String>, SubmitError> {
        let statement = self.prepare(sql)?;
        if let Some(parameter) = parameter {
            bind_text(self.raw, statement, 1, &parameter)?;
        }
        let code = unsafe { sqlite3_step(statement) };
        let result = match code {
            SQLITE_ROW => Ok(Some(column_string(statement, 0)?)),
            SQLITE_DONE => Ok(None),
            _ => Err(SubmitError::Database(self.error_message())),
        };
        unsafe {
            sqlite3_finalize(statement);
        }
        result
    }

    fn query_pair(
        &self,
        sql: &str,
        parameter: &str,
    ) -> Result<Option<(String, String)>, SubmitError> {
        let statement = self.prepare(sql)?;
        bind_text(self.raw, statement, 1, parameter)?;
        let code = unsafe { sqlite3_step(statement) };
        let result = match code {
            SQLITE_ROW => Ok(Some((
                column_string(statement, 0)?,
                column_string(statement, 1)?,
            ))),
            SQLITE_DONE => Ok(None),
            _ => Err(SubmitError::Database(self.error_message())),
        };
        unsafe {
            sqlite3_finalize(statement);
        }
        result
    }

    fn query_texts(&self, sql: &str, parameter: Option<&str>) -> Result<Vec<String>, SubmitError> {
        let statement = self.prepare(sql)?;
        if let Some(parameter) = parameter {
            bind_text(self.raw, statement, 1, parameter)?;
        }
        self.collect_texts(statement, 0)
    }

    fn query_texts_column(&self, sql: &str, column: c_int) -> Result<Vec<String>, SubmitError> {
        let statement = self.prepare(sql)?;
        self.collect_texts(statement, column)
    }

    fn query_text_pairs(&self, sql: &str) -> Result<Vec<(String, String)>, SubmitError> {
        let statement = self.prepare(sql)?;
        let mut rows = Vec::new();
        loop {
            match unsafe { sqlite3_step(statement) } {
                SQLITE_ROW => {
                    rows.push((column_string(statement, 0)?, column_string(statement, 1)?))
                }
                SQLITE_DONE => break,
                _ => {
                    let error = SubmitError::Database(self.error_message());
                    unsafe { sqlite3_finalize(statement) };
                    return Err(error);
                }
            }
        }
        unsafe { sqlite3_finalize(statement) };
        Ok(rows)
    }

    fn query_queue_job_counts(&self) -> Result<Vec<QueueJobCounts>, SubmitError> {
        let statement = self.prepare(
            "SELECT queue,
                    SUM(CASE WHEN state='PENDING' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN state IN ('STARTING','RUNNING','CANCELLING') THEN 1 ELSE 0 END),
                    SUM(CASE WHEN state='COMPLETED' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN state='FAILED' THEN 1 ELSE 0 END)
             FROM jobs GROUP BY queue ORDER BY queue",
        )?;
        let mut counts = Vec::new();
        loop {
            match unsafe { sqlite3_step(statement) } {
                SQLITE_ROW => counts.push(QueueJobCounts {
                    queue: column_string(statement, 0)?,
                    pending: unsafe { sqlite3_column_int64(statement, 1) }.max(0) as u64,
                    running: unsafe { sqlite3_column_int64(statement, 2) }.max(0) as u64,
                    completed: unsafe { sqlite3_column_int64(statement, 3) }.max(0) as u64,
                    failed: unsafe { sqlite3_column_int64(statement, 4) }.max(0) as u64,
                }),
                SQLITE_DONE => break,
                _ => {
                    let error = SubmitError::Database(self.error_message());
                    unsafe { sqlite3_finalize(statement) };
                    return Err(error);
                }
            }
        }
        unsafe { sqlite3_finalize(statement) };
        Ok(counts)
    }

    fn collect_texts(
        &self,
        statement: *mut sqlite3_stmt,
        column: c_int,
    ) -> Result<Vec<String>, SubmitError> {
        let mut rows = Vec::new();
        loop {
            match unsafe { sqlite3_step(statement) } {
                SQLITE_ROW => rows.push(column_string(statement, column)?),
                SQLITE_DONE => break,
                _ => {
                    unsafe {
                        sqlite3_finalize(statement);
                    }
                    return Err(SubmitError::Database(self.error_message()));
                }
            }
        }
        unsafe {
            sqlite3_finalize(statement);
        }
        Ok(rows)
    }

    fn insert_job(
        &self,
        request_id: &str,
        request_digest: &str,
        created_unix_ms: i64,
        queue: &str,
        snapshot_sync_pending: bool,
    ) -> Result<(), SubmitError> {
        let statement = self.prepare(
            "INSERT INTO jobs(request_id, request_digest, payload_json, state, cancel_requested, assigned_node, created_unix_ms, queue, snapshot_sync_pending, log_sync_pending) VALUES (?1, ?2, '', 'PENDING', 0, NULL, ?3, ?4, ?5, 0)",
        )?;
        bind_text(self.raw, statement, 1, request_id)?;
        bind_text(self.raw, statement, 2, request_digest)?;
        check_sqlite(self.raw, unsafe {
            sqlite3_bind_int64(statement, 3, created_unix_ms)
        })?;
        bind_text(self.raw, statement, 4, queue)?;
        check_sqlite(self.raw, unsafe {
            sqlite3_bind_int64(statement, 5, i64::from(snapshot_sync_pending))
        })?;
        let code = unsafe { sqlite3_step(statement) };
        unsafe { sqlite3_finalize(statement) };
        if code == SQLITE_DONE {
            Ok(())
        } else {
            Err(SubmitError::Database(self.error_message()))
        }
    }

    fn update_job_index_fields(
        &self,
        id: i64,
        queue: &str,
        snapshot_sync_pending: bool,
        log_sync_pending: bool,
    ) -> Result<(), SubmitError> {
        let statement = self.prepare(
            "UPDATE jobs SET queue=?1, snapshot_sync_pending=?2, log_sync_pending=?3 WHERE id=?4",
        )?;
        bind_text(self.raw, statement, 1, queue)?;
        for (index, value) in [(2, snapshot_sync_pending), (3, log_sync_pending)] {
            check_sqlite(self.raw, unsafe {
                sqlite3_bind_int64(statement, index, i64::from(value))
            })?;
        }
        check_sqlite(self.raw, unsafe { sqlite3_bind_int64(statement, 4, id) })?;
        let code = unsafe { sqlite3_step(statement) };
        unsafe { sqlite3_finalize(statement) };
        if code == SQLITE_DONE {
            Ok(())
        } else {
            Err(SubmitError::Database(self.error_message()))
        }
    }

    fn update_job_record(&self, record: &JobRecord, payload: &str) -> Result<(), SubmitError> {
        let node = record.node.as_ref().map_or("", |node| node.as_str());
        let statement = self.prepare(
            "UPDATE jobs SET payload_json=?1, state=?2, cancel_requested=CASE WHEN ?2='CANCELLING' THEN 1 ELSE cancel_requested END, assigned_node=NULLIF(?3,''), queue=?4, snapshot_sync_pending=?5, log_sync_pending=?6 WHERE id=?7",
        )?;
        bind_text(self.raw, statement, 1, payload)?;
        bind_text(self.raw, statement, 2, job_state_name(record.state))?;
        bind_text(self.raw, statement, 3, node)?;
        bind_text(self.raw, statement, 4, record.spec.queue.as_str())?;
        check_sqlite(self.raw, unsafe {
            sqlite3_bind_int64(statement, 5, i64::from(record.snapshot_sync_pending))
        })?;
        check_sqlite(self.raw, unsafe {
            sqlite3_bind_int64(statement, 6, i64::from(record.log_sync_pending))
        })?;
        check_sqlite(self.raw, unsafe {
            sqlite3_bind_int64(statement, 7, record.id as i64)
        })?;
        let code = unsafe { sqlite3_step(statement) };
        unsafe { sqlite3_finalize(statement) };
        if code == SQLITE_DONE {
            Ok(())
        } else {
            Err(SubmitError::Database(self.error_message()))
        }
    }

    fn execute_integer_text_integer(
        &self,
        sql: &str,
        first: i64,
        state: &str,
        third: i64,
    ) -> Result<(), SubmitError> {
        let statement = self.prepare(sql)?;
        check_sqlite(self.raw, unsafe { sqlite3_bind_int64(statement, 1, first) })?;
        bind_text(self.raw, statement, 2, state)?;
        check_sqlite(self.raw, unsafe { sqlite3_bind_int64(statement, 3, third) })?;
        let code = unsafe { sqlite3_step(statement) };
        unsafe {
            sqlite3_finalize(statement);
        }
        if code == SQLITE_DONE {
            Ok(())
        } else {
            Err(SubmitError::Database(self.error_message()))
        }
    }

    fn execute_integer(&self, sql: &str, value: i64) -> Result<(), SubmitError> {
        let statement = self.prepare(sql)?;
        check_sqlite(self.raw, unsafe { sqlite3_bind_int64(statement, 1, value) })?;
        let code = unsafe { sqlite3_step(statement) };
        unsafe { sqlite3_finalize(statement) };
        if code == SQLITE_DONE {
            Ok(())
        } else {
            Err(SubmitError::Database(self.error_message()))
        }
    }

    fn error_message(&self) -> String {
        unsafe { CStr::from_ptr(sqlite3_errmsg(self.raw)) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            sqlite3_close_v2(self.raw);
        }
    }
}

fn bind_text(
    database: *mut sqlite3,
    statement: *mut sqlite3_stmt,
    index: c_int,
    value: &str,
) -> Result<(), SubmitError> {
    let value =
        CString::new(value).map_err(|_| SubmitError::Database("text value contains NUL".into()))?;
    // SQLITE_TRANSIENT asks SQLite to copy bytes before this CString is dropped.
    let destructor =
        unsafe { std::mem::transmute::<isize, Option<unsafe extern "C" fn(*mut c_void)>>(-1) };
    check_sqlite(database, unsafe {
        sqlite3_bind_text(statement, index, value.as_ptr(), -1, destructor)
    })
}

fn column_string(statement: *mut sqlite3_stmt, column: c_int) -> Result<String, SubmitError> {
    let pointer = unsafe { sqlite3_column_text(statement, column) };
    if pointer.is_null() {
        return Err(SubmitError::Database("unexpected NULL text value".into()));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(pointer, sqlite3_column_bytes(statement, column) as usize)
    };
    String::from_utf8(bytes.to_vec()).map_err(|error| SubmitError::Database(error.to_string()))
}

fn check_sqlite(database: *mut sqlite3, code: c_int) -> Result<(), SubmitError> {
    if code == SQLITE_OK {
        Ok(())
    } else {
        Err(SubmitError::Database(
            unsafe { CStr::from_ptr(sqlite3_errmsg(database)) }
                .to_string_lossy()
                .into_owned(),
        ))
    }
}

fn file_size_if_present(path: &Path) -> Result<u64, SubmitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            Ok(metadata.len())
        }
        Ok(_) => Ok(0),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn safe_tree_size(root: &Path, path: &Path) -> Result<u64, SubmitError> {
    let root = root.canonicalize()?;
    let Some(metadata) = checked_managed_path(&root, path)? else {
        return Ok(0);
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    tree_size_no_follow(path).map_err(SubmitError::Io)
}

fn safe_file_size(root: &Path, path: &Path) -> Result<u64, SubmitError> {
    let root = root.canonicalize()?;
    let Some(metadata) = checked_managed_path(&root, path)? else {
        return Ok(0);
    };
    if metadata.is_file() || metadata.file_type().is_symlink() {
        Ok(metadata.len())
    } else {
        Ok(0)
    }
}

fn safe_remove_tree(root: &Path, path: &Path) -> Result<(), SubmitError> {
    let root = root.canonicalize()?;
    let Some(metadata) = checked_managed_path(&root, path)? else {
        return Ok(());
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn safe_remove_file(root: &Path, path: &Path) -> Result<(), SubmitError> {
    let root = root.canonicalize()?;
    let Some(metadata) = checked_managed_path(&root, path)? else {
        return Ok(());
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        return Err(SubmitError::Database(format!(
            "refusing to remove non-file snapshot path {}",
            path.display()
        )));
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Confirm every ancestor below a managed root is a real directory. This
/// prevents cleanup from following a user-created symlink outside the store.
fn checked_managed_path(root: &Path, path: &Path) -> Result<Option<fs::Metadata>, SubmitError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        SubmitError::Database(format!(
            "managed cleanup path {} escaped {}",
            path.display(),
            root.display()
        ))
    })?;
    if relative.as_os_str().is_empty() {
        return Err(SubmitError::Database(
            "refusing to operate on a managed storage root".into(),
        ));
    }
    let components = relative.components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(SubmitError::Database(
                "managed cleanup path contains an unsafe component".into(),
            ));
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let last = index + 1 == components.len();
        if !last && (metadata.file_type().is_symlink() || !metadata.is_dir()) {
            return Err(SubmitError::Database(format!(
                "managed path ancestor {} is not a real directory",
                current.display()
            )));
        }
        if last {
            return Ok(Some(metadata));
        }
    }
    Ok(None)
}

fn tree_size_no_follow(path: &Path) -> io::Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            total = total.saturating_add(tree_size_no_follow(&entry.path())?);
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

#[cfg(test)]
mod read_only_tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use macluster_protocol::identifiers::Id128;

    use super::{Connection, ReadOnlyJobStore};

    fn fresh_root() -> PathBuf {
        std::env::temp_dir().join(format!("macluster-read-only-unit-{}", Id128::random()))
    }

    #[test]
    fn incompatible_schema_is_rejected_without_migration() {
        let root = fresh_root();
        fs::create_dir_all(&root).unwrap();
        let database = root.join("controller.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .exec("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version','99');")
            .unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();

        assert!(ReadOnlyJobStore::open(&root).is_err());
        assert_eq!(fs::read(&database).unwrap(), before);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maintenance_work_query_detects_active_jobs_and_pending_sync_only() {
        let root = fresh_root();
        fs::create_dir_all(&root).unwrap();
        let database = root.join("controller.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .exec(
                "CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO schema_meta VALUES('schema_version','3');
                 CREATE TABLE jobs(state TEXT, snapshot_sync_pending INTEGER, log_sync_pending INTEGER);
                 INSERT INTO jobs VALUES('COMPLETED', 0, 0);",
            )
            .unwrap();
        drop(connection);

        assert!(
            !ReadOnlyJobStore::open(&root)
                .unwrap()
                .has_maintenance_work()
                .unwrap()
        );

        let connection = Connection::open(&database).unwrap();
        connection
            .exec("INSERT INTO jobs VALUES('RUNNING', 0, 0);")
            .unwrap();
        drop(connection);
        assert!(
            ReadOnlyJobStore::open(&root)
                .unwrap()
                .has_maintenance_work()
                .unwrap()
        );

        let connection = Connection::open(&database).unwrap();
        connection
            .exec("DELETE FROM jobs WHERE state='RUNNING'; INSERT INTO jobs VALUES('COMPLETED', 1, 0);")
            .unwrap();
        drop(connection);
        assert!(
            ReadOnlyJobStore::open(&root)
                .unwrap()
                .has_maintenance_work()
                .unwrap()
        );

        let connection = Connection::open(&database).unwrap();
        connection
            .exec("UPDATE jobs SET snapshot_sync_pending=0;")
            .unwrap();
        drop(connection);
        assert!(
            !ReadOnlyJobStore::open(&root)
                .unwrap()
                .has_maintenance_work()
                .unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_database_lock_fails_within_the_busy_timeout() {
        let root = fresh_root();
        fs::create_dir_all(&root).unwrap();
        let database = root.join("controller.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection
            .exec("PRAGMA journal_mode=DELETE; CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version','2'); CREATE TABLE jobs(payload_json TEXT, state TEXT, id INTEGER);")
            .unwrap();
        connection.exec("BEGIN EXCLUSIVE").unwrap();

        let started = Instant::now();
        let result = ReadOnlyJobStore::open(&root);
        let elapsed = started.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed >= Duration::from_millis(400),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod schema_migration_tests {
    use std::{fs, path::PathBuf};

    use macluster_protocol::{
        identifiers::{Id128, NodeId, QueueName, RequestId},
        types::{JobMode, JobSpec, JobState},
    };

    use super::{Connection, ReadOnlyJobStore, Storage};

    fn fresh_root() -> PathBuf {
        std::env::temp_dir().join(format!("macluster-schema-v3-{}", Id128::random()))
    }

    fn interactive_spec(queue: &str) -> JobSpec {
        JobSpec {
            storage_namespace: None,
            queue: QueueName::new(queue).unwrap(),
            node: Some(NodeId::new("mini01-a").unwrap()),
            name: "migration fixture".into(),
            cwd: "/Users/Shared/macluster".into(),
            stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
            stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
            walltime_secs: None,
            env: Default::default(),
            mode: JobMode::Interactive,
            snapshot: None,
        }
    }

    fn set_schema_v2(root: &PathBuf) {
        let connection = Connection::open(&root.join("controller.sqlite3")).unwrap();
        connection
            .exec(
                "DROP INDEX IF EXISTS jobs_queue_work;
                 DROP INDEX IF EXISTS jobs_queue_state;
                 ALTER TABLE jobs DROP COLUMN log_sync_pending;
                 ALTER TABLE jobs DROP COLUMN snapshot_sync_pending;
                 ALTER TABLE jobs DROP COLUMN queue;
                 UPDATE schema_meta SET value='2' WHERE key='schema_version';",
            )
            .unwrap();
    }

    #[test]
    fn schema_v2_migrates_atomically_and_can_be_reopened() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let record = storage
            .submit_once(RequestId(Id128::random()), interactive_spec("mini01"))
            .unwrap();
        drop(storage);
        set_schema_v2(&root);

        let migrated = Storage::open(&root).unwrap();
        assert_eq!(
            migrated
                .get_job(record.id)
                .unwrap()
                .unwrap()
                .spec
                .queue
                .as_str(),
            "mini01"
        );
        assert_eq!(migrated.queue_job_counts().unwrap()[0].pending, 1);
        assert_eq!(migrated.list_reconcile_jobs().unwrap().len(), 1);
        drop(migrated);
        assert_eq!(
            ReadOnlyJobStore::open(&root)
                .unwrap()
                .list_jobs(None)
                .unwrap()
                .len(),
            1
        );
        drop(ReadOnlyJobStore::open(&root).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn schema_v2_migration_rolls_back_when_a_payload_is_invalid() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let record = storage
            .submit_once(RequestId(Id128::random()), interactive_spec("mini01"))
            .unwrap();
        drop(storage);
        set_schema_v2(&root);
        let connection = Connection::open(&root.join("controller.sqlite3")).unwrap();
        connection
            .exec(&format!(
                "UPDATE jobs SET payload_json='invalid json' WHERE id={};",
                record.id
            ))
            .unwrap();
        drop(connection);

        assert!(Storage::open(&root).is_err());

        let connection = Connection::open(&root.join("controller.sqlite3")).unwrap();
        assert_eq!(
            connection
                .query_text(
                    "SELECT value FROM schema_meta WHERE key='schema_version'",
                    None
                )
                .unwrap()
                .as_deref(),
            Some("2")
        );
        let columns = connection
            .query_texts_column("PRAGMA table_info(jobs)", 1)
            .unwrap();
        assert!(!columns.iter().any(|column| column == "queue"));
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_newer_schema_is_rejected_without_database_changes() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let record = storage
            .submit_once(RequestId(Id128::random()), interactive_spec("mini01"))
            .unwrap();
        drop(storage);
        let connection = Connection::open(&root.join("controller.sqlite3")).unwrap();
        connection
            .exec("UPDATE schema_meta SET value='99' WHERE key='schema_version';")
            .unwrap();
        drop(connection);
        let database = root.join("controller.sqlite3");
        let before = fs::read(&database).unwrap();

        assert!(Storage::open(&root).is_err());

        assert_eq!(fs::read(&database).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
        assert!(record.id > 0);
    }

    #[test]
    fn terminal_state_remains_terminal_after_schema_reopen() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let record = storage
            .submit_once(RequestId(Id128::random()), interactive_spec("mini01"))
            .unwrap();
        storage
            .reserve_job(record.id, NodeId::new("mini01-a").unwrap())
            .unwrap();
        storage.mark_running(record.id).unwrap();
        storage
            .finish_job(record.id, JobState::Completed, Some(0), None)
            .unwrap();
        drop(storage);
        let reopened = Storage::open(&root).unwrap();
        assert_eq!(
            reopened.get_job(record.id).unwrap().unwrap().state,
            JobState::Completed
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_node_lookup_uses_the_partial_occupation_index() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let node = NodeId::new("mini01-a").unwrap();
        assert!(!storage.has_active_node_job(&node).unwrap());
        let record = storage
            .submit_once(RequestId(Id128::random()), interactive_spec("mini01"))
            .unwrap();
        storage.reserve_job(record.id, node.clone()).unwrap();
        assert!(storage.has_active_node_job(&node).unwrap());
        let plan = storage
            .connection
            .query_texts_column(
                "EXPLAIN QUERY PLAN SELECT 1 FROM jobs WHERE assigned_node='mini01-a' AND state IN ('STARTING','RUNNING','CANCELLING') LIMIT 1",
                3,
            )
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail.contains("active_node_occupation")),
            "{plan:?}"
        );
        let queue_plan = storage
            .connection
            .query_texts_column(
                "EXPLAIN QUERY PLAN SELECT queue, SUM(CASE WHEN state='PENDING' THEN 1 ELSE 0 END) FROM jobs GROUP BY queue ORDER BY queue",
                3,
            )
            .unwrap();
        assert!(
            queue_plan
                .iter()
                .any(|detail| detail.contains("jobs_queue_state")),
            "{queue_plan:?}"
        );
        storage.mark_running(record.id).unwrap();
        storage
            .finish_job(record.id, JobState::Completed, Some(0), None)
            .unwrap();
        assert!(!storage.has_active_node_job(&node).unwrap());
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod cancellation_recovery_tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use macluster_protocol::{
        identifiers::{Id128, NodeId, QueueName, RequestId},
        types::{JobMode, JobSpec, JobState, SnapshotRef},
    };

    use super::Storage;

    fn fresh_root() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("macluster-cancel-snapshot-{}", Id128::random()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn job_spec(snapshot: SnapshotRef) -> JobSpec {
        JobSpec {
            storage_namespace: None,
            queue: QueueName::new("mini01").unwrap(),
            node: Some(NodeId::new("mini01-a").unwrap()),
            name: "snapshot cancellation".into(),
            cwd: "/Users/Shared/macluster".into(),
            stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
            stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
            walltime_secs: None,
            env: BTreeMap::new(),
            mode: JobMode::Batch,
            snapshot: Some(snapshot),
        }
    }

    fn legacy_cancelled_job(storage: &Storage) -> u64 {
        let snapshot = storage.stage_snapshot(b"echo unused\n").unwrap();
        let job = storage
            .submit_once(RequestId(Id128::random()), job_spec(snapshot))
            .unwrap();
        storage.request_cancel(job.id, false).unwrap();
        storage.set_snapshot_sync_pending(job.id, true).unwrap();
        assert_eq!(
            storage.get_job(job.id).unwrap().unwrap().state,
            JobState::Cancelled
        );
        job.id
    }

    #[test]
    fn idempotent_cancel_clears_a_legacy_snapshot_pending_flag() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let job_id = legacy_cancelled_job(&storage);

        let job = storage.request_cancel(job_id, false).unwrap();

        assert!(!job.snapshot_sync_pending);
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readonly_queue_counts_do_not_deserialize_terminal_history() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        legacy_cancelled_job(&storage);
        storage
            .connection
            .exec("UPDATE jobs SET state='COMPLETED', payload_json='not-json';")
            .unwrap();
        let expected = storage.queue_job_counts().unwrap();
        assert_eq!(expected[0].completed, 1);
        let reader = super::ReadOnlyJobStore::open(&root).unwrap();
        assert_eq!(reader.queue_job_counts().unwrap(), expected);
        drop(reader);
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_job_listing_includes_terminal_jobs_with_sync_pending() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let job_id = legacy_cancelled_job(&storage);

        let active = storage.list_active_jobs().unwrap();

        assert!(active.iter().any(|job| job.id == job_id));
        let reader = super::ReadOnlyJobStore::open(&root).unwrap();
        assert_eq!(reader.list_active_jobs().unwrap(), active);
        drop(reader);
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_job_listing_includes_terminal_jobs_with_log_sync_pending() {
        let root = fresh_root();
        let storage = Storage::open(&root).unwrap();
        let job_id = legacy_cancelled_job(&storage);
        storage.set_snapshot_sync_pending(job_id, false).unwrap();
        storage.set_log_sync_pending(job_id, true).unwrap();

        let active = storage.list_active_jobs().unwrap();

        assert!(active.iter().any(|job| job.id == job_id));
        let reader = super::ReadOnlyJobStore::open(&root).unwrap();
        assert_eq!(reader.list_active_jobs().unwrap(), active);
        drop(reader);
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }
}
