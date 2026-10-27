use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_core::storage::{Storage, SubmitError};
use macluster_protocol::{
    identifiers::{Id128, NodeId, QueueName, RequestId},
    types::{JobMode, JobSpec, JobState},
};

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("macluster-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn spec(snapshot: macluster_protocol::types::SnapshotRef) -> JobSpec {
    JobSpec {
        storage_namespace: None,
        queue: QueueName::new("mini01").unwrap(),
        node: Some(NodeId::new("mini01-a").unwrap()),
        name: "analysis".into(),
        cwd: "/Users/Shared/macluster/projects/demo".into(),
        stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
        stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
        walltime_secs: None,
        env: BTreeMap::new(),
        mode: JobMode::Batch,
        snapshot: Some(snapshot),
    }
}

#[test]
fn duplicate_submit_returns_same_job_and_conflicting_reuse_fails() {
    let root = temp_dir("submit-once");
    let storage = Storage::open(&root).unwrap();
    let bytes = b"#!/bin/bash\necho hello\n";
    let snapshot = storage.stage_snapshot(bytes).unwrap();
    let request = RequestId(Id128::random());
    let first_spec = spec(snapshot.clone());

    let first = storage.submit_once(request, first_spec.clone()).unwrap();
    let replay = storage.submit_once(request, first_spec).unwrap();

    assert_eq!(first.id, replay.id);
    assert_eq!(first.state, JobState::Pending);
    assert_eq!(storage.list_jobs(None).unwrap().len(), 1);
    assert!(matches!(
        storage.submit_once(request, spec(storage.stage_snapshot(b"different").unwrap())),
        Err(SubmitError::RequestConflict)
    ));

    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn snapshot_is_durable_and_database_survives_reopen() {
    let root = temp_dir("snapshot-reopen");
    let request = RequestId(Id128::random());
    let job_id;
    {
        let storage = Storage::open(&root).unwrap();
        let snapshot = storage.stage_snapshot(b"echo durable\n").unwrap();
        assert!(storage.snapshot_path(&snapshot).exists());
        let job = storage.submit_once(request, spec(snapshot)).unwrap();
        job_id = job.id;
    }
    let reopened = Storage::open(&root).unwrap();
    let job = reopened.get_job(job_id).unwrap().unwrap();
    assert_eq!(job.id, job_id);
    assert_eq!(job.state, JobState::Pending);
    assert!(job.snapshot_sync_pending);
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interactive_shell_job_persists_without_snapshot() {
    let root = temp_dir("interactive-shell-submit");
    let storage = Storage::open(&root).unwrap();
    let placeholder = storage.stage_snapshot(b"placeholder").unwrap();
    let mut value = serde_json::to_value(spec(placeholder)).unwrap();
    value["mode"] = serde_json::json!("interactive");
    value["snapshot"] = serde_json::Value::Null;
    let interactive = serde_json::from_value(value).unwrap();

    let job = storage
        .submit_once(RequestId(Id128::random()), interactive)
        .unwrap();

    assert_eq!(job.state, JobState::Pending);
    assert!(!job.snapshot_sync_pending);
    assert_eq!(
        serde_json::to_value(job.spec).unwrap()["snapshot"],
        serde_json::Value::Null
    );
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn batch_job_without_snapshot_is_rejected() {
    let root = temp_dir("batch-without-snapshot");
    let storage = Storage::open(&root).unwrap();
    let placeholder = storage.stage_snapshot(b"placeholder").unwrap();
    let mut value = serde_json::to_value(spec(placeholder)).unwrap();
    value["mode"] = serde_json::json!("batch");
    value["snapshot"] = serde_json::Value::Null;
    let batch = serde_json::from_value(value).unwrap();

    let result = storage.submit_once(RequestId(Id128::random()), batch);

    assert!(result.is_err());
    assert!(storage.list_jobs(None).unwrap().is_empty());
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_wait_reason_can_be_set_and_cleared_without_changing_job_state() {
    let root = temp_dir("waiting-reason");
    let storage = Storage::open(&root).unwrap();
    let snapshot = storage.stage_snapshot(b"echo queued\n").unwrap();
    let job = storage
        .submit_once(RequestId(Id128::random()), spec(snapshot))
        .unwrap();

    let waiting = storage
        .set_waiting_reason(job.id, Some("retry msub to trigger an Agent update".into()))
        .unwrap();
    assert_eq!(waiting.state, JobState::Pending);
    assert_eq!(
        waiting.waiting_reason.as_deref(),
        Some("retry msub to trigger an Agent update")
    );
    let ready = storage.set_waiting_reason(job.id, None).unwrap();
    assert_eq!(ready.state, JobState::Pending);
    assert_eq!(ready.waiting_reason, None);

    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn queue_job_counts_aggregate_states_without_decoding_all_job_records() {
    let root = temp_dir("queue-counts");
    let storage = Storage::open(&root).unwrap();
    let node = NodeId::new("mini01-a").unwrap();
    let submit = |queue: &str, body: &[u8]| {
        let snapshot = storage.stage_snapshot(body).unwrap();
        let mut job_spec = spec(snapshot);
        job_spec.queue = QueueName::new(queue).unwrap();
        storage
            .submit_once(RequestId(Id128::random()), job_spec)
            .unwrap()
    };

    let _pending = submit("mini01", b"echo pending");
    let running = submit("mini01", b"echo running");
    storage.reserve_job(running.id, node.clone()).unwrap();
    let completed = submit("mini01", b"echo completed");
    storage
        .reserve_job(completed.id, NodeId::new("mini01-b").unwrap())
        .unwrap();
    storage.mark_running(completed.id).unwrap();
    storage
        .finish_job(completed.id, JobState::Completed, Some(0), None)
        .unwrap();
    let failed = submit("mini02", b"echo failed");
    storage
        .reserve_job(failed.id, NodeId::new("mini01-c").unwrap())
        .unwrap();
    storage.mark_running(failed.id).unwrap();
    storage
        .finish_job(failed.id, JobState::Failed, Some(1), Some("failed".into()))
        .unwrap();

    let counts = storage.queue_job_counts().unwrap();

    assert_eq!(counts.len(), 2);
    assert_eq!(counts[0].queue, "mini01");
    assert_eq!(
        (
            counts[0].pending,
            counts[0].running,
            counts[0].completed,
            counts[0].failed
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(counts[1].queue, "mini02");
    assert_eq!(
        (
            counts[1].pending,
            counts[1].running,
            counts[1].completed,
            counts[1].failed
        ),
        (0, 0, 0, 1)
    );
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconcile_job_query_keeps_active_pending_and_terminal_log_sync_work() {
    let root = temp_dir("reconcile-jobs");
    let storage = Storage::open(&root).unwrap();
    let node = NodeId::new("mini01-a").unwrap();
    let pending = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo pending").unwrap()),
        )
        .unwrap();
    let log_pending = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo log").unwrap()),
        )
        .unwrap();
    let shared_root = root.join("shared");
    storage
        .publish_snapshot(log_pending.id, &shared_root)
        .unwrap();
    storage.reserve_job(log_pending.id, node.clone()).unwrap();
    storage.mark_running(log_pending.id).unwrap();
    storage
        .finish_job(log_pending.id, JobState::Completed, Some(0), None)
        .unwrap();
    storage.set_log_sync_pending(log_pending.id, true).unwrap();
    let old_terminal = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo done").unwrap()),
        )
        .unwrap();
    storage
        .publish_snapshot(old_terminal.id, &shared_root)
        .unwrap();
    storage.reserve_job(old_terminal.id, node.clone()).unwrap();
    storage.mark_running(old_terminal.id).unwrap();
    storage
        .finish_job(old_terminal.id, JobState::Completed, Some(0), None)
        .unwrap();

    let jobs = storage.list_reconcile_jobs().unwrap();
    let ids: Vec<_> = jobs.into_iter().map(|job| job.id).collect();

    assert!(ids.contains(&pending.id));
    assert!(ids.contains(&log_pending.id));
    assert!(!ids.contains(&old_terminal.id));
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_cancel_is_idempotent_and_terminal_jobs_are_not_rewritten() {
    let root = temp_dir("cancel");
    let storage = Storage::open(&root).unwrap();
    let snapshot = storage.stage_snapshot(b"exit 0\n").unwrap();
    let job = storage
        .submit_once(RequestId(Id128::random()), spec(snapshot))
        .unwrap();

    storage
        .set_waiting_reason(
            job.id,
            Some("waiting for an online node; retry msub to trigger an Agent update".into()),
        )
        .unwrap();
    storage.request_cancel(job.id, false).unwrap();
    storage.request_cancel(job.id, false).unwrap();
    let cancelled = storage.get_job(job.id).unwrap().unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
    assert!(!cancelled.snapshot_sync_pending);
    assert_eq!(cancelled.waiting_reason, None);
    assert_eq!(
        storage.list_jobs(Some(JobState::Cancelled)).unwrap().len(),
        1
    );
    assert_eq!(
        storage.request_cancel(job.id, false).unwrap().state,
        JobState::Cancelled
    );

    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn node_reservation_is_exclusive_and_job_transitions_are_persisted() {
    let root = temp_dir("reservation");
    let storage = Storage::open(&root).unwrap();
    let first = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo first\n").unwrap()),
        )
        .unwrap();
    let second = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo second\n").unwrap()),
        )
        .unwrap();
    let node = NodeId::new("mini01-a").unwrap();

    storage.reserve_job(first.id, node.clone()).unwrap();
    assert!(matches!(
        storage.reserve_job(second.id, node.clone()),
        Err(SubmitError::NodeBusy(_))
    ));
    storage.mark_running(first.id).unwrap();
    assert_eq!(
        storage.get_job(first.id).unwrap().unwrap().state,
        JobState::Running
    );
    storage
        .finish_job(first.id, JobState::Completed, Some(0), None)
        .unwrap();
    storage.reserve_job(second.id, node).unwrap();

    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn controller_epoch_increments_and_uuid_survives_reopen() {
    let root = temp_dir("controller-epoch");
    let first;
    {
        let storage = Storage::open(&root).unwrap();
        first = storage.begin_controller_epoch().unwrap();
        assert_eq!(first.epoch, 1);
    }
    let storage = Storage::open(&root).unwrap();
    let second = storage.begin_controller_epoch().unwrap();
    assert_eq!(second.controller_uuid, first.controller_uuid);
    assert_eq!(second.epoch, 2);
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn current_controller_epoch_can_be_read_without_advancing_the_fence() {
    let root = temp_dir("read-controller-epoch");
    let storage = Storage::open(&root).unwrap();
    assert_eq!(storage.current_controller_epoch().unwrap(), None);
    let first = storage.begin_controller_epoch().unwrap();
    assert_eq!(storage.current_controller_epoch().unwrap(), Some(first));
    assert_eq!(storage.current_controller_epoch().unwrap(), Some(first));
    let second = storage.begin_controller_epoch().unwrap();
    assert_eq!(second.epoch, first.epoch + 1);
    assert_eq!(storage.current_controller_epoch().unwrap(), Some(second));
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema_v1_migrates_atomically_and_can_be_reopened() {
    let root = temp_dir("schema-v1");
    let database = root.join("controller.sqlite3");
    let sql = "CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version','1'); CREATE TABLE jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,payload_json TEXT NOT NULL,state TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,created_unix_ms INTEGER NOT NULL); CREATE TABLE state_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL REFERENCES jobs(id),state TEXT NOT NULL,at_unix_ms INTEGER NOT NULL,reason TEXT);";
    let status = std::process::Command::new("/usr/bin/sqlite3")
        .arg(&database)
        .arg(sql)
        .status()
        .unwrap();
    assert!(status.success());

    let storage = Storage::open(&root).unwrap();
    drop(storage);
    let reopened = Storage::open(&root).unwrap();
    let bytes = b"echo after migration\n";
    let snapshot = reopened.stage_snapshot(bytes).unwrap();
    let job = reopened
        .submit_once(RequestId(Id128::random()), spec(snapshot))
        .unwrap();
    reopened
        .reserve_job(job.id, NodeId::new("mini01-a").unwrap())
        .unwrap();
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_schema_migrations_observe_the_committed_version() {
    let root = temp_dir("concurrent-schema-migration");
    let database = root.join("controller.sqlite3");
    let sql = "CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version','1'); CREATE TABLE jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,request_digest TEXT NOT NULL,payload_json TEXT NOT NULL,state TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,created_unix_ms INTEGER NOT NULL); CREATE TABLE state_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL REFERENCES jobs(id),state TEXT NOT NULL,at_unix_ms INTEGER NOT NULL,reason TEXT);";
    let status = std::process::Command::new("/usr/bin/sqlite3")
        .arg(&database)
        .arg(sql)
        .status()
        .unwrap();
    assert!(status.success());

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
    let handles: Vec<_> = (0..12)
        .map(|_| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                Storage::open(root)
                    .map(drop)
                    .map_err(|error| error.to_string())
            })
        })
        .collect();
    let errors: Vec<_> = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap().err())
        .collect();
    assert!(
        errors.is_empty(),
        "concurrent migrations failed: {errors:?}"
    );

    let storage = Storage::open(&root).unwrap();
    let snapshot = storage.stage_snapshot(b"echo migrated\n").unwrap();
    let job = storage
        .submit_once(RequestId(Id128::random()), spec(snapshot))
        .unwrap();
    assert_eq!(
        storage.get_job(job.id).unwrap().unwrap().state,
        JobState::Pending
    );
    drop(storage);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_reservations_cannot_occupy_one_node_twice() {
    let root = temp_dir("parallel-reservation");
    let storage = Storage::open(&root).unwrap();
    let first = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo one\n").unwrap()),
        )
        .unwrap();
    let second = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo two\n").unwrap()),
        )
        .unwrap();
    drop(storage);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = [first.id, second.id]
        .into_iter()
        .map(|job_id| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let storage = Storage::open(root).unwrap();
                barrier.wait();
                storage.reserve_job(job_id, NodeId::new("mini01-a").unwrap())
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(SubmitError::NodeBusy(_))))
            .count(),
        1
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_first_opens_initialize_one_valid_schema() {
    let root = temp_dir("concurrent-first-open");

    for round in 0..3 {
        let database_root = root.join(round.to_string());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let database_root = database_root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    Storage::open(database_root)
                        .map(drop)
                        .map_err(|error| error.to_string())
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let errors: Vec<_> = results.into_iter().filter_map(Result::err).collect();
        assert!(
            errors.is_empty(),
            "concurrent first opens failed in round {round}: {errors:?}"
        );
    }

    fs::remove_dir_all(root).unwrap();
}
