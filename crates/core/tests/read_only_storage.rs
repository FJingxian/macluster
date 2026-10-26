use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use macluster_core::storage::{ReadOnlyJobStore, Storage};
use macluster_protocol::{
    identifiers::{Id128, NodeId, QueueName, RequestId},
    types::{JobMode, JobSpec, JobState},
};

fn fresh_root() -> PathBuf {
    std::env::temp_dir().join(format!("macluster-read-only-{}", Id128::random()))
}

#[test]
fn opening_missing_state_never_creates_it() {
    let root = fresh_root();
    assert!(!root.exists());

    let result = ReadOnlyJobStore::open(&root);

    assert!(result.is_err());
    assert!(!root.exists());
}

#[test]
fn reading_existing_state_does_not_change_database_bytes() {
    let root = fresh_root();
    let storage = Storage::open(&root).expect("create controller database");
    drop(storage);
    let database = root.join("controller.sqlite3");
    let before = fs::read(&database).expect("read database before monitor access");
    let entries_before = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<BTreeSet<_>>();

    let jobs = ReadOnlyJobStore::open(&root)
        .expect("open monitor view")
        .list_jobs(None)
        .expect("read jobs");

    assert!(jobs.is_empty());
    assert_eq!(
        fs::read(&database).expect("read database after monitor access"),
        before
    );
    let entries_after = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(entries_after, entries_before);
    fs::remove_dir_all(&root).expect("remove temporary state");
}

#[test]
fn monitor_query_returns_only_pending_and_active_job_records() {
    let root = fresh_root();
    let storage = Storage::open(&root).expect("create controller database");
    let node = NodeId::new("mini01-a").unwrap();
    let spec = |snapshot| JobSpec {
        storage_namespace: None,
        queue: QueueName::new("mini01").unwrap(),
        node: Some(node.clone()),
        name: "fixture".into(),
        cwd: "/Users/Shared/macluster".into(),
        stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
        stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
        walltime_secs: None,
        env: BTreeMap::new(),
        mode: JobMode::Batch,
        snapshot: Some(snapshot),
    };
    let pending = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo pending").unwrap()),
        )
        .unwrap();
    let completed = storage
        .submit_once(
            RequestId(Id128::random()),
            spec(storage.stage_snapshot(b"echo complete").unwrap()),
        )
        .unwrap();
    storage.reserve_job(completed.id, node).unwrap();
    storage.mark_running(completed.id).unwrap();
    storage
        .finish_job(completed.id, JobState::Completed, Some(0), None)
        .unwrap();
    drop(storage);

    let monitor_jobs = ReadOnlyJobStore::open(&root)
        .unwrap()
        .list_monitor_jobs()
        .unwrap();

    assert_eq!(monitor_jobs.len(), 1);
    assert_eq!(monitor_jobs[0].id, pending.id);
    assert_eq!(monitor_jobs[0].state, JobState::Pending);
    fs::remove_dir_all(&root).unwrap();
}
