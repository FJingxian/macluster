//! Local administrative transitions, serialized with normal agent requests.
use super::*;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveOutcome {
    Archived,
    PreservedForeign,
    Absent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PendingArchive {
    namespace: String,
    archive: PathBuf,
}

/// The old owner remains fenced while its numbered execution directory moves
/// to durable history. No new controller is admitted until the move commits.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PendingHandoff {
    controller: ControllerEpoch,
    namespace: String,
    history: PathBuf,
    had_jobs: bool,
    retired_controllers: Vec<ControllerEpoch>,
}

/// Read the accepted controller under the same lock used by requests.
pub fn current_controller(state_dir: &Path) -> Result<Option<ControllerEpoch>, AgentError> {
    if !state_dir.exists() {
        return Ok(None);
    }
    let _lock = StateLock::acquire_existing(state_dir)?;
    Ok(read_store(state_dir)?.controller)
}

/// Read the explicitly claimed namespace; legacy agents may have no owner tag.
pub fn owner_namespace(state_dir: &Path) -> Result<Option<String>, AgentError> {
    if !state_dir.exists() {
        return Ok(None);
    }
    let _lock = StateLock::acquire_existing(state_dir)?;
    Ok(read_store(state_dir)?.owner_namespace)
}

// Old agents ignore newly added fields, but have always rejected a different
// non-null controller UUID. Keep this legacy-visible fence during transitions.
fn controller_sentinel() -> ControllerEpoch {
    ControllerEpoch {
        controller_uuid: macluster_protocol::identifiers::ControllerUuid(Id128::random()),
        epoch: u64::MAX,
    }
}

fn retire(store: &mut AgentStore, controller: ControllerEpoch) {
    if let Some(old) = store
        .retired_controllers
        .iter_mut()
        .find(|old| old.controller_uuid == controller.controller_uuid)
    {
        old.epoch = old.epoch.max(controller.epoch);
    } else {
        store.retired_controllers.push(controller);
    }
}

// A receipt may lag the main terminal record. Prefer the main record for that
// exact execution, while still discovering orphaned receipts after state loss.
pub(super) fn records(state: &Path, store: &AgentStore) -> Result<Vec<AgentRecord>, AgentError> {
    let mut records: Vec<_> = store
        .active
        .iter()
        .chain(store.tombstones.iter())
        .cloned()
        .collect();
    let jobs = state.join("jobs");
    if !jobs.exists() {
        return Ok(records);
    }
    for job in fs::read_dir(jobs)? {
        let job = job?;
        if !job.file_type()?.is_dir() {
            return Err(AgentError::State("invalid jobs directory entry".into()));
        }
        for entry in fs::read_dir(job.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("execution-") && name.ends_with(".json") {
                if !entry.file_type()?.is_file() {
                    return Err(AgentError::State("invalid execution receipt".into()));
                }
                let mut receipt: AgentRecord = serde_json::from_slice(&fs::read(entry.path())?)
                    .map_err(|e| AgentError::State(e.to_string()))?;
                if let Some(current) = records
                    .iter()
                    .find(|r| r.job_id == receipt.job_id && r.start_token == receipt.start_token)
                {
                    receipt.terminal_state = current.terminal_state;
                    receipt.log_sync_pending = current.log_sync_pending;
                }
                records.push(receipt);
            }
        }
    }
    Ok(records)
}

fn idle(records: &[AgentRecord], discard_terminal_sync: bool) -> Result<(), AgentError> {
    if records
        .iter()
        .any(|r| !r.terminal() || (r.log_sync_pending && !discard_terminal_sync))
    {
        return Err(AgentError::Busy);
    }
    Ok(())
}

fn publisher_lock(state: &Path) -> Result<File, AgentError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join("log-sync-lifecycle.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(AgentError::Busy);
    }
    Ok(file)
}

/// Explicitly hand an idle account-level agent to a controller/namespace.
/// A retired controller may return only with an epoch above its retired floor.
pub fn claim_idle(
    state_dir: &Path,
    controller: ControllerEpoch,
    namespace: &str,
) -> Result<(), AgentError> {
    if namespace.is_empty() {
        return Err(AgentError::State("empty namespace".into()));
    }
    let _lock = StateLock::acquire(state_dir)?;
    let mut store = read_store(state_dir)?;
    if store.pending_archive.is_some() {
        return Err(AgentError::State(
            "resume pending archive before claiming agent".into(),
        ));
    }
    if let Some(pending) = store.pending_handoff.clone() {
        let _publishers = publisher_lock(state_dir)?;
        return finish_handoff(state_dir, pending, controller, namespace);
    }
    let all = records(state_dir, &store)?;
    idle(&all, false)?;
    prove_job_directories(state_dir, &all)?;
    let _publishers = publisher_lock(state_dir)?;
    if store.controller != Some(controller) {
        if let Some(current) = store.controller {
            if current.controller_uuid == controller.controller_uuid
                && controller.epoch < current.epoch
            {
                return Err(AgentError::Fenced("claim epoch is stale".into()));
            }
        }
        if store.retired_controllers.iter().any(|old| {
            old.controller_uuid == controller.controller_uuid && controller.epoch <= old.epoch
        }) {
            return Err(AgentError::Fenced(
                "claim epoch does not exceed retired epoch".into(),
            ));
        }
    }
    let same_owner = store
        .controller
        .is_some_and(|current| current.controller_uuid == controller.controller_uuid)
        && store
            .owner_namespace
            .as_deref()
            .is_none_or(|owner| owner == namespace)
        && all.iter().all(|record| {
            record.controller.controller_uuid == controller.controller_uuid
                && record
                    .share_uuid
                    .as_deref()
                    .is_none_or(|owner| owner == namespace)
                && record
                    .spec
                    .storage_namespace
                    .is_none_or(|owner| owner.to_string() == namespace)
        });
    if same_owner && store.controller == Some(controller) && store.active.is_none() {
        if store.retired_controllers.iter().any(|old| {
            old.controller_uuid == controller.controller_uuid && controller.epoch <= old.epoch
        }) {
            return Err(AgentError::Fenced(
                "claim epoch does not exceed retired epoch".into(),
            ));
        }
        // Idempotent retries using the live controller's exact epoch must not
        // retire that same epoch; doing so would fence the controller which
        // issued the claim (notably during in-process address migration).
        return Ok(());
    }
    if !same_owner && (!all.is_empty() || state_dir.join("jobs").exists()) {
        let pending = prepare_handoff(state_dir, &store, &all, controller, namespace)?;
        store.pending_handoff = Some(pending.clone());
        store.controller = Some(controller_sentinel());
        store.log_sync_shutdown = Some(Id128::random());
        write_store(state_dir, &store)?;
        return finish_handoff(state_dir, pending, controller, namespace);
    }
    if let Some(previous) = store.controller
        && previous != controller
    {
        retire(&mut store, previous);
    }
    if let Some(active) = store.active.take() {
        store.tombstones.push(active);
    }
    store.controller = Some(controller);
    store.owner_namespace = Some(namespace.into());
    store.reset_fence = false;
    store.log_sync_shutdown = None;
    write_store(state_dir, &store)
}

fn prove_job_directories(state: &Path, all: &[AgentRecord]) -> Result<(), AgentError> {
    let jobs = state.join("jobs");
    if !jobs.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(jobs)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || !all
                .iter()
                .any(|record| entry.file_name().to_string_lossy() == record.job_id.to_string())
        {
            return Err(AgentError::State(
                "unidentified local job directory requires manual reconciliation".into(),
            ));
        }
    }
    Ok(())
}

fn prepare_handoff(
    state: &Path,
    store: &AgentStore,
    all: &[AgentRecord],
    controller: ControllerEpoch,
    namespace: &str,
) -> Result<PendingHandoff, AgentError> {
    let parent = state
        .parent()
        .ok_or_else(|| AgentError::State("agent state has no parent".into()))?;
    let mut name = state
        .file_name()
        .ok_or_else(|| AgentError::State("agent state has no directory name".into()))?
        .to_os_string();
    name.push("-history");
    let history_root = parent.join(name);
    fs::create_dir_all(&history_root)?;
    if !fs::symlink_metadata(&history_root)?.is_dir() {
        return Err(AgentError::State(
            "agent history is not a real directory".into(),
        ));
    }
    fs::set_permissions(&history_root, fs::Permissions::from_mode(0o700))?;
    let history = history_root.join(Id128::random().to_string());
    fs::create_dir(&history)?;
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700))?;
    let mut snapshot = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(history.join("agent-state.json"))?;
    snapshot.write_all(
        &serde_json::to_vec(store).map_err(|error| AgentError::State(error.to_string()))?,
    )?;
    snapshot.sync_all()?;
    if state.join("jobs").exists() {
        sync_job_tree(&state.join("jobs"))?;
    }
    File::open(&history)?.sync_all()?;
    File::open(&history_root)?.sync_all()?;
    File::open(parent)?.sync_all()?;
    let mut floors = AgentStore {
        retired_controllers: store.retired_controllers.clone(),
        ..AgentStore::default()
    };
    if let Some(old) = store.controller {
        retire(&mut floors, old);
    }
    for record in all {
        retire(&mut floors, record.controller);
    }
    Ok(PendingHandoff {
        controller,
        namespace: namespace.into(),
        history,
        had_jobs: state.join("jobs").exists(),
        retired_controllers: floors.retired_controllers,
    })
}

fn sync_job_tree(path: &Path) -> Result<(), AgentError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            sync_job_tree(&entry?.path())?;
        }
        File::open(path)?.sync_all()?;
    } else if metadata.is_file() {
        File::open(path)?.sync_all()?;
    }
    // A symlink or stale socket is preserved by the directory rename; never
    // follow it to touch a path outside the local execution directory.
    Ok(())
}

fn finish_handoff(
    state: &Path,
    pending: PendingHandoff,
    controller: ControllerEpoch,
    namespace: &str,
) -> Result<(), AgentError> {
    if controller.controller_uuid != pending.controller.controller_uuid
        || controller.epoch < pending.controller.epoch
        || namespace != pending.namespace
    {
        return Err(AgentError::Fenced("resume the pending handoff with its target namespace/controller and an equal or higher epoch".into()));
    }
    if !fs::symlink_metadata(&pending.history)?.is_dir()
        || !pending.history.join("agent-state.json").is_file()
    {
        return Err(AgentError::State(
            "pending handoff history is missing".into(),
        ));
    }
    let source = state.join("jobs");
    let target = pending.history.join("jobs");
    if pending.had_jobs {
        match (source.exists(), target.exists()) {
            (true, false) => fs::rename(&source, &target)?,
            (false, true) => {}
            _ => {
                return Err(AgentError::State(
                    "pending handoff job directories require reconciliation".into(),
                ));
            }
        }
        // Persist both sides of the rename before admitting a new job number.
        File::open(&pending.history)?.sync_all()?;
        File::open(state)?.sync_all()?;
    } else if source.exists() || target.exists() {
        return Err(AgentError::State(
            "job directories changed during pending handoff".into(),
        ));
    }
    let store = AgentStore {
        controller: Some(controller),
        owner_namespace: Some(namespace.into()),
        retired_controllers: pending.retired_controllers,
        ..AgentStore::default()
    };
    write_store(state, &store)
}

fn owns(record: &AgentRecord, namespace: &str) -> bool {
    let mut known = false;
    if let Some(share) = &record.share_uuid {
        known = true;
        if share != namespace {
            return false;
        }
    }
    if let Some(share) = record.spec.storage_namespace {
        known = true;
        if share.to_string() != namespace {
            return false;
        }
    }
    known
}

fn copy_tree(source: &Path, target: &Path) -> Result<(), AgentError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(AgentError::State("symlink in agent archive".into()));
    }
    if metadata.is_dir() {
        fs::create_dir(target)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        }
        File::open(target)?.sync_all()?;
    } else if metadata.is_file() {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)?;
        io::copy(&mut File::open(source)?, &mut output)?;
        output.sync_all()?;
    } else {
        return Err(AgentError::State(
            "unsupported entry in agent archive".into(),
        ));
    }
    Ok(())
}

/// Archive only proven namespace-owned idle state. The directory and lock
/// inodes remain stable; durable retired epochs fence delayed protocol calls.
pub fn archive_idle_namespace(
    state_dir: &Path,
    archive: &Path,
    namespace: &str,
    discard_terminal_sync: bool,
) -> Result<ArchiveOutcome, AgentError> {
    if !state_dir.exists() {
        return Ok(ArchiveOutcome::Absent);
    }
    let _lock = StateLock::acquire_existing(state_dir)?;
    let mut store = read_store(state_dir)?;
    if store.pending_handoff.is_some() {
        return Err(AgentError::Busy);
    }
    if let Some(pending) = &store.pending_archive {
        if pending.namespace != namespace || pending.archive != archive {
            return Ok(ArchiveOutcome::PreservedForeign);
        }
        if !archive.is_dir() {
            return Err(AgentError::State("pending archive is missing".into()));
        }
        let _publishers = publisher_lock(state_dir)?;
        cleanup(state_dir)?;
        store.pending_archive = None;
        write_store(state_dir, &store)?;
        return Ok(ArchiveOutcome::Archived);
    }
    let all = records(state_dir, &store)?;
    let jobs_present = state_dir.join("jobs").exists();
    if store.reset_fence
        && store.controller.is_some()
        && store.owner_namespace.is_none()
        && all.is_empty()
        && !jobs_present
    {
        return Ok(ArchiveOutcome::Absent);
    }
    if !namespace_owned(state_dir, &store, namespace)? {
        return Ok(ArchiveOutcome::PreservedForeign);
    }
    idle(&all, discard_terminal_sync)?;
    let _publishers = publisher_lock(state_dir)?;
    if archive.starts_with(state_dir) {
        return Err(AgentError::State(
            "archive must be outside agent state".into(),
        ));
    }
    if archive.exists() && !same_tree(state_dir, archive)? {
        return Err(AgentError::State(
            "agent archive already exists with different data".into(),
        ));
    }
    let parent = archive
        .parent()
        .ok_or_else(|| AgentError::State("archive has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".agent-archive-{}", Id128::random()));
    let result = (|| {
        if !archive.exists() {
            copy_tree(state_dir, &staging)?;
            fs::rename(&staging, archive)?;
            File::open(parent)?.sync_all()?;
        }
        let mut fenced = AgentStore {
            controller: Some(controller_sentinel()),
            reset_fence: true,
            retired_controllers: store.retired_controllers.clone(),
            pending_archive: Some(PendingArchive {
                namespace: namespace.into(),
                archive: archive.into(),
            }),
            ..AgentStore::default()
        };
        if let Some(current) = store.controller {
            retire(&mut fenced, current);
        }
        for record in &all {
            retire(&mut fenced, record.controller);
        }
        // Commit fencing before removing any source data. A failed cleanup
        // leaves duplicate archived data, never an unfenced owner or data loss.
        write_store(state_dir, &fenced)?;
        cleanup(state_dir)?;
        fenced.pending_archive = None;
        write_store(state_dir, &fenced)?;
        Ok(ArchiveOutcome::Archived)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Caller must hold StateLock throughout the ownership check and transition.
pub(super) fn namespace_owned(
    state_dir: &Path,
    store: &AgentStore,
    namespace: &str,
) -> Result<bool, AgentError> {
    let all = records(state_dir, store)?;
    if store
        .owner_namespace
        .as_deref()
        .is_some_and(|owner| owner != namespace)
        || all.iter().any(|record| !owns(record, namespace))
        || (store.owner_namespace.is_none() && all.is_empty())
    {
        return Ok(false);
    }
    // Every job directory must have an identified execution; otherwise its
    // provenance cannot safely be inferred from neighboring jobs.
    if state_dir.join("jobs").exists() {
        for entry in fs::read_dir(state_dir.join("jobs"))? {
            let entry = entry?;
            if !all
                .iter()
                .any(|r| entry.file_name().to_string_lossy() == r.job_id.to_string())
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn cleanup(state: &Path) -> Result<(), AgentError> {
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "agent-state.json" || name.to_string_lossy().ends_with(".lock") {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    File::open(state)?.sync_all()?;
    Ok(())
}

fn same_tree(left: &Path, right: &Path) -> Result<bool, AgentError> {
    let a = fs::symlink_metadata(left)?;
    let b = fs::symlink_metadata(right)?;
    if a.file_type().is_symlink() || b.file_type().is_symlink() {
        return Ok(false);
    }
    if a.is_file() && b.is_file() {
        return Ok(fs::read(left)? == fs::read(right)?);
    }
    if !a.is_dir() || !b.is_dir() {
        return Ok(false);
    }
    let mut names = fs::read_dir(left)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut other = fs::read_dir(right)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    other.sort();
    if names != other {
        return Ok(false);
    }
    for name in names {
        if !same_tree(&left.join(&name), &right.join(&name))? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use macluster_protocol::identifiers::ControllerUuid;
    use std::os::unix::fs::MetadataExt;
    const NS: &str = "00000000-0000-4000-8000-000000000001";

    fn controller(epoch: u64) -> ControllerEpoch {
        ControllerEpoch {
            controller_uuid: ControllerUuid(Id128::random()),
            epoch,
        }
    }
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("macluster-admin-{}", Id128::random()))
    }
    fn fixture(terminal: bool, pending: bool) -> (PathBuf, PathBuf) {
        let (root, state, _, _) = crate::tests::status_fixture(
            "admin",
            "boot",
            terminal.then_some(JobState::Completed),
            pending,
        );
        let mut store = read_store(&state).unwrap();
        store.active.as_mut().unwrap().share_uuid = Some(NS.into());
        write_store(&state, &store).unwrap();
        (root, state)
    }

    #[test]
    fn explicit_idle_handoff_fences_retired_controller_and_allows_higher_return_epoch() {
        let root = root();
        let state = root.join("agent");
        let a = controller(7);
        let b = controller(1);
        fence(a, &state).unwrap();
        claim_idle(&state, b, NS).unwrap();
        assert!(fence(a, &state).is_err());
        assert!(claim_idle(&state, a, NS).is_err());
        let newer_a = ControllerEpoch { epoch: 8, ..a };
        claim_idle(&state, newer_a, NS).unwrap();
        claim_idle(&state, newer_a, NS).unwrap();
        assert_eq!(read_store(&state).unwrap().controller, Some(newer_a));
        assert!(fence(b, &state).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_or_pending_records_block_claim_without_changing_store() {
        for (terminal, pending) in [(false, false), (true, true)] {
            let (root, state) = fixture(terminal, pending);
            let before = fs::read(state.join("agent-state.json")).unwrap();
            assert!(matches!(
                claim_idle(&state, controller(1), NS),
                Err(AgentError::Busy)
            ));
            assert_eq!(fs::read(state.join("agent-state.json")).unwrap(), before);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn same_owner_claim_preserves_receipts_and_moves_terminal_active_to_tombstones() {
        let (root, state) = fixture(true, false);
        let original = read_store(&state).unwrap().active.unwrap();
        claim_idle(&state, original.controller, NS).unwrap();
        let store = read_store(&state).unwrap();
        assert!(store.active.is_none());
        assert_eq!(store.tombstones.len(), 1);
        assert!(execution_receipt_path(&state, original.job_id, original.start_token).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_same_owner_claim_is_idempotent_and_does_not_fence_live_epoch() {
        let root = root();
        let state = root.join("agent");
        let active = controller(7);
        fence(active, &state).unwrap();
        let before = fs::read(state.join("agent-state.json")).unwrap();
        claim_idle(&state, active, NS).unwrap();
        assert_eq!(fs::read(state.join("agent-state.json")).unwrap(), before);
        assert!(fence(active, &state).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn foreign_unknown_and_mixed_namespaces_are_preserved() {
        for mode in [0, 1, 2] {
            let (root, state) = fixture(true, false);
            let mut store = read_store(&state).unwrap();
            if mode == 0 {
                store.active.as_mut().unwrap().share_uuid = Some("foreign".into());
            }
            if mode == 1 {
                store.active.as_mut().unwrap().share_uuid = None;
            }
            if mode == 2 {
                let mut foreign = store.active.clone().unwrap();
                foreign.share_uuid = Some("foreign".into());
                store.tombstones.push(foreign);
            }
            write_store(&state, &store).unwrap();
            let before = fs::read(state.join("agent-state.json")).unwrap();
            assert_eq!(
                archive_idle_namespace(&state, &root.join("archive"), NS, true).unwrap(),
                ArchiveOutcome::PreservedForeign
            );
            assert_eq!(fs::read(state.join("agent-state.json")).unwrap(), before);
            assert!(!root.join("archive").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn archive_retains_lock_inode_and_fences_delayed_requests_and_stale_claims() {
        let (root, state) = fixture(true, false);
        let old = read_store(&state).unwrap().controller.unwrap();
        {
            let _lock = StateLock::acquire(&state).unwrap();
        }
        let inode = fs::metadata(state.join("agent.lock")).unwrap().ino();
        let archive = root.join("archive");
        assert_eq!(
            archive_idle_namespace(&state, &archive, NS, false).unwrap(),
            ArchiveOutcome::Archived
        );
        assert_eq!(fs::metadata(state.join("agent.lock")).unwrap().ino(), inode);
        assert!(archive.join("jobs/1/stdout.log").exists());
        assert!(!state.join("jobs").exists());
        assert!(fence(old, &state).is_err());
        assert!(fence(controller(1), &state).is_err());
        assert!(claim_idle(&state, old, NS).is_err());
        assert_eq!(
            archive_idle_namespace(&state, &archive, NS, false).unwrap(),
            ArchiveOutcome::Absent
        );
        claim_idle(
            &state,
            ControllerEpoch {
                epoch: old.epoch + 1,
                ..old
            },
            NS,
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_refuses_live_and_requires_explicit_pending_log_discard() {
        for (terminal, pending) in [(false, false), (true, true)] {
            let (root, state) = fixture(terminal, pending);
            assert!(matches!(
                archive_idle_namespace(&state, &root.join("archive"), NS, false),
                Err(AgentError::Busy)
            ));
            if terminal {
                assert_eq!(
                    archive_idle_namespace(&state, &root.join("archive"), NS, true).unwrap(),
                    ArchiveOutcome::Archived
                );
                let snapshot = read_store(&root.join("archive")).unwrap();
                assert!(snapshot.active.unwrap().log_sync_pending);
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn reset_resumes_after_fencing_before_cleanup() {
        let (root, state) = fixture(true, false);
        let archive = root.join("archive");
        copy_tree(&state, &archive).unwrap();
        let old = read_store(&state).unwrap().controller.unwrap();
        let mut fenced = AgentStore {
            controller: Some(controller_sentinel()),
            reset_fence: true,
            pending_archive: Some(PendingArchive {
                namespace: NS.into(),
                archive: archive.clone(),
            }),
            ..AgentStore::default()
        };
        retire(&mut fenced, old);
        write_store(&state, &fenced).unwrap();
        assert!(claim_idle(&state, controller(1), NS).is_err());
        assert!(fence(controller(1), &state).is_err());
        assert_eq!(
            archive_idle_namespace(&state, &archive, NS, true).unwrap(),
            ArchiveOutcome::Archived
        );
        assert!(!state.join("jobs").exists());
        assert!(read_store(&state).unwrap().pending_archive.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn quiesce_preserves_foreign_unknown_and_mixed_state_without_barrier() {
        for mode in [0, 1, 2] {
            let (root, state) = fixture(true, true);
            let mut store = read_store(&state).unwrap();
            if mode == 0 {
                store.owner_namespace = Some("foreign".into());
            }
            if mode == 1 {
                store.active.as_mut().unwrap().share_uuid = None;
            }
            if mode == 2 {
                let mut foreign = store.active.clone().unwrap();
                foreign.share_uuid = Some("foreign".into());
                store.tombstones.push(foreign);
            }
            write_store(&state, &store).unwrap();
            let before = fs::read(state.join("agent-state.json")).unwrap();
            crate::log_sync::quiesce(
                &state,
                Id128::parse(NS).unwrap(),
                Id128::random(),
                std::time::Duration::from_millis(10),
            )
            .unwrap();
            assert_eq!(fs::read(state.join("agent-state.json")).unwrap(), before);
            assert!(read_store(&state).unwrap().log_sync_shutdown.is_none());
            fs::remove_dir_all(root).unwrap();
        }
    }
    fn histories(state: &Path) -> Vec<PathBuf> {
        let mut name = state.file_name().unwrap().to_os_string();
        name.push("-history");
        fs::read_dir(state.parent().unwrap().join(name))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    #[test]
    fn different_owner_job_number_reuse_preserves_raw_logs_and_never_recovers_old_receipts() {
        let (root, state) = fixture(true, false);
        let original = read_store(&state).unwrap().active.unwrap();
        let old_inode = fs::metadata(state.join("jobs/1/stdout.log")).unwrap().ino();
        let b = controller(1);
        claim_idle(&state, b, "namespace-b").unwrap();
        let history_a = histories(&state).pop().unwrap();
        assert_eq!(
            fs::metadata(history_a.join("jobs/1/stdout.log"))
                .unwrap()
                .ino(),
            old_inode
        );
        assert_eq!(
            fs::read(history_a.join("jobs/1/stdout.log")).unwrap(),
            b"saved stdout\n"
        );
        assert!(read_store(&state).unwrap().active.is_none());
        assert!(read_store(&state).unwrap().tombstones.is_empty());
        assert!(
            read_execution_receipt(&state, 1, original.start_token)
                .unwrap()
                .is_none()
        );
        fs::create_dir_all(state.join("jobs/1")).unwrap();
        fs::write(state.join("jobs/1/stdout.log"), b"B output").unwrap();
        let mut record_b = original.clone();
        record_b.controller = b;
        record_b.share_uuid = Some("namespace-b".into());
        record_b.start_token = StartToken(Id128::random());
        let mut live = read_store(&state).unwrap();
        live.active = Some(record_b);
        write_store(&state, &live).unwrap();
        let returning_a = ControllerEpoch {
            epoch: original.controller.epoch + 1,
            ..original.controller
        };
        claim_idle(&state, returning_a, NS).unwrap();
        assert_eq!(histories(&state).len(), 2);
        assert_eq!(
            fs::read(history_a.join("jobs/1/stdout.log")).unwrap(),
            b"saved stdout\n"
        );
        let history_b = histories(&state)
            .into_iter()
            .find(|path| *path != history_a)
            .unwrap();
        assert_eq!(
            fs::read(history_b.join("jobs/1/stdout.log")).unwrap(),
            b"B output"
        );
        let config = crate::tests::status_config(Path::new(&original.shared_root));
        assert!(matches!(
            recover_job(
                returning_a,
                original.start_token,
                1,
                &config,
                &state,
                &original.node_id
            ),
            Err(ProtocolError::NotFound)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn namespace_change_archives_even_when_controller_uuid_matches() {
        let (root, state) = fixture(true, false);
        let original = read_store(&state).unwrap().active.unwrap();
        claim_idle(&state, original.controller, "namespace-b").unwrap();
        assert!(!state.join("jobs").exists());
        assert_eq!(histories(&state).len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_handoff_resumes_before_and_after_jobs_rename_and_blocks_other_requests() {
        for renamed in [false, true] {
            let (root, state) = fixture(true, false);
            let mut old = read_store(&state).unwrap();
            let b = controller(1);
            let all = records(&state, &old).unwrap();
            let pending = prepare_handoff(&state, &old, &all, b, NS).unwrap();
            old.pending_handoff = Some(pending.clone());
            old.controller = Some(controller_sentinel());
            old.log_sync_shutdown = Some(Id128::random());
            write_store(&state, &old).unwrap();
            if renamed {
                fs::rename(state.join("jobs"), pending.history.join("jobs")).unwrap();
            }
            assert!(fence(b, &state).is_err());
            assert!(claim_idle(&state, controller(1), NS).is_err());
            assert!(matches!(
                archive_idle_namespace(&state, &root.join("reset"), NS, true),
                Err(AgentError::Busy)
            ));
            claim_idle(&state, ControllerEpoch { epoch: 2, ..b }, NS).unwrap();
            assert!(read_store(&state).unwrap().pending_handoff.is_none());
            assert!(read_store(&state).unwrap().tombstones.is_empty());
            assert!(!state.join("jobs").exists());
            assert_eq!(
                fs::read(pending.history.join("jobs/1/stdout.log")).unwrap(),
                b"saved stdout\n"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn unidentified_job_directory_and_pending_tombstone_block_handoff_unchanged() {
        for unknown in [true, false] {
            let (root, state) = fixture(true, false);
            if unknown {
                fs::create_dir_all(state.join("jobs/999")).unwrap();
            } else {
                let mut store = read_store(&state).unwrap();
                let mut old = store.active.take().unwrap();
                old.log_sync_pending = true;
                store.tombstones.push(old);
                write_store(&state, &store).unwrap();
            }
            let before = fs::read(state.join("agent-state.json")).unwrap();
            assert!(claim_idle(&state, controller(1), NS).is_err());
            assert_eq!(fs::read(state.join("agent-state.json")).unwrap(), before);
            assert!(state.join("jobs/1/stdout.log").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn reset_fence_is_visible_to_legacy_agents_which_ignore_retirement_fields() {
        #[derive(Deserialize)]
        struct LegacyStore {
            controller: Option<ControllerEpoch>,
        }
        let (root, state) = fixture(true, false);
        let a = read_store(&state).unwrap().controller.unwrap();
        let b = controller(4);
        let archive = root.join("archive");
        archive_idle_namespace(&state, &archive, NS, false).unwrap();
        let bytes = fs::read(state.join("agent-state.json")).unwrap();
        let legacy: LegacyStore = serde_json::from_slice(&bytes).unwrap();
        let sentinel = legacy
            .controller
            .expect("legacy agents must observe a non-null controller");
        assert_ne!(sentinel.controller_uuid, a.controller_uuid);
        assert_ne!(sentinel.controller_uuid, b.controller_uuid);
        // This is the original admission rule, which knows no retired fields.
        for delayed in [
            a,
            b,
            ControllerEpoch {
                epoch: u64::MAX,
                ..a
            },
        ] {
            assert_ne!(sentinel.controller_uuid, delayed.controller_uuid);
            assert!(fence(delayed, &state).is_err());
        }
        assert_eq!(
            archive_idle_namespace(&state, &archive, NS, false).unwrap(),
            ArchiveOutcome::Absent
        );
        let returning_a = ControllerEpoch {
            epoch: a.epoch + 1,
            ..a
        };
        claim_idle(&state, returning_a, NS).unwrap();
        assert_eq!(current_controller(&state).unwrap(), Some(returning_a));
        assert!(!read_store(&state).unwrap().reset_fence);
        fs::remove_dir_all(root).unwrap();
    }
}
