//! Durable, ticket-bound controller maintenance sessions.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use macluster_core::config::ClusterConfig;
use macluster_protocol::{
    control::{MaintenancePhase, MaintenanceScope, MaintenanceStatus, MaintenanceTicket},
    framing::sha256_hex,
    identifiers::{Id128, NodeId},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SESSION_VERSION: u32 = 1;
const GENERATION_VERSION: u32 = 1;
const MAX_BLOCKERS: usize = 32;
const MAX_BLOCKER_CHARS: usize = 256;

/// Ensure a scoped ticket covers every scheduler-visible change. Storage and
/// cluster identity changes are cluster-wide; queue membership changes drain
/// every pre-existing member of the affected queue.
pub fn validate_scope_config_change(
    old: &ClusterConfig,
    next: &ClusterConfig,
    scope: &MaintenanceScope,
) -> Result<(), String> {
    if old.share_uuid != next.share_uuid {
        return Err(
            "controller storage namespace cannot change in-place; use `macluster init` to create a new cluster"
                .into(),
        );
    }
    if old.login_node != next.login_node {
        return Err(
            "login-node ownership cannot change in-place; use `macluster init` to configure the new login node"
                .into(),
        );
    }
    if matches!(scope, MaintenanceScope::Cluster) {
        return Ok(());
    }
    let MaintenanceScope::Nodes(nodes) = scope else {
        unreachable!()
    };
    let covered = nodes.iter().map(NodeId::as_str).collect::<BTreeSet<_>>();
    if old.name != next.name
        || old.default_queue != next.default_queue
        || old.shared_root != next.shared_root
        || old.storage_source_root != next.storage_source_root
        || old.storage_server != next.storage_server
        || old.protocol_version != next.protocol_version
        || old.shares != next.shares
    {
        return Err(
            "cluster identity or shared storage changed outside a cluster-wide maintenance scope"
                .into(),
        );
    }

    let queue_names = old
        .queues
        .keys()
        .chain(next.queues.keys())
        .collect::<BTreeSet<_>>();
    let mut touched_queues = BTreeSet::new();
    for name in queue_names {
        let before = old.queues.get(name);
        let after = next.queues.get(name);
        if before == after {
            continue;
        }
        touched_queues.insert(name.as_str());
        let (Some(before), Some(after)) = (before, after) else {
            return Err(format!(
                "queue '{name}' was created or removed outside a cluster-wide maintenance scope"
            ));
        };
        if before.scheduler != after.scheduler {
            for member in before.nodes.iter().chain(&after.nodes) {
                if old.nodes.contains_key(member) && !covered.contains(member.as_str()) {
                    return Err(format!(
                        "queue '{name}' scheduler changed but existing member '{member}' is outside the maintenance scope"
                    ));
                }
            }
        }
        let before_members = before.nodes.iter().collect::<BTreeSet<_>>();
        let after_members = after.nodes.iter().collect::<BTreeSet<_>>();
        for removed in before_members.difference(&after_members) {
            if !covered.contains(removed.as_str()) {
                return Err(format!(
                    "node '{removed}' was removed from queue '{name}' outside the maintenance scope"
                ));
            }
        }
        for added in after_members.difference(&before_members) {
            if old.nodes.contains_key(added.as_str()) && !covered.contains(added.as_str()) {
                return Err(format!(
                    "node '{added}' was added to queue '{name}' outside the maintenance scope"
                ));
            }
        }
    }

    for id in old.nodes.keys() {
        match next.nodes.get(id) {
            Some(next_node) if old.nodes.get(id) == Some(next_node) => {}
            Some(_) | None if !covered.contains(id.as_str()) => {
                return Err(format!("node '{id}' changed outside the maintenance scope"));
            }
            _ => {}
        }
    }
    let added = next.nodes.keys().filter(|id| !old.nodes.contains_key(*id));
    for id in added {
        let is_queue_member = next
            .queues
            .values()
            .any(|queue| queue.nodes.iter().any(|member| member == id));
        if !is_queue_member || touched_queues.is_empty() {
            return Err(format!(
                "new node '{id}' is not covered by a changed queue in this maintenance scope"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum MaintenanceError {
    #[error("maintenance storage error: {0}")]
    Io(#[from] io::Error),
    #[error("maintenance journal is invalid: {0}")]
    Invalid(String),
    #[error("maintenance is already active for operation {0}")]
    Busy(Id128),
    #[error("maintenance ticket is stale or belongs to another operation")]
    StaleTicket,
    #[error("maintenance preflight journal changed before the ticket was issued")]
    JournalChanged,
    #[error("maintenance can complete only after all blockers drain")]
    NotDrained,
    #[error("candidate config or admin journal digest does not match the on-disk file")]
    CandidateChanged,
    #[error("maintenance cannot be aborted after config application has started")]
    Applying,
    #[error("maintenance scope contains unknown node '{0}'")]
    UnknownNode(NodeId),
    #[error("maintenance scope contains duplicate node IDs")]
    DuplicateNode,
    #[error("maintenance node scope cannot be empty")]
    EmptyScope,
    #[error("service metadata belongs to a different controller binding")]
    WrongBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GenerationRecord {
    version: u32,
    binding_digest: String,
    generation: u64,
    config_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SessionRecord {
    version: u32,
    binding_digest: String,
    ticket: MaintenanceTicket,
    scope: MaintenanceScope,
    phase: MaintenancePhase,
    preflight_journal_digest: String,
    candidate_config_digest: Option<String>,
    candidate_journal_digest: Option<String>,
    blockers: Vec<String>,
}

/// Persists the active maintenance ticket and the controller config generation.
/// The controller runtime owns this object and serializes all mutations on its
/// main thread. The private files remain after process death for recovery.
pub struct MaintenanceCoordinator {
    state_dir: PathBuf,
    binding_digest: String,
    generation_record: GenerationRecord,
    session: Option<SessionRecord>,
    startup_config_mismatch: bool,
}

impl MaintenanceCoordinator {
    pub fn open(
        state_dir: &Path,
        binding_digest: &str,
        current_config_digest: &str,
    ) -> Result<Self, MaintenanceError> {
        fs::create_dir_all(state_dir)?;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))?;
        let state_dir = fs::canonicalize(state_dir)?;
        let generation_path = state_dir.join("controller-generation.json");
        let generation_record = match read_json::<GenerationRecord>(&generation_path)? {
            Some(record) => {
                if record.version != GENERATION_VERSION {
                    return Err(MaintenanceError::Invalid(format!(
                        "unsupported generation metadata version {}",
                        record.version
                    )));
                }
                if record.binding_digest != binding_digest {
                    return Err(MaintenanceError::WrongBinding);
                }
                record
            }
            None => {
                let record = GenerationRecord {
                    version: GENERATION_VERSION,
                    binding_digest: binding_digest.to_owned(),
                    generation: 0,
                    config_digest: current_config_digest.to_owned(),
                };
                write_json_atomic(&generation_path, &record)?;
                record
            }
        };
        let session = read_json::<SessionRecord>(&state_dir.join("maintenance-session.json"))?;
        if session.as_ref().is_some_and(|record| {
            record.version != SESSION_VERSION || record.binding_digest != binding_digest
        }) {
            return Err(MaintenanceError::WrongBinding);
        }
        let mut coordinator = Self {
            state_dir,
            binding_digest: binding_digest.to_owned(),
            generation_record,
            session,
            startup_config_mismatch: false,
        };
        if let Some(record) = coordinator.session.clone()
            && record.phase == MaintenancePhase::Applying
            && record.candidate_config_digest.as_deref() == Some(current_config_digest)
            && record.candidate_journal_digest.as_deref()
                == Some(coordinator.digest_node_admin_journal()?.as_str())
        {
            coordinator.commit_complete(&record.ticket)?;
        }
        coordinator.startup_config_mismatch =
            !coordinator.config_digest_matches(current_config_digest);
        Ok(coordinator)
    }

    pub fn generation(&self) -> u64 {
        self.generation_record.generation
    }

    pub fn config_digest(&self) -> &str {
        &self.generation_record.config_digest
    }

    pub fn config_digest_matches(&self, digest: &str) -> bool {
        self.generation_record.config_digest == digest
    }

    pub fn startup_config_mismatch(&self) -> bool {
        self.startup_config_mismatch
    }

    pub fn scope(&self) -> Option<MaintenanceScope> {
        self.session.as_ref().map(|record| record.scope.clone())
    }

    pub fn inspect(&self) -> Option<MaintenanceStatus> {
        self.session.as_ref().map(|record| MaintenanceStatus {
            ticket: record.ticket.clone(),
            scope: record.scope.clone(),
            phase: if record.phase == MaintenancePhase::Applying {
                MaintenancePhase::RecoveryRequired
            } else {
                record.phase
            },
            blockers: record.blockers.clone(),
        })
    }

    pub fn begin(
        &mut self,
        operation_id: Id128,
        mut scope: MaintenanceScope,
        journal_digest: &str,
        configured_nodes: &BTreeSet<NodeId>,
    ) -> Result<MaintenanceTicket, MaintenanceError> {
        canonicalize_scope(&mut scope, configured_nodes)?;
        if let Some(active) = &self.session {
            if active.ticket.operation_id == operation_id && active.scope == scope {
                return Ok(active.ticket.clone());
            }
            return Err(MaintenanceError::Busy(active.ticket.operation_id));
        }
        let actual_journal = self.digest_node_admin_journal()?;
        if actual_journal != journal_digest {
            return Err(MaintenanceError::JournalChanged);
        }
        let ticket = MaintenanceTicket {
            operation_id,
            token: Id128::random(),
            generation: self.generation_record.generation,
        };
        let record = SessionRecord {
            version: SESSION_VERSION,
            binding_digest: self.binding_digest.clone(),
            ticket: ticket.clone(),
            scope,
            phase: MaintenancePhase::Draining,
            preflight_journal_digest: journal_digest.to_owned(),
            candidate_config_digest: None,
            candidate_journal_digest: None,
            blockers: Vec::new(),
        };
        self.persist_session(&record)?;
        self.session = Some(record);
        Ok(ticket)
    }

    /// Update the persisted phase from a runtime drain snapshot. Blocker text
    /// is bounded so diagnostics can never grow the local IPC frame without
    /// limit.
    pub fn update_blockers(
        &mut self,
        ticket: &MaintenanceTicket,
        blockers: Vec<String>,
    ) -> Result<bool, MaintenanceError> {
        let record = self.ticketed_session_mut(ticket)?;
        let applying = record.phase == MaintenancePhase::Applying;
        let blockers = blockers
            .into_iter()
            .take(MAX_BLOCKERS)
            .map(|blocker| blocker.chars().take(MAX_BLOCKER_CHARS).collect())
            .collect::<Vec<_>>();
        let phase = if applying {
            MaintenancePhase::Applying
        } else if blockers.is_empty() {
            MaintenancePhase::Ready
        } else {
            MaintenancePhase::Draining
        };
        if record.phase == phase && record.blockers == blockers {
            return Ok(phase == MaintenancePhase::Ready);
        }
        record.phase = phase;
        record.blockers = blockers;
        let ready = record.phase == MaintenancePhase::Ready;
        let clone = record.clone();
        self.persist_session(&clone)?;
        Ok(ready)
    }

    pub fn mark_ready(
        &mut self,
        ticket: &MaintenanceTicket,
        blockers: Vec<String>,
    ) -> Result<bool, MaintenanceError> {
        self.update_blockers(ticket, blockers)
    }

    pub fn prepare_complete(
        &mut self,
        ticket: &MaintenanceTicket,
        candidate_config_digest: &str,
        actual_config_digest: &str,
        candidate_journal_digest: &str,
        actual_journal_digest: &str,
    ) -> Result<(), MaintenanceError> {
        let record = self.ticketed_session_mut(ticket)?;
        if candidate_config_digest != actual_config_digest
            || candidate_journal_digest != actual_journal_digest
        {
            return Err(MaintenanceError::CandidateChanged);
        }
        if record.phase == MaintenancePhase::Applying {
            if record.candidate_config_digest.as_deref() == Some(candidate_config_digest)
                && record.candidate_journal_digest.as_deref() == Some(candidate_journal_digest)
            {
                return Ok(());
            }
            return Err(MaintenanceError::StaleTicket);
        }
        if record.phase != MaintenancePhase::Ready {
            return Err(MaintenanceError::NotDrained);
        }
        record.phase = MaintenancePhase::Applying;
        record.candidate_config_digest = Some(candidate_config_digest.to_owned());
        record.candidate_journal_digest = Some(candidate_journal_digest.to_owned());
        let clone = record.clone();
        self.persist_session(&clone)?;
        Ok(())
    }

    pub fn commit_complete(&mut self, ticket: &MaintenanceTicket) -> Result<(), MaintenanceError> {
        let record = self.ticketed_session(ticket)?.clone();
        if record.phase != MaintenancePhase::Applying {
            return Err(MaintenanceError::NotDrained);
        }
        let candidate_digest = record.candidate_config_digest.as_deref().ok_or_else(|| {
            MaintenanceError::Invalid("applying ticket has no candidate digest".into())
        })?;
        if self.generation_record.generation == ticket.generation
            && self.generation_record.config_digest == candidate_digest
        {
            // A maintenance operation may only change external node state
            // (for example, aborting an incomplete share). Keep the same
            // generation when the active config bytes did not change.
        } else if self.generation_record.generation == ticket.generation {
            self.generation_record = GenerationRecord {
                version: GENERATION_VERSION,
                binding_digest: self.binding_digest.clone(),
                generation: ticket.generation.saturating_add(1),
                config_digest: candidate_digest.to_owned(),
            };
            write_json_atomic(
                &self.state_dir.join("controller-generation.json"),
                &self.generation_record,
            )?;
        } else if self.generation_record.generation != ticket.generation.saturating_add(1)
            || self.generation_record.config_digest != candidate_digest
        {
            return Err(MaintenanceError::StaleTicket);
        }
        self.remove_session_file()?;
        self.session = None;
        self.startup_config_mismatch = false;
        Ok(())
    }

    pub fn abort(&mut self, ticket: &MaintenanceTicket) -> Result<(), MaintenanceError> {
        let record = self.ticketed_session(ticket)?;
        if record.phase == MaintenancePhase::Applying {
            return Err(MaintenanceError::Applying);
        }
        self.remove_session_file()?;
        self.session = None;
        Ok(())
    }

    fn ticketed_session(
        &self,
        ticket: &MaintenanceTicket,
    ) -> Result<&SessionRecord, MaintenanceError> {
        let record = self.session.as_ref().ok_or(MaintenanceError::StaleTicket)?;
        if record.ticket != *ticket || record.binding_digest != self.binding_digest {
            return Err(MaintenanceError::StaleTicket);
        }
        Ok(record)
    }

    fn ticketed_session_mut(
        &mut self,
        ticket: &MaintenanceTicket,
    ) -> Result<&mut SessionRecord, MaintenanceError> {
        let record = self.session.as_mut().ok_or(MaintenanceError::StaleTicket)?;
        if record.ticket != *ticket || record.binding_digest != self.binding_digest {
            return Err(MaintenanceError::StaleTicket);
        }
        Ok(record)
    }

    fn digest_node_admin_journal(&self) -> Result<String, MaintenanceError> {
        let path = self.state_dir.join("node-admin.json");
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(sha256_hex(&bytes).map_err(|error| MaintenanceError::Invalid(error.to_string()))?)
    }

    pub fn node_admin_journal_digest(&self) -> Result<String, MaintenanceError> {
        self.digest_node_admin_journal()
    }

    fn persist_session(&self, record: &SessionRecord) -> Result<(), MaintenanceError> {
        write_json_atomic(&self.state_dir.join("maintenance-session.json"), record)?;
        Ok(())
    }

    fn remove_session_file(&self) -> Result<(), MaintenanceError> {
        let path = self.state_dir.join("maintenance-session.json");
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn canonicalize_scope(
    scope: &mut MaintenanceScope,
    configured_nodes: &BTreeSet<NodeId>,
) -> Result<(), MaintenanceError> {
    let MaintenanceScope::Nodes(nodes) = scope else {
        return Ok(());
    };
    if nodes.is_empty() {
        return Err(MaintenanceError::EmptyScope);
    }
    let mut sorted = nodes.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != nodes.len() {
        return Err(MaintenanceError::DuplicateNode);
    }
    for node in &sorted {
        if !configured_nodes.contains(node) {
            return Err(MaintenanceError::UnknownNode(node.clone()));
        }
    }
    *nodes = sorted;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, MaintenanceError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(MaintenanceError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    io::Read::read_to_end(&mut file, &mut bytes)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| MaintenanceError::Invalid(format!("{}: {error}", path.display())))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    let temp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Id128::random()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
    };

    use macluster_core::config::{ClusterConfig, ShareConfig};
    use macluster_protocol::{
        control::{MaintenancePhase, MaintenanceScope},
        identifiers::{Id128, NodeId},
    };

    use super::{MaintenanceCoordinator, validate_scope_config_change};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "macluster-maintenance-coordinator-{}-{}",
                std::process::id(),
                Id128::random()
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn nodes(&self) -> BTreeSet<NodeId> {
            ["arm-a", "arm-b", "login-01"]
                .into_iter()
                .map(|id| NodeId::new(id).unwrap())
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(queue_members: &[&str], shared_root: &Path) -> ClusterConfig {
        let nodes = ["login", "arm-a", "arm-b"];
        let mut source = format!(
            "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"{}\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"login\"\nprotocol_version=1\n\n[queues.q]\nnodes=[{}]\nscheduler=\"fifo\"\n",
            shared_root.display(),
            queue_members
                .iter()
                .map(|node| format!("\"{node}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        for (index, node) in nodes.iter().enumerate() {
            if *node == "login" {
                source.push_str(&format!(
                    "\n[nodes.{node}]\nhost=\"192.0.2.{}\"\ntransport=\"local\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n",
                    index + 1
                ));
            } else {
                source.push_str(&format!(
                    "\n[nodes.{node}]\nhost=\"192.0.2.{}\"\ntransport=\"ssh\"\n",
                    index + 1
                ));
            }
        }
        ClusterConfig::parse(&source).unwrap()
    }

    #[test]
    fn scoped_maintenance_survives_restart_and_requires_ticket_to_complete() {
        let fixture = Fixture::new();
        let nodes = fixture.nodes();
        let journal_path = fixture.0.join("node-admin.json");
        fs::write(&journal_path, b"preflight journal").unwrap();
        let journal_digest = macluster_protocol::framing::sha256_hex(b"preflight journal").unwrap();
        let operation_id = Id128::random();
        let mut coordinator =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();

        let ticket = coordinator
            .begin(
                operation_id,
                MaintenanceScope::Nodes(vec![
                    NodeId::new("arm-b").unwrap(),
                    NodeId::new("arm-a").unwrap(),
                ]),
                &journal_digest,
                &nodes,
            )
            .unwrap();
        let status = coordinator.inspect().unwrap();
        assert_eq!(status.phase, MaintenancePhase::Draining);
        assert_eq!(
            status.scope,
            MaintenanceScope::Nodes(vec![
                NodeId::new("arm-a").unwrap(),
                NodeId::new("arm-b").unwrap(),
            ])
        );

        drop(coordinator);
        let mut recovered =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();
        assert_eq!(
            recovered.scope().unwrap(),
            MaintenanceScope::Nodes(vec![
                NodeId::new("arm-a").unwrap(),
                NodeId::new("arm-b").unwrap(),
            ])
        );
        assert!(recovered.mark_ready(&ticket, Vec::new()).unwrap());
        assert_eq!(recovered.inspect().unwrap().phase, MaintenancePhase::Ready);
        recovered
            .prepare_complete(
                &ticket,
                "config-b",
                "config-b",
                &journal_digest,
                &journal_digest,
            )
            .unwrap();
        recovered.commit_complete(&ticket).unwrap();
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.config_digest(), "config-b");
        assert!(recovered.inspect().is_none());

        let reopened = MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-b").unwrap();
        assert_eq!(reopened.generation(), 1);
    }

    #[test]
    fn maintenance_rejects_unconfigured_and_duplicate_node_ids() {
        let fixture = Fixture::new();
        let nodes = fixture.nodes();
        fs::write(fixture.0.join("node-admin.json"), b"journal").unwrap();
        let digest = macluster_protocol::framing::sha256_hex(b"journal").unwrap();
        let mut coordinator =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();
        let operation_id = Id128::random();
        assert!(
            coordinator
                .begin(
                    operation_id,
                    MaintenanceScope::Nodes(vec![NodeId::new("unknown").unwrap()]),
                    &digest,
                    &nodes,
                )
                .is_err()
        );
        assert!(
            coordinator
                .begin(
                    operation_id,
                    MaintenanceScope::Nodes(vec![
                        NodeId::new("arm-a").unwrap(),
                        NodeId::new("arm-a").unwrap(),
                    ]),
                    &digest,
                    &nodes,
                )
                .is_err()
        );
    }

    #[test]
    fn a_changed_preflight_journal_and_stale_ticket_cannot_complete() {
        let fixture = Fixture::new();
        let nodes = fixture.nodes();
        let journal_path = fixture.0.join("node-admin.json");
        fs::write(&journal_path, b"original").unwrap();
        let original_digest = macluster_protocol::framing::sha256_hex(b"original").unwrap();
        let mut coordinator =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();
        let ticket = coordinator
            .begin(
                Id128::random(),
                MaintenanceScope::Nodes(vec![NodeId::new("arm-a").unwrap()]),
                &original_digest,
                &nodes,
            )
            .unwrap();
        assert!(coordinator.mark_ready(&ticket, Vec::new()).unwrap());
        fs::write(&journal_path, b"changed").unwrap();
        assert!(
            coordinator
                .prepare_complete(
                    &ticket,
                    "config-b",
                    "config-b",
                    &original_digest,
                    &macluster_protocol::framing::sha256_hex(b"changed").unwrap(),
                )
                .is_err()
        );
        let mut stale_ticket = ticket;
        stale_ticket.generation += 1;
        assert!(
            coordinator
                .prepare_complete(
                    &stale_ticket,
                    "config-b",
                    "config-b",
                    &original_digest,
                    &macluster_protocol::framing::sha256_hex(b"changed").unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn applying_ticket_recovers_generation_after_controller_restart() {
        let fixture = Fixture::new();
        let nodes = fixture.nodes();
        fs::write(fixture.0.join("node-admin.json"), b"journal candidate").unwrap();
        let journal_digest = macluster_protocol::framing::sha256_hex(b"journal candidate").unwrap();
        let mut coordinator =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();
        let ticket = coordinator
            .begin(
                Id128::random(),
                MaintenanceScope::Nodes(vec![NodeId::new("arm-b").unwrap()]),
                &journal_digest,
                &nodes,
            )
            .unwrap();
        coordinator.mark_ready(&ticket, Vec::new()).unwrap();
        coordinator
            .prepare_complete(
                &ticket,
                "config-b",
                "config-b",
                &journal_digest,
                &journal_digest,
            )
            .unwrap();
        assert!(
            !coordinator
                .update_blockers(&ticket, vec!["worker still active".into()])
                .unwrap()
        );
        let applying = coordinator.inspect().unwrap();
        assert_eq!(applying.phase, MaintenancePhase::RecoveryRequired);
        assert_eq!(applying.blockers, vec!["worker still active"]);
        drop(coordinator);

        let recovered = MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-b").unwrap();
        assert_eq!(recovered.generation(), 1);
        assert!(recovered.inspect().is_none());
        assert!(!recovered.startup_config_mismatch());
    }

    #[test]
    fn config_digest_change_without_a_ticket_requires_recovery() {
        let fixture = Fixture::new();
        let coordinator =
            MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-a").unwrap();
        drop(coordinator);

        let recovered = MaintenanceCoordinator::open(&fixture.0, "binding-a", "config-b").unwrap();
        assert!(recovered.startup_config_mismatch());
    }

    #[test]
    fn scoped_reload_must_cover_removed_queue_member_and_storage_changes_are_cluster_wide() {
        let fixture = Fixture::new();
        let root = fixture.0.join("shared");
        fs::create_dir_all(&root).unwrap();
        let old = config(&["login", "arm-a", "arm-b"], &root);
        let next = config(&["login", "arm-b"], &root);
        let arm_a = MaintenanceScope::Nodes(vec![NodeId::new("arm-a").unwrap()]);
        let arm_b = MaintenanceScope::Nodes(vec![NodeId::new("arm-b").unwrap()]);
        assert!(validate_scope_config_change(&old, &next, &arm_a).is_ok());
        assert!(validate_scope_config_change(&old, &next, &arm_b).is_err());

        let new_shared_root = fixture.0.join("other-shared");
        fs::create_dir_all(&new_shared_root).unwrap();
        let changed_storage = config(&["login", "arm-b"], &new_shared_root);
        assert!(validate_scope_config_change(&old, &changed_storage, &arm_a).is_err());

        let mut named_share_change = old.clone();
        named_share_change.shares.insert(
            "datasets".into(),
            ShareConfig {
                server: NodeId::new("arm-a").unwrap(),
                source_root: PathBuf::from("/Volumes/datasets"),
                mount_root: PathBuf::from("/Volumes/datasets"),
                share_uuid: "share-id".into(),
                allow_existing_contents: false,
            },
        );
        assert!(validate_scope_config_change(&old, &named_share_change, &arm_a).is_err());
        assert!(
            validate_scope_config_change(&old, &named_share_change, &MaintenanceScope::Cluster)
                .is_ok()
        );

        let mut changed_namespace = old.clone();
        changed_namespace.share_uuid = "00000000-0000-4000-8000-000000000002".into();
        assert!(
            validate_scope_config_change(&old, &changed_namespace, &MaintenanceScope::Cluster)
                .is_err()
        );

        let mut changed_login = old.clone();
        changed_login.login_node = Some(NodeId::new("arm-a").unwrap());
        assert!(
            validate_scope_config_change(&old, &changed_login, &MaintenanceScope::Cluster).is_err()
        );
    }
}
