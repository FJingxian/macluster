//! Generation- and freshness-aware cache for remote Agent build checks.

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use macluster_core::config::{ClusterConfig, NodeConfig, Transport};
use macluster_protocol::{framing::sha256_hex, identifiers::NodeId};

use crate::ssh::{ConnectionKey, SshPool};

pub const COMPATIBILITY_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityState {
    Current,
    Mismatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityView {
    Current,
    Mismatch,
    Unknown,
    Stale,
}

struct CacheEntry {
    generation: u64,
    state: CompatibilityState,
    checked_at: Instant,
    boot_id: Option<String>,
}

/// Controller-local cache. Callers check `view` before dispatching a probe,
/// then use `begin_check` to collapse concurrent refreshes into one task.
/// Results are accepted only for the active configuration generation.
#[derive(Default)]
pub struct CompatibilityCache {
    generation: Mutex<u64>,
    entries: Mutex<HashMap<NodeId, CacheEntry>>,
    in_flight: Mutex<HashSet<(NodeId, u64)>>,
}

struct CompatibilityTask {
    node_id: NodeId,
    node: NodeConfig,
    generation: u64,
}

/// Bounded, on-demand background refresh. The control request only enqueues
/// stale cache entries; slow or offline SSH probes never block the IPC loop.
pub struct CompatibilityRefresher {
    cache: Arc<CompatibilityCache>,
    configured_nodes: HashMap<String, NodeConfig>,
    sender: Option<SyncSender<CompatibilityTask>>,
    workers: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl CompatibilityRefresher {
    pub fn start(cache: Arc<CompatibilityCache>, config: ClusterConfig, namespace: String) -> Self {
        let current_digest = Arc::new(OnceLock::<Option<String>>::new());
        Self::start_with_probe(
            cache,
            config,
            namespace,
            Arc::new(move |node_id, node, pool| {
                let current_digest = current_digest.get_or_init(|| current_build_digest().ok());
                current_digest
                    .as_deref()
                    .map_or(CompatibilityState::Unknown, |digest| {
                        probe_agent_build(node_id, node, pool, digest)
                    })
            }),
        )
    }

    fn start_with_probe(
        cache: Arc<CompatibilityCache>,
        config: ClusterConfig,
        namespace: String,
        probe: Arc<dyn Fn(&NodeId, &NodeConfig, &SshPool) -> CompatibilityState + Send + Sync>,
    ) -> Self {
        const WORKERS: usize = 4;
        const QUEUE_CAPACITY: usize = 128;
        let (sender, receiver) = mpsc::sync_channel::<CompatibilityTask>(QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        let stop = Arc::new(AtomicBool::new(false));
        let pool = SshPool::new(namespace);
        let workers = (0..WORKERS)
            .filter_map(|index| {
                let cache = Arc::clone(&cache);
                let receiver = Arc::clone(&receiver);
                let stop = Arc::clone(&stop);
                let probe = Arc::clone(&probe);
                let pool = pool.clone();
                thread::Builder::new()
                    .name(format!("agent-compatibility-{index}"))
                    .spawn(move || {
                        loop {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            let task = receiver.lock().ok().and_then(|receiver| {
                                receiver.recv_timeout(Duration::from_millis(250)).ok()
                            });
                            let Some(task) = task else {
                                continue;
                            };
                            let state = probe(&task.node_id, &task.node, &pool);
                            cache.complete_check(
                                &task.node_id,
                                task.generation,
                                state,
                                None,
                                Instant::now(),
                            );
                        }
                    })
                    .ok()
            })
            .collect();
        let configured = config
            .nodes
            .into_iter()
            .map(|(id, node)| (id, node))
            .collect::<HashMap<_, _>>();
        Self {
            cache,
            configured_nodes: configured,
            sender: Some(sender),
            workers,
            stop,
        }
    }

    pub fn request(&self, node_id: &NodeId, generation: u64) -> bool {
        let Some(node) = self.configured_nodes.get(node_id.as_str()).cloned() else {
            return false;
        };
        if !self.cache.begin_check(node_id, generation) {
            return false;
        }
        let Some(sender) = &self.sender else {
            self.cache.cancel_check(node_id, generation);
            return false;
        };
        match sender.try_send(CompatibilityTask {
            node_id: node_id.clone(),
            node,
            generation,
        }) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.cache.cancel_check(node_id, generation);
                false
            }
        }
    }
}

impl Drop for CompatibilityRefresher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl CompatibilityCache {
    pub fn new(generation: u64) -> Self {
        Self {
            generation: Mutex::new(generation),
            entries: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    pub fn set_generation(&self, generation: u64) {
        if let Ok(mut current) = self.generation.lock() {
            *current = generation;
        }
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.retain(|(_, entry_generation)| *entry_generation == generation);
        }
    }

    pub fn view(
        &self,
        node_id: &NodeId,
        generation: u64,
        observed_boot_id: Option<&str>,
        now: Instant,
    ) -> CompatibilityView {
        let Ok(active_generation) = self.generation.lock() else {
            return CompatibilityView::Unknown;
        };
        if *active_generation != generation {
            return CompatibilityView::Stale;
        }
        let Ok(entries) = self.entries.lock() else {
            return CompatibilityView::Unknown;
        };
        let Some(entry) = entries.get(node_id) else {
            return CompatibilityView::Unknown;
        };
        if entry.generation != generation
            || now.saturating_duration_since(entry.checked_at) >= COMPATIBILITY_TTL
            || matches!((entry.boot_id.as_deref(), observed_boot_id), (Some(a), Some(b)) if a != b)
        {
            return CompatibilityView::Stale;
        }
        match entry.state {
            CompatibilityState::Current => CompatibilityView::Current,
            CompatibilityState::Mismatch => CompatibilityView::Mismatch,
            CompatibilityState::Unknown => CompatibilityView::Unknown,
        }
    }

    /// Return true only to the first caller that starts a check for this node
    /// and generation. A stale-generation check is rejected before it starts.
    pub fn begin_check(&self, node_id: &NodeId, generation: u64) -> bool {
        let Ok(active_generation) = self.generation.lock() else {
            return false;
        };
        if *active_generation != generation {
            return false;
        }
        self.in_flight
            .lock()
            .is_ok_and(|mut in_flight| in_flight.insert((node_id.clone(), generation)))
    }

    /// Complete an on-demand/background probe. Returns false when the result
    /// belongs to an old configuration or no matching check was active.
    pub fn complete_check(
        &self,
        node_id: &NodeId,
        generation: u64,
        state: CompatibilityState,
        boot_id: Option<String>,
        now: Instant,
    ) -> bool {
        let removed = self
            .in_flight
            .lock()
            .is_ok_and(|mut in_flight| in_flight.remove(&(node_id.clone(), generation)));
        let active_generation = self
            .generation
            .lock()
            .ok()
            .is_some_and(|active| *active == generation);
        if !removed || !active_generation {
            return false;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        entries.insert(
            node_id.clone(),
            CacheEntry {
                generation,
                state,
                checked_at: now,
                boot_id,
            },
        );
        true
    }

    /// Store a result computed by the authenticated local CLI. This refreshes
    /// the shared cache even when another observer was checking the same node.
    pub fn publish(
        &self,
        node_id: &NodeId,
        generation: u64,
        state: CompatibilityState,
        boot_id: Option<String>,
        now: Instant,
    ) -> bool {
        let active_generation = self
            .generation
            .lock()
            .ok()
            .is_some_and(|active| *active == generation);
        if !active_generation {
            return false;
        }
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(&(node_id.clone(), generation));
        }
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        entries.insert(
            node_id.clone(),
            CacheEntry {
                generation,
                state,
                checked_at: now,
                boot_id,
            },
        );
        true
    }

    pub fn age(&self, node_id: &NodeId, generation: u64, now: Instant) -> Option<Duration> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(node_id)?;
        (entry.generation == generation).then(|| now.saturating_duration_since(entry.checked_at))
    }

    pub fn invalidate_node(&self, node_id: &NodeId) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(node_id);
        }
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.retain(|(candidate, _)| candidate != node_id);
        }
    }

    pub fn invalidate_all(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.clear();
        }
    }

    pub fn cancel_check(&self, node_id: &NodeId, generation: u64) {
        if let Ok(mut in_flight) = self.in_flight.lock() {
            in_flight.remove(&(node_id.clone(), generation));
        }
    }
}

fn current_build_digest() -> Result<String, std::io::Error> {
    let executable = env::current_exe()?.canonicalize()?;
    let bytes = fs::read(executable)?;
    sha256_hex(&bytes).map_err(std::io::Error::other)
}

fn probe_agent_build(
    node_id: &NodeId,
    node: &NodeConfig,
    pool: &SshPool,
    current_digest: &str,
) -> CompatibilityState {
    if node.transport == Transport::Local {
        return fs::read(&node.remote_binary)
            .ok()
            .and_then(|bytes| sha256_hex(&bytes).ok())
            .map_or(CompatibilityState::Unknown, |digest| {
                compare_digest(&digest, current_digest)
            });
    }
    if let Some(digest) = managed_binary_digest(&node.remote_binary) {
        return compare_digest(&digest, current_digest);
    }
    let quoted = shell_quote(&node.remote_binary);
    let remote_command = format!(
        "version=$({quoted} --version) || exit; printf 'VERSION=%s\\n' \"$version\"; if digest=$(/usr/bin/shasum -a 256 -- {quoted} 2>/dev/null); then digest=${{digest%% *}}; printf 'SHA256=%s\\n' \"$digest\"; fi"
    );
    let mut command = Command::new("/usr/bin/ssh");
    command.args([
        "-T",
        "-oLogLevel=ERROR",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=5",
        "-oServerAliveInterval=5",
        "-oServerAliveCountMax=1",
    ]);
    node.add_ssh_identity_args(&mut command);
    if let Ok(key) = ConnectionKey::for_node(pool.namespace(), node_id.as_str(), node) {
        let _ = pool.append_args(&key, &mut command);
    }
    command.arg(&node.host).arg(remote_command);
    let Ok(output) = crate::transport::run_child_bounded(command, None, Duration::from_secs(8))
    else {
        return CompatibilityState::Unknown;
    };
    if !output.status.success() {
        return CompatibilityState::Unknown;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut version = None;
    let mut digest = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("VERSION=") {
            version = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("SHA256=")
            && value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            digest = Some(value.trim());
        }
    }
    if let Some(digest) = digest {
        return compare_digest(digest, current_digest);
    }
    match version {
        Some(version) if version.starts_with(concat!("macluster ", env!("CARGO_PKG_VERSION"))) => {
            CompatibilityState::Current
        }
        Some(version) if version.starts_with("macluster ") => CompatibilityState::Mismatch,
        _ => CompatibilityState::Unknown,
    }
}

fn managed_binary_digest(binary: &str) -> Option<String> {
    let path = Path::new(binary);
    if path.file_name()? != "macluster" {
        return None;
    }
    let digest = path.parent()?.file_name()?.to_str()?;
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| digest.to_ascii_lowercase())
}

fn compare_digest(remote: &str, current: &str) -> CompatibilityState {
    if remote.eq_ignore_ascii_case(current) {
        CompatibilityState::Current
    } else {
        CompatibilityState::Mismatch
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use macluster_core::config::ClusterConfig;
    use macluster_protocol::identifiers::NodeId;

    use super::{
        CompatibilityCache, CompatibilityRefresher, CompatibilityState, CompatibilityView,
    };

    fn node(value: &str) -> NodeId {
        value.parse().unwrap()
    }

    #[test]
    fn concurrent_checks_for_a_node_are_coalesced() {
        let cache = CompatibilityCache::new(7);
        let node = node("worker-a");
        assert!(cache.begin_check(&node, 7));
        assert!(!cache.begin_check(&node, 7));
        cache.complete_check(
            &node,
            7,
            CompatibilityState::Current,
            Some("boot-a".into()),
            Instant::now(),
        );
        assert_eq!(
            cache.view(&node, 7, Some("boot-a"), Instant::now()),
            CompatibilityView::Current
        );
    }

    #[test]
    fn generation_change_drops_old_inflight_result_and_marks_old_value_stale() {
        let cache = CompatibilityCache::new(4);
        let node = node("worker-a");
        let now = Instant::now();
        assert!(cache.begin_check(&node, 4));
        cache.complete_check(&node, 4, CompatibilityState::Mismatch, None, now);
        cache.set_generation(5);
        assert_eq!(cache.view(&node, 5, None, now), CompatibilityView::Stale);
        assert!(!cache.complete_check(
            &node,
            4,
            CompatibilityState::Current,
            None,
            now + Duration::from_millis(1),
        ));
        assert_eq!(cache.view(&node, 5, None, now), CompatibilityView::Stale);
    }

    #[test]
    fn expired_and_rebooted_entries_are_stale_not_current_or_mismatch() {
        let cache = CompatibilityCache::new(1);
        let node = node("worker-a");
        let checked = Instant::now();
        assert!(cache.begin_check(&node, 1));
        cache.complete_check(
            &node,
            1,
            CompatibilityState::Current,
            Some("boot-before".into()),
            checked,
        );
        assert_eq!(
            cache.view(
                &node,
                1,
                Some("boot-after"),
                checked + Duration::from_secs(1)
            ),
            CompatibilityView::Stale
        );
        assert_eq!(
            cache.view(
                &node,
                1,
                Some("boot-before"),
                checked + Duration::from_secs(61)
            ),
            CompatibilityView::Stale
        );
    }

    #[test]
    fn fresh_mismatch_is_distinct_from_unknown_offline_and_stale() {
        let cache = CompatibilityCache::new(1);
        let mismatch = node("worker-a");
        let offline = node("worker-b");
        let checked = Instant::now();
        assert!(cache.begin_check(&mismatch, 1));
        cache.complete_check(&mismatch, 1, CompatibilityState::Mismatch, None, checked);
        assert_eq!(
            cache.view(&mismatch, 1, None, checked),
            CompatibilityView::Mismatch
        );
        assert_eq!(
            cache.view(&offline, 1, None, checked),
            CompatibilityView::Unknown
        );
        assert_eq!(
            cache.view(&mismatch, 1, None, checked + Duration::from_secs(61)),
            CompatibilityView::Stale
        );
    }

    #[test]
    fn node_invalidation_forces_an_on_demand_check() {
        let cache = CompatibilityCache::new(1);
        let node = node("worker-a");
        let now = Instant::now();
        assert!(cache.begin_check(&node, 1));
        cache.complete_check(&node, 1, CompatibilityState::Current, None, now);
        cache.invalidate_node(&node);
        assert_eq!(cache.view(&node, 1, None, now), CompatibilityView::Unknown);
        assert!(cache.begin_check(&node, 1));
    }

    #[test]
    fn slow_compatibility_probe_runs_in_background_without_blocking_cache_queries() {
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname=\"compatibility-test\"\ndefault_queue=\"q\"\nlogin_node=\"worker\"\nshared_root=\"/tmp/macluster-compatibility-test\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/usr/bin/true\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
            unsafe { libc::geteuid() }
        ))
        .unwrap();
        let cache = Arc::new(CompatibilityCache::new(3));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let refresher = CompatibilityRefresher::start_with_probe(
            Arc::clone(&cache),
            config,
            "compatibility-test".into(),
            Arc::new(move |_, _, _| {
                started_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                CompatibilityState::Unknown
            }),
        );
        let node_id = node("worker");

        let started = Instant::now();
        assert!(refresher.request(&node_id, 3));
        assert!(started.elapsed() < Duration::from_millis(100));
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let query_started = Instant::now();
        assert_eq!(
            cache.view(&node_id, 3, None, Instant::now()),
            CompatibilityView::Unknown
        );
        assert!(cache.age(&node_id, 3, Instant::now()).is_none());
        assert!(query_started.elapsed() < Duration::from_millis(100));

        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while cache.age(&node_id, 3, Instant::now()).is_none() {
            assert!(Instant::now() < deadline, "background probe did not finish");
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            cache.view(&node_id, 3, None, Instant::now()),
            CompatibilityView::Unknown
        );
    }
}
