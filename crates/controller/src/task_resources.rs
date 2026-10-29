//! Leased task telemetry. All clients of one job share one bounded worker probe.
use macluster_core::{
    config::{ClusterConfig, NodeConfig},
    storage::Storage,
};
use macluster_protocol::{
    identifiers::{Id128, StartToken},
    resources::{JobResourceSnapshot, TASK_RESOURCE_INTERVAL_MS, TaskResourceSample},
    types::{JobRecord, JobState},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

const LEASE: Duration = Duration::from_secs(30);
const INTERVAL: Duration = Duration::from_millis(TASK_RESOURCE_INTERVAL_MS);
const LIMIT: usize = 128;
pub(crate) type Probe =
    dyn Fn(&JobRecord, &NodeConfig) -> Result<TaskResourceSample, String> + Send + Sync;
struct Cache {
    token: Option<StartToken>,
    sample: Option<(TaskResourceSample, Instant)>,
    error: Option<String>,
    next: Instant,
}
struct ResultRow {
    job: JobRecord,
    result: Result<TaskResourceSample, String>,
}
struct Task {
    job: JobRecord,
    node: NodeConfig,
}
pub(crate) struct TaskResourceHub {
    subscriptions: HashMap<Id128, (u64, Instant)>,
    cache: HashMap<u64, Cache>,
    in_flight: HashSet<u64>,
    tasks: mpsc::SyncSender<Task>,
    results: mpsc::Receiver<ResultRow>,
}
impl TaskResourceHub {
    pub fn new(probe: Arc<Probe>) -> Self {
        let (tasks, receiver) = mpsc::sync_channel::<Task>(2);
        let receiver = Arc::new(Mutex::new(receiver));
        let (sender, results) = mpsc::channel();
        for index in 0..2 {
            let receiver = Arc::clone(&receiver);
            let sender = sender.clone();
            let probe = Arc::clone(&probe);
            thread::Builder::new()
                .name(format!("job-resources-{index}"))
                .spawn(move || {
                    loop {
                        let task = match receiver.lock() {
                            Ok(rx) => rx.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else { return };
                        let result = probe(&task.job, &task.node);
                        if sender
                            .send(ResultRow {
                                job: task.job,
                                result,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                })
                .expect("start job resource worker");
        }
        Self {
            subscriptions: HashMap::new(),
            cache: HashMap::new(),
            in_flight: HashSet::new(),
            tasks,
            results,
        }
    }
    pub fn subscribe(
        &mut self,
        session: Id128,
        job: &JobRecord,
        now: Instant,
    ) -> Result<(), String> {
        self.expire(now);
        if !self.subscriptions.contains_key(&session) && self.subscriptions.len() >= LIMIT {
            return Err("too many task resource subscriptions".into());
        }
        self.subscriptions.insert(session, (job.id, now + LEASE));
        self.cache.entry(job.id).or_insert_with(|| Cache {
            token: job.start_token,
            sample: None,
            error: None,
            next: now,
        });
        Ok(())
    }
    pub fn disconnect(&mut self, session: Id128) {
        self.subscriptions.remove(&session);
        self.expire(Instant::now());
    }
    fn expire(&mut self, now: Instant) {
        self.subscriptions.retain(|_, (_, expiry)| now < *expiry);
        let watched = self
            .subscriptions
            .values()
            .map(|(id, _)| *id)
            .collect::<HashSet<_>>();
        self.cache.retain(|id, _| watched.contains(id));
    }
    pub fn tick(&mut self, storage: &Storage, config: &ClusterConfig, now: Instant) {
        self.expire(now);
        while let Ok(row) = self.results.try_recv() {
            self.in_flight.remove(&row.job.id);
            if let Some(cache) = self.cache.get_mut(&row.job.id) {
                if cache.token == row.job.start_token {
                    match row.result {
                        Ok(sample) => {
                            cache.sample = Some((sample, now));
                            cache.error = None;
                        }
                        Err(error) => {
                            cache.error = Some(error.chars().take(1024).collect());
                        }
                    }
                    cache.next = now + INTERVAL;
                }
            }
        }
        if self.in_flight.len() >= 2 {
            return;
        }
        let due = self
            .cache
            .iter()
            .filter(|(id, c)| now >= c.next && !self.in_flight.contains(id))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in due {
            let Some(cache) = self.cache.get_mut(&id) else {
                continue;
            };
            cache.next = now + INTERVAL;
            let job = match storage.get_job(id) {
                Ok(Some(job)) => job,
                _ => {
                    cache.error = Some("job is no longer available".into());
                    continue;
                }
            };
            if cache.token != job.start_token {
                cache.token = job.start_token;
                cache.sample = None;
                cache.error = None;
            }
            if !matches!(job.state, JobState::Running | JobState::Cancelling) {
                continue;
            }
            let Some(node) = job
                .node
                .as_ref()
                .and_then(|id| config.nodes.get(id.as_str()))
            else {
                continue;
            };
            match self.tasks.try_send(Task {
                job: job.clone(),
                node: node.clone(),
            }) {
                Ok(()) => {
                    self.in_flight.insert(id);
                }
                Err(_) => break,
            }
            if self.in_flight.len() >= 2 {
                break;
            }
        }
    }
    pub fn snapshot(
        &mut self,
        session: Id128,
        job: &JobRecord,
        now: Instant,
    ) -> Result<JobResourceSnapshot, String> {
        self.expire(now);
        let sub = self
            .subscriptions
            .get_mut(&session)
            .filter(|(id, _)| *id == job.id)
            .ok_or("task resource subscription expired; subscribe again")?;
        sub.1 = now + LEASE;
        let cache = self
            .cache
            .get(&job.id)
            .filter(|cache| cache.token == job.start_token);
        let sample = cache.and_then(|c| c.sample.as_ref());
        let age_ms = sample.map(|(sample, at)| {
            sample.age_ms.saturating_add(
                now.saturating_duration_since(*at)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
            )
        });
        let error = cache
            .and_then(|c| c.error.clone())
            .or_else(|| sample.and_then(|(s, _)| s.error.clone()));
        let error = error.or_else(|| {
            (job.state.is_terminal() && sample.is_none()).then(|| {
                "no live observations retained; use submit -v for persistent task accounting".into()
            })
        });
        Ok(JobResourceSnapshot {
            schema_version: 1,
            job_id: job.id,
            node_id: job.node.clone(),
            start_token: job.start_token,
            state: job.state,
            sample: sample.map(|(sample, _)| sample.clone()),
            age_ms,
            stale: error.is_some() || age_ms.is_none_or(|ms| ms > TASK_RESOURCE_INTERVAL_MS * 3),
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macluster_protocol::{
        identifiers::{NodeId, RequestId},
        types::{JobMode, JobSpec},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fixture {
        root: std::path::PathBuf,
        storage: Storage,
        config: ClusterConfig,
        job: JobRecord,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("task-resources-{}", Id128::random()));
            let storage = Storage::open(&root).unwrap();
            let config=ClusterConfig::parse("[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"127.0.0.1\"\ntransport=\"ssh\"\n").unwrap();
            let spec = JobSpec {
                storage_namespace: None,
                queue: "q".parse().unwrap(),
                node: None,
                name: "probe".into(),
                cwd: "/tmp/shared".into(),
                stdout_path: "/tmp/shared/out".into(),
                stderr_path: "/tmp/shared/err".into(),
                walltime_secs: None,
                env: Default::default(),
                mode: JobMode::Interactive,
                snapshot: None,
            };
            let job = storage
                .submit_once(RequestId(Id128::random()), spec)
                .unwrap();
            storage
                .reserve_job(job.id, NodeId::new("worker").unwrap())
                .unwrap();
            let job = storage.mark_running(job.id).unwrap();
            Self {
                root,
                storage,
                config,
                job,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn sample() -> TaskResourceSample {
        TaskResourceSample {
            schema_version: 1,
            observed_unix_ms: 1,
            age_ms: 0,
            interval_ms: Some(5000),
            cpu_percent: Some(123.0),
            rss_bytes: Some(1024),
            cpu_time_seconds: 1.0,
            memory_time_gib_seconds: 0.1,
            memory_peak_sampled_bytes: 1024,
            process_count: 1,
            source: "test".into(),
            coverage: "partial".into(),
            error: None,
        }
    }
    fn wait(
        hub: &mut TaskResourceHub,
        f: &Fixture,
        session: Id128,
        now: Instant,
    ) -> JobResourceSnapshot {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            hub.tick(&f.storage, &f.config, now);
            let snapshot = hub.snapshot(session, &f.job, now).unwrap();
            if snapshot.sample.is_some() {
                return snapshot;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn subscribers_share_one_probe_and_disconnect_stops_work() {
        let f = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut hub = TaskResourceHub::new(Arc::new(move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(15));
            Ok(sample())
        }));
        let a = Id128::random();
        let b = Id128::random();
        let now = Instant::now();
        hub.subscribe(a, &f.job, now).unwrap();
        hub.subscribe(b, &f.job, now).unwrap();
        hub.tick(&f.storage, &f.config, now);
        let first = wait(&mut hub, &f, a, now + Duration::from_millis(20));
        assert_eq!(first.sample.unwrap().cpu_percent, Some(123.0));
        assert!(hub.snapshot(b, &f.job, now).unwrap().sample.is_some());
        assert!(hub.snapshot(Id128::random(), &f.job, now).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        hub.disconnect(a);
        hub.disconnect(b);
        hub.tick(&f.storage, &f.config, now + Duration::from_secs(20));
        assert!(hub.cache.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failures_preserve_last_sample_and_expired_leases_stop_sampling() {
        let f = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut hub = TaskResourceHub::new(Arc::new(move |_, _| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(sample())
            } else {
                Err("offline".into())
            }
        }));
        let session = Id128::random();
        let now = Instant::now();
        hub.subscribe(session, &f.job, now).unwrap();
        wait(&mut hub, &f, session, now);
        let later = now + Duration::from_secs(6);
        hub.tick(&f.storage, &f.config, later);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            hub.tick(&f.storage, &f.config, later);
            if hub
                .snapshot(session, &f.job, later)
                .unwrap()
                .error
                .is_some()
            {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        let snapshot = hub
            .snapshot(session, &f.job, now + Duration::from_secs(20))
            .unwrap();
        assert!(snapshot.sample.is_some());
        assert!(snapshot.stale);
        assert_eq!(snapshot.error.as_deref(), Some("offline"));
        hub.tick(&f.storage, &f.config, now + Duration::from_secs(51));
        assert!(
            hub.snapshot(session, &f.job, now + Duration::from_secs(51))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn finished_jobs_stop_sampling_and_limits_bound_memory() {
        let f = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut hub = TaskResourceHub::new(Arc::new(move |_, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(sample())
        }));
        let now = Instant::now();
        let a = Id128::random();
        hub.subscribe(a, &f.job, now).unwrap();
        wait(&mut hub, &f, a, now);
        f.storage
            .finish_job(f.job.id, JobState::Completed, Some(0), None)
            .unwrap();
        hub.tick(&f.storage, &f.config, now + Duration::from_secs(6));
        let job = f.storage.get_job(f.job.id).unwrap().unwrap();
        assert!(
            hub.snapshot(a, &job, now + Duration::from_secs(6))
                .unwrap()
                .state
                .is_terminal()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for _ in 1..LIMIT {
            hub.subscribe(Id128::random(), &job, now).unwrap();
        }
        assert!(hub.subscribe(Id128::random(), &job, now).is_err());
    }
}
