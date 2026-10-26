//! Opt-in, bounded task output capture and resource accounting.

use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{ChildStderr, ChildStdout},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_protocol::identifiers::{Id128, StartToken};
use serde::Serialize;

const LOG_LIMIT_BYTES: u64 = 10 * 1024 * 1024;
const RESOURCE_LIMIT_BYTES: u64 = 1024 * 1024;
const SEGMENT_TARGET_BYTES: usize = 2 * 1024 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;
const ENHANCEMENT_QUEUE_DEPTH: usize = 64;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_TRACKED_PROCESSES: usize = 4096;

#[derive(Clone, Copy, Debug)]
enum OutputStream {
    Stdout,
    Stderr,
    Pty,
}

impl OutputStream {
    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Pty => "pty",
        }
    }
}

#[derive(Clone, Serialize)]
struct ResourceSample {
    schema_version: u8,
    observed_unix_ms: u64,
    elapsed_seconds: f64,
    interval_ms: Option<u64>,
    cpu_percent: Option<f64>,
    rss_bytes: Option<u64>,
    runner_rss_bytes: Option<u64>,
    cpu_time_seconds: f64,
    memory_time_gib_seconds: f64,
    memory_peak_sampled_bytes: u64,
    covered_memory_seconds: f64,
    missing_memory_seconds: f64,
    process_count: usize,
    missed_process_queries: u64,
    cpu_quality: &'static str,
    memory_quality: &'static str,
    error: Option<String>,
}

#[derive(Clone)]
struct LogIdentity {
    cluster_id: String,
    share_id: Option<String>,
    job_id: u64,
    start_token: String,
}

enum EnhancementEvent {
    Output {
        stream: OutputStream,
        offset: u64,
        bytes: Vec<u8>,
        sample: Option<ResourceSample>,
    },
    Sample(ResourceSample),
    Heartbeat {
        observed_unix_ms: u64,
        sample: Option<ResourceSample>,
    },
    Stop,
}

#[derive(Clone, Copy, Default)]
struct CaptureStats {
    retained_bytes: u64,
    discarded_bytes: u64,
}

#[derive(Serialize)]
struct TaskResourceSummary {
    schema_version: u8,
    cluster_id: String,
    share_id: Option<String>,
    job_id: u64,
    start_token: String,
    elapsed_seconds: f64,
    cpu_time_seconds: f64,
    memory_time_gib_seconds: f64,
    memory_peak_sampled_bytes: u64,
    covered_memory_seconds: f64,
    missing_memory_seconds: f64,
    cpu_quality: &'static str,
    memory_quality: &'static str,
    samples: u64,
    missed_process_queries: u64,
    stdout_retained_bytes: u64,
    stdout_discarded_bytes: u64,
    stderr_retained_bytes: u64,
    stderr_discarded_bytes: u64,
    monitor_discarded_bytes: u64,
    resources_discarded_bytes: u64,
    annotation_dropped_bytes: u64,
    annotation_dropped_samples: u64,
    dropped_heartbeats: u64,
    annotation_failed: Option<String>,
    raw_capture_failed: Option<String>,
    runner_cpu_user_seconds: f64,
    runner_cpu_system_seconds: f64,
    runner_rss_baseline_bytes: Option<u64>,
    runner_peak_rss_sampled_bytes: Option<u64>,
    runner_peak_rss_sampled_growth_bytes: Option<u64>,
}

pub(super) struct TaskLogCompletion {
    pub(super) raw_capture_failed: Option<String>,
    pub(super) annotation_failed: Option<String>,
}

pub(super) struct TaskLogSession {
    identity: LogIdentity,
    local_dir: PathBuf,
    sender: Option<SyncSender<EnhancementEvent>>,
    collectors: Vec<JoinHandle<io::Result<CaptureStats>>>,
    pty_raw_log: Option<SegmentedLog>,
    enhancer: Option<JoinHandle<EnhancementResult>>,
    latest_sample: Arc<Mutex<Option<ResourceSample>>>,
    stdout_bytes: Arc<AtomicU64>,
    stderr_bytes: Arc<AtomicU64>,
    raw_error: Arc<Mutex<Option<String>>>,
    annotation_dropped_bytes: Arc<AtomicU64>,
    annotation_dropped_samples: Arc<AtomicU64>,
    dropped_heartbeats: Arc<AtomicU64>,
    accounting: ProcessAccounting,
    started_at: Instant,
    runner_usage_at_start: ProcessUsage,
    runner_rss_baseline_bytes: Option<u64>,
    runner_peak_rss_sampled_bytes: Option<u64>,
}

struct EnhancementResult {
    annotation_failed: Option<String>,
    monitor_discarded_bytes: u64,
    resources_discarded_bytes: u64,
}

impl TaskLogSession {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn start(
        local_dir: &Path,
        cluster_id: String,
        share_id: Option<String>,
        job_id: u64,
        start_token: StartToken,
        stdout: ChildStdout,
        stderr: ChildStderr,
    ) -> io::Result<Self> {
        let stdout_path = local_dir.join("stdout.log");
        let stderr_path = local_dir.join("stderr.log");
        for output in [&stdout_path, &stderr_path] {
            if output.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("verbose task output {} already exists", output.display()),
                ));
            }
        }
        let runner_usage_at_start = current_process_usage();
        let runner_rss_baseline_bytes = current_process_rss_bytes();

        let identity = LogIdentity {
            cluster_id,
            share_id,
            job_id,
            start_token: start_token.to_string(),
        };
        let latest_sample = Arc::new(Mutex::new(None));
        let stdout_bytes = Arc::new(AtomicU64::new(0));
        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let raw_error = Arc::new(Mutex::new(None));
        let annotation_dropped_bytes = Arc::new(AtomicU64::new(0));
        let annotation_dropped_samples = Arc::new(AtomicU64::new(0));
        let dropped_heartbeats = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = mpsc::sync_channel(ENHANCEMENT_QUEUE_DEPTH);

        let enhancer_identity = identity.clone();
        let monitor_dir = local_dir.join("monitor.segments");
        let resources_dir = local_dir.join("resources.segments");
        let enhancer = thread::Builder::new()
            .name(format!("macluster-enhance-{job_id}"))
            .spawn(move || {
                enhance_logs(receiver, &monitor_dir, &resources_dir, enhancer_identity)
            })?;

        let mut collectors = Vec::with_capacity(2);
        let stdout_collector = spawn_collector(
            stdout,
            OutputStream::Stdout,
            local_dir.join("stdout.segments"),
            stdout_path,
            sender.clone(),
            Arc::clone(&latest_sample),
            Arc::clone(&stdout_bytes),
            Arc::clone(&raw_error),
            Arc::clone(&annotation_dropped_bytes),
        );
        match stdout_collector {
            Ok(handle) => collectors.push(handle),
            Err(error) => {
                drop(sender);
                return Err(error);
            }
        }
        let stderr_collector = spawn_collector(
            stderr,
            OutputStream::Stderr,
            local_dir.join("stderr.segments"),
            stderr_path,
            sender.clone(),
            Arc::clone(&latest_sample),
            Arc::clone(&stderr_bytes),
            Arc::clone(&raw_error),
            Arc::clone(&annotation_dropped_bytes),
        );
        match stderr_collector {
            Ok(handle) => collectors.push(handle),
            Err(error) => {
                drop(sender);
                drop(collectors);
                return Err(error);
            }
        }

        Ok(Self {
            identity,
            local_dir: local_dir.to_path_buf(),
            sender: Some(sender),
            collectors,
            pty_raw_log: None,
            enhancer: Some(enhancer),
            latest_sample,
            stdout_bytes,
            stderr_bytes,
            raw_error,
            annotation_dropped_bytes,
            annotation_dropped_samples,
            dropped_heartbeats,
            accounting: ProcessAccounting::default(),
            started_at: Instant::now(),
            runner_usage_at_start,
            runner_rss_baseline_bytes,
            runner_peak_rss_sampled_bytes: runner_rss_baseline_bytes,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn start_pty(
        local_dir: &Path,
        cluster_id: String,
        share_id: Option<String>,
        job_id: u64,
        start_token: StartToken,
    ) -> io::Result<Self> {
        let stdout_path = local_dir.join("stdout.log");
        if stdout_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "verbose PTY output {} already exists",
                    stdout_path.display()
                ),
            ));
        }
        let runner_usage_at_start = current_process_usage();
        let runner_rss_baseline_bytes = current_process_rss_bytes();
        let identity = LogIdentity {
            cluster_id,
            share_id,
            job_id,
            start_token: start_token.to_string(),
        };
        let latest_sample = Arc::new(Mutex::new(None));
        let stdout_bytes = Arc::new(AtomicU64::new(0));
        let stderr_bytes = Arc::new(AtomicU64::new(0));
        let raw_error = Arc::new(Mutex::new(None));
        let annotation_dropped_bytes = Arc::new(AtomicU64::new(0));
        let annotation_dropped_samples = Arc::new(AtomicU64::new(0));
        let dropped_heartbeats = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = mpsc::sync_channel(ENHANCEMENT_QUEUE_DEPTH);
        let monitor_dir = local_dir.join("monitor.segments");
        let resources_dir = local_dir.join("resources.segments");
        let enhancer_identity = identity.clone();
        let enhancer = thread::Builder::new()
            .name(format!("macluster-enhance-{job_id}"))
            .spawn(move || {
                enhance_logs(receiver, &monitor_dir, &resources_dir, enhancer_identity)
            })?;
        let pty_raw_log =
            match SegmentedLog::create(&local_dir.join("stdout.segments"), LOG_LIMIT_BYTES) {
                Ok(log) => log,
                Err(error) => {
                    drop(sender);
                    let _ = enhancer.join();
                    return Err(error);
                }
            };
        Ok(Self {
            identity,
            local_dir: local_dir.to_path_buf(),
            sender: Some(sender),
            collectors: Vec::new(),
            pty_raw_log: Some(pty_raw_log),
            enhancer: Some(enhancer),
            latest_sample,
            stdout_bytes,
            stderr_bytes,
            raw_error,
            annotation_dropped_bytes,
            annotation_dropped_samples,
            dropped_heartbeats,
            accounting: ProcessAccounting::default(),
            started_at: Instant::now(),
            runner_usage_at_start,
            runner_rss_baseline_bytes,
            runner_peak_rss_sampled_bytes: runner_rss_baseline_bytes,
        })
    }

    pub(super) fn initialize_sample(&mut self, process_group: u32) {
        let mut sample = self
            .accounting
            .sample(process_group, self.started_at.elapsed());
        self.record_runner_rss(&mut sample);
        if let Ok(mut latest) = self.latest_sample.lock() {
            *latest = Some(sample.clone());
        }
        self.send_event(
            EnhancementEvent::Sample(sample),
            &self.annotation_dropped_samples,
        );
    }

    pub(super) fn sample(&mut self, process_group: u32) {
        let mut sample = self
            .accounting
            .sample(process_group, self.started_at.elapsed());
        self.record_runner_rss(&mut sample);
        if let Ok(mut latest) = self.latest_sample.lock() {
            *latest = Some(sample.clone());
        }
        self.send_event(
            EnhancementEvent::Sample(sample),
            &self.annotation_dropped_samples,
        );
    }

    pub(super) fn output_bytes(&self) -> u64 {
        self.stdout_bytes
            .load(Ordering::Relaxed)
            .saturating_add(self.stderr_bytes.load(Ordering::Relaxed))
    }

    fn record_runner_rss(&mut self, sample: &mut ResourceSample) {
        let rss = current_process_rss_bytes();
        sample.runner_rss_bytes = rss;
        if let Some(rss) = rss {
            self.runner_peak_rss_sampled_bytes = Some(
                self.runner_peak_rss_sampled_bytes
                    .map_or(rss, |current| current.max(rss)),
            );
        }
    }

    pub(super) fn append_pty_output(&mut self, bytes: &[u8]) -> io::Result<()> {
        let result = self
            .pty_raw_log
            .as_mut()
            .ok_or_else(|| io::Error::other("PTY raw logger is unavailable"))?
            .append(bytes);
        if let Err(error) = result {
            store_first_error(&self.raw_error, error.to_string());
            return Err(error);
        }
        let offset = self
            .stdout_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        let sample = self
            .latest_sample
            .lock()
            .ok()
            .and_then(|value| value.clone());
        let event = EnhancementEvent::Output {
            stream: OutputStream::Pty,
            offset,
            bytes: bytes.to_vec(),
            sample,
        };
        match self.sender.as_ref().map(|sender| sender.try_send(event)) {
            Some(Ok(())) => {}
            Some(Err(TrySendError::Full(EnhancementEvent::Output { bytes, .. }))) => {
                self.annotation_dropped_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            Some(Err(TrySendError::Disconnected(_))) | None => {}
            Some(Err(TrySendError::Full(_))) => {}
        }
        Ok(())
    }

    pub(super) fn raw_error(&self) -> Option<String> {
        self.raw_error.lock().ok().and_then(|error| error.clone())
    }

    pub(super) fn heartbeat(&self) {
        let sample = self
            .latest_sample
            .lock()
            .ok()
            .and_then(|value| value.clone());
        self.send_event(
            EnhancementEvent::Heartbeat {
                observed_unix_ms: now_unix_ms(),
                sample,
            },
            &self.dropped_heartbeats,
        );
    }

    fn send_event(&self, event: EnhancementEvent, dropped: &AtomicU64) {
        let Some(sender) = &self.sender else {
            return;
        };
        match sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    pub(super) fn finish(mut self) -> io::Result<TaskLogCompletion> {
        let mut capture_stats = [None, None];
        for (index, collector) in std::mem::take(&mut self.collectors).into_iter().enumerate() {
            match collector.join() {
                Ok(Ok(stats)) => capture_stats[index] = Some(stats),
                Ok(Err(error)) => store_first_error(&self.raw_error, error.to_string()),
                Err(_) => {
                    store_first_error(&self.raw_error, "raw task log collector panicked".into())
                }
            }
        }
        if let Some(log) = self.pty_raw_log.take() {
            match log.flatten_to(&self.local_dir.join("stdout.log")) {
                Ok(stats) => capture_stats[0] = Some(stats),
                Err(error) => store_first_error(&self.raw_error, error.to_string()),
            }
        }

        if let Some(sender) = self.sender.take() {
            let _ = sender.send(EnhancementEvent::Stop);
        }
        let enhancement = match self.enhancer.take() {
            Some(enhancer) => enhancer.join().unwrap_or_else(|_| EnhancementResult {
                annotation_failed: Some("task log enhancer panicked".into()),
                monitor_discarded_bytes: 0,
                resources_discarded_bytes: 0,
            }),
            None => EnhancementResult {
                annotation_failed: Some("task log enhancer was not started".into()),
                monitor_discarded_bytes: 0,
                resources_discarded_bytes: 0,
            },
        };

        let stdout = capture_stats[0].unwrap_or_default();
        let stderr = capture_stats[1].unwrap_or_default();
        let accounting = self.accounting.summary(self.started_at.elapsed());
        let usage = current_process_usage();
        let summary = TaskResourceSummary {
            schema_version: 1,
            cluster_id: self.identity.cluster_id.clone(),
            share_id: self.identity.share_id.clone(),
            job_id: self.identity.job_id,
            start_token: self.identity.start_token.clone(),
            elapsed_seconds: self.started_at.elapsed().as_secs_f64(),
            cpu_time_seconds: accounting.cpu_time_seconds,
            memory_time_gib_seconds: accounting.memory_time_gib_seconds,
            memory_peak_sampled_bytes: accounting.memory_peak_sampled_bytes,
            covered_memory_seconds: accounting.covered_memory_seconds,
            missing_memory_seconds: accounting.missing_memory_seconds,
            cpu_quality: accounting.cpu_quality,
            memory_quality: accounting.memory_quality,
            samples: self.accounting.samples,
            missed_process_queries: self.accounting.missed_process_queries,
            stdout_retained_bytes: stdout.retained_bytes,
            stdout_discarded_bytes: stdout.discarded_bytes,
            stderr_retained_bytes: stderr.retained_bytes,
            stderr_discarded_bytes: stderr.discarded_bytes,
            monitor_discarded_bytes: enhancement.monitor_discarded_bytes,
            resources_discarded_bytes: enhancement.resources_discarded_bytes,
            annotation_dropped_bytes: self.annotation_dropped_bytes.load(Ordering::Relaxed),
            annotation_dropped_samples: self.annotation_dropped_samples.load(Ordering::Relaxed),
            dropped_heartbeats: self.dropped_heartbeats.load(Ordering::Relaxed),
            annotation_failed: enhancement.annotation_failed.clone(),
            raw_capture_failed: self.raw_error(),
            runner_cpu_user_seconds: (usage.user_seconds - self.runner_usage_at_start.user_seconds)
                .max(0.0),
            runner_cpu_system_seconds: (usage.system_seconds
                - self.runner_usage_at_start.system_seconds)
                .max(0.0),
            runner_rss_baseline_bytes: self.runner_rss_baseline_bytes,
            runner_peak_rss_sampled_bytes: self.runner_peak_rss_sampled_bytes,
            runner_peak_rss_sampled_growth_bytes: self.runner_rss_baseline_bytes.and_then(
                |baseline| {
                    self.runner_peak_rss_sampled_bytes
                        .map(|peak| peak.saturating_sub(baseline))
                },
            ),
        };
        let summary_result = serde_json::to_vec_pretty(&summary)
            .map_err(|error| io::Error::other(format!("could not encode task summary: {error}")))
            .and_then(|summary_bytes| {
                if summary_bytes.len() > 64 * 1024 {
                    return Err(io::Error::other("task resource summary exceeded 64 KiB"));
                }
                write_atomic(&self.local_dir.join("summary.json"), &summary_bytes)
            });
        let annotation_failed = match (enhancement.annotation_failed, summary_result) {
            (Some(reason), _) => Some(reason),
            (None, Err(error)) => Some(error.to_string()),
            (None, Ok(())) => None,
        };
        Ok(TaskLogCompletion {
            raw_capture_failed: self.raw_error(),
            annotation_failed,
        })
    }
}

fn spawn_collector<R: Read + Send + 'static>(
    mut reader: R,
    stream: OutputStream,
    segment_dir: PathBuf,
    flat_path: PathBuf,
    sender: SyncSender<EnhancementEvent>,
    latest_sample: Arc<Mutex<Option<ResourceSample>>>,
    byte_counter: Arc<AtomicU64>,
    raw_error: Arc<Mutex<Option<String>>>,
    annotation_dropped_bytes: Arc<AtomicU64>,
) -> io::Result<JoinHandle<io::Result<CaptureStats>>> {
    thread::Builder::new()
        .name(format!("macluster-capture-{}", stream.label()))
        .spawn(move || {
            let mut log = match SegmentedLog::create(&segment_dir, LOG_LIMIT_BYTES) {
                Ok(log) => log,
                Err(error) => {
                    store_first_error(&raw_error, error.to_string());
                    return Err(error);
                }
            };
            let mut buffer = [0_u8; IO_BUFFER_BYTES];
            let mut read_error = None;
            loop {
                let count = match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        read_error = Some(error);
                        break;
                    }
                };
                if let Err(error) = log.append(&buffer[..count]) {
                    store_first_error(&raw_error, error.to_string());
                    read_error = Some(error);
                    break;
                }
                let offset = byte_counter.fetch_add(count as u64, Ordering::Relaxed);
                let sample = latest_sample.lock().ok().and_then(|value| value.clone());
                let event = EnhancementEvent::Output {
                    stream,
                    offset,
                    bytes: buffer[..count].to_vec(),
                    sample,
                };
                match sender.try_send(event) {
                    Ok(()) => {}
                    Err(TrySendError::Full(EnhancementEvent::Output { bytes, .. })) => {
                        annotation_dropped_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => {}
                    Err(TrySendError::Full(_)) => {}
                }
            }
            let stats = CaptureStats {
                retained_bytes: log.retained_bytes,
                discarded_bytes: log.discarded_bytes,
            };
            let flatten_result = log.flatten_to(&flat_path);
            if let Some(error) = read_error {
                store_first_error(&raw_error, error.to_string());
                return Err(error);
            }
            flatten_result?;
            Ok(stats)
        })
}

fn store_first_error(slot: &Mutex<Option<String>>, message: String) {
    if let Ok(mut slot) = slot.lock()
        && slot.is_none()
    {
        *slot = Some(message);
    }
}

struct SegmentedLog {
    dir: PathBuf,
    segments: VecDeque<Segment>,
    current: Option<File>,
    current_path: Option<PathBuf>,
    current_len: usize,
    next_segment: u64,
    retained_bytes: u64,
    discarded_bytes: u64,
    limit: u64,
}

struct Segment {
    path: PathBuf,
    len: usize,
}

impl SegmentedLog {
    fn create(dir: &Path, limit: u64) -> io::Result<Self> {
        fs::create_dir(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            segments: VecDeque::new(),
            current: None,
            current_path: None,
            current_len: 0,
            next_segment: 0,
            retained_bytes: 0,
            discarded_bytes: 0,
            limit,
        })
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0;
        while offset < bytes.len() {
            if self.retained_bytes >= self.limit {
                self.discard_oldest()?;
            }
            if self.current.is_none() || self.current_len == SEGMENT_TARGET_BYTES {
                self.open_next_segment()?;
            }
            let segment_free = SEGMENT_TARGET_BYTES.saturating_sub(self.current_len);
            let total_free = self.limit.saturating_sub(self.retained_bytes) as usize;
            let count = (bytes.len() - offset).min(segment_free).min(total_free);
            if count == 0 {
                continue;
            }
            while self.retained_bytes.saturating_add(count as u64) > self.limit {
                self.discard_oldest()?;
            }
            let file = self
                .current
                .as_mut()
                .ok_or_else(|| io::Error::other("log segment writer is unavailable"))?;
            file.write_all(&bytes[offset..offset + count])?;
            self.current_len += count;
            self.retained_bytes = self.retained_bytes.saturating_add(count as u64);
            if let Some(segment) = self.segments.back_mut() {
                segment.len += count;
            }
            offset += count;
        }
        Ok(())
    }

    fn open_next_segment(&mut self) -> io::Result<()> {
        self.current.take();
        self.current_len = 0;
        self.next_segment = self.next_segment.saturating_add(1);
        let path = self.dir.join(format!("{:016}.log", self.next_segment));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        self.segments.push_back(Segment {
            path: path.clone(),
            len: 0,
        });
        self.current_path = Some(path);
        self.current = Some(file);
        Ok(())
    }

    fn discard_oldest(&mut self) -> io::Result<()> {
        let Some(oldest) = self.segments.pop_front() else {
            return Err(io::Error::other(
                "log retention budget has no removable segment",
            ));
        };
        if self.current_path.as_ref() == Some(&oldest.path) {
            self.current.take();
            self.current_path = None;
            self.current_len = 0;
        }
        self.retained_bytes = self.retained_bytes.saturating_sub(oldest.len as u64);
        self.discarded_bytes = self.discarded_bytes.saturating_add(oldest.len as u64);
        fs::remove_file(oldest.path)?;
        Ok(())
    }

    fn flatten_to(mut self, destination: &Path) -> io::Result<CaptureStats> {
        self.current.take();
        if destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("refusing to overwrite task log {}", destination.display()),
            ));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("task log destination has no parent"))?;
        let temp = parent.join(format!(
            ".{}.{}.{}.tmp",
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("task-log"),
            std::process::id(),
            Id128::random()
        ));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        let write_result: io::Result<()> = (|| {
            for segment in &self.segments {
                let mut input = File::open(&segment.path)?;
                io::copy(&mut input, &mut output)?;
            }
            output.sync_all()?;
            fs::rename(&temp, destination)?;
            File::open(parent)?.sync_all()?;
            fs::remove_dir_all(&self.dir)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        write_result?;
        Ok(CaptureStats {
            retained_bytes: self.retained_bytes,
            discarded_bytes: self.discarded_bytes,
        })
    }
}

fn enhance_logs(
    receiver: mpsc::Receiver<EnhancementEvent>,
    monitor_dir: &Path,
    resources_dir: &Path,
    identity: LogIdentity,
) -> EnhancementResult {
    let mut monitor = match SegmentedLog::create(monitor_dir, LOG_LIMIT_BYTES) {
        Ok(log) => Some(log),
        Err(_) => None,
    };
    let mut resources = match SegmentedLog::create(resources_dir, RESOURCE_LIMIT_BYTES) {
        Ok(log) => Some(log),
        Err(_) => None,
    };
    let mut annotation_failed = if monitor.is_none() || resources.is_none() {
        Some("could not create enhanced log storage".into())
    } else {
        None
    };
    let mut pending = [
        PendingLine::default(),
        PendingLine::default(),
        PendingLine::default(),
    ];
    let mut expected_offsets = [0_u64, 0_u64, 0_u64];

    while let Ok(event) = receiver.recv() {
        if matches!(event, EnhancementEvent::Stop) {
            break;
        }
        match event {
            EnhancementEvent::Output {
                stream,
                offset,
                bytes,
                sample,
            } => {
                let stream_index = stream_index(stream);
                if offset > expected_offsets[stream_index]
                    && let Some(log) = monitor.as_mut()
                {
                    let gap = offset - expected_offsets[stream_index];
                    let gap_line = format!(
                        "[{} / MEM N/A / CPU N/A] [missing] {gap} earlier {} output bytes were not annotated\n",
                        format_timestamp(now_unix_ms()),
                        stream.label()
                    );
                    if let Err(error) = log.append(gap_line.as_bytes()) {
                        annotation_failed.get_or_insert_with(|| error.to_string());
                        monitor = None;
                        continue;
                    }
                    let line = &mut pending[stream_index];
                    if !line.bytes.is_empty() {
                        if let Err(error) = emit_pending_line(log, stream, line, true) {
                            annotation_failed.get_or_insert_with(|| error.to_string());
                            monitor = None;
                        }
                    }
                }
                expected_offsets[stream_index] = offset.saturating_add(bytes.len() as u64);
                if let Some(log) = monitor.as_mut()
                    && let Err(error) =
                        process_output(log, stream, &bytes, sample, &mut pending[stream_index])
                {
                    annotation_failed.get_or_insert_with(|| error.to_string());
                    monitor = None;
                }
            }
            EnhancementEvent::Sample(sample) => {
                if let Some(log) = resources.as_mut() {
                    let record = ResourceLogRecord {
                        schema_version: 1,
                        cluster_id: &identity.cluster_id,
                        share_id: identity.share_id.as_deref(),
                        job_id: identity.job_id,
                        start_token: &identity.start_token,
                        sample: &sample,
                    };
                    if let Err(error) = append_json_line(log, &record) {
                        annotation_failed.get_or_insert_with(|| error.to_string());
                        resources = None;
                    }
                }
            }
            EnhancementEvent::Heartbeat {
                observed_unix_ms,
                sample,
            } => {
                if let Some(log) = monitor.as_mut()
                    && let Err(error) = append_monitor_line(
                        log,
                        sample.as_ref(),
                        observed_unix_ms,
                        "heartbeat",
                        b"no new output",
                        false,
                    )
                {
                    annotation_failed.get_or_insert_with(|| error.to_string());
                    monitor = None;
                }
            }
            EnhancementEvent::Stop => break,
        }
    }

    for (index, stream) in [
        OutputStream::Stdout,
        OutputStream::Stderr,
        OutputStream::Pty,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(log) = monitor.as_mut()
            && !pending[index].bytes.is_empty()
            && let Err(error) = emit_pending_line(log, stream, &mut pending[index], false)
        {
            annotation_failed.get_or_insert_with(|| error.to_string());
        }
    }

    let mut monitor_discarded_bytes = 0;
    if let Some(log) = monitor {
        monitor_discarded_bytes = log.discarded_bytes;
        if let Err(error) = log.flatten_to(&monitor_dir.with_file_name("monitor.log")) {
            annotation_failed.get_or_insert_with(|| error.to_string());
        }
    } else {
        let _ = create_empty_file(&monitor_dir.with_file_name("monitor.log"));
    }
    let mut resources_discarded_bytes = 0;
    if let Some(log) = resources {
        resources_discarded_bytes = log.discarded_bytes;
        if let Err(error) = log.flatten_to(&resources_dir.with_file_name("resources.jsonl")) {
            annotation_failed.get_or_insert_with(|| error.to_string());
        }
    } else {
        let _ = create_empty_file(&resources_dir.with_file_name("resources.jsonl"));
    }
    EnhancementResult {
        annotation_failed,
        monitor_discarded_bytes,
        resources_discarded_bytes,
    }
}

#[derive(Serialize)]
struct ResourceLogRecord<'a> {
    schema_version: u8,
    cluster_id: &'a str,
    share_id: Option<&'a str>,
    job_id: u64,
    start_token: &'a str,
    sample: &'a ResourceSample,
}

fn append_json_line(log: &mut SegmentedLog, value: &impl Serialize) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    log.append(&bytes)
}

#[derive(Default)]
struct PendingLine {
    bytes: Vec<u8>,
    sample: Option<ResourceSample>,
}

fn process_output(
    log: &mut SegmentedLog,
    stream: OutputStream,
    bytes: &[u8],
    sample: Option<ResourceSample>,
    pending: &mut PendingLine,
) -> io::Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let newline = bytes[cursor..].iter().position(|byte| *byte == b'\n');
        let end = newline.map_or(bytes.len(), |position| cursor + position + 1);
        let mut fragment = &bytes[cursor..end];
        let has_newline = newline.is_some();
        while !fragment.is_empty() {
            if pending.bytes.is_empty() {
                pending.sample = sample.clone();
            }
            let free = MAX_LINE_BYTES.saturating_sub(pending.bytes.len());
            let count = fragment.len().min(free);
            pending.bytes.extend_from_slice(&fragment[..count]);
            fragment = &fragment[count..];
            if pending.bytes.len() == MAX_LINE_BYTES && (!fragment.is_empty() || !has_newline) {
                emit_pending_line(log, stream, pending, true)?;
                pending.sample = sample.clone();
            }
        }
        if has_newline {
            if pending.bytes.last() == Some(&b'\n') {
                pending.bytes.pop();
            }
            emit_pending_line(log, stream, pending, false)?;
        }
        cursor = end;
    }
    Ok(())
}

fn emit_pending_line(
    log: &mut SegmentedLog,
    stream: OutputStream,
    pending: &mut PendingLine,
    continued: bool,
) -> io::Result<()> {
    let label = if continued {
        format!("{}:continued", stream.label())
    } else {
        stream.label().to_owned()
    };
    append_monitor_line(
        log,
        pending.sample.as_ref(),
        pending
            .sample
            .as_ref()
            .map_or_else(now_unix_ms, |sample| sample.observed_unix_ms),
        &label,
        &pending.bytes,
        true,
    )?;
    pending.bytes.clear();
    pending.sample = None;
    Ok(())
}

fn append_monitor_line(
    log: &mut SegmentedLog,
    sample: Option<&ResourceSample>,
    observed_unix_ms: u64,
    label: &str,
    content: &[u8],
    content_line: bool,
) -> io::Result<()> {
    let time = format_timestamp(observed_unix_ms);
    let memory = sample
        .and_then(|sample| sample.rss_bytes)
        .map(format_gib)
        .unwrap_or_else(|| "N/A".into());
    let cpu = sample
        .and_then(|sample| sample.cpu_percent)
        .map(|value| format!("{value:.1}%"))
        .unwrap_or_else(|| "N/A".into());
    let mut line = format!("[{time} / MEM {memory} / CPU {cpu}] [{label}] ");
    if content_line {
        line.push_str(&escape_log_bytes(content));
    } else {
        line.push_str(&String::from_utf8_lossy(content));
    }
    line.push('\n');
    log.append(line.as_bytes())
}

fn escape_log_bytes(mut bytes: &[u8]) -> String {
    let mut output = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                push_escaped_text(&mut output, text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    let text = std::str::from_utf8(&bytes[..valid]).unwrap_or_default();
                    push_escaped_text(&mut output, text);
                    bytes = &bytes[valid..];
                }
                let invalid = error
                    .error_len()
                    .unwrap_or(bytes.len())
                    .max(1)
                    .min(bytes.len());
                for byte in &bytes[..invalid] {
                    use std::fmt::Write as _;
                    let _ = write!(output, "\\x{byte:02x}");
                }
                bytes = &bytes[invalid..];
            }
        }
    }
    output
}

fn push_escaped_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\t' => output.push_str("\\t"),
            '\r' => output.push_str("\\r"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{{{:x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
}

struct ProcessIdentity {
    start_time: u64,
    cpu_time_ns: u64,
}

#[derive(Default)]
struct ProcessAccounting {
    previous: HashMap<i32, ProcessIdentity>,
    last_sample_at: Option<Instant>,
    last_rss: Option<u64>,
    cpu_time_ns: u128,
    memory_time_gib_seconds: f64,
    covered_memory_seconds: f64,
    missing_memory_seconds: f64,
    memory_peak_sampled_bytes: u64,
    samples: u64,
    missed_process_queries: u64,
    elapsed_seconds: f64,
    latest_cpu_percent: Option<f64>,
    latest_rss: Option<u64>,
    interval_ms: Option<u64>,
}

struct AccountingSummary {
    cpu_time_seconds: f64,
    memory_time_gib_seconds: f64,
    memory_peak_sampled_bytes: u64,
    covered_memory_seconds: f64,
    missing_memory_seconds: f64,
    cpu_quality: &'static str,
    memory_quality: &'static str,
}

impl ProcessAccounting {
    fn sample(&mut self, process_group: u32, elapsed: Duration) -> ResourceSample {
        self.elapsed_seconds = elapsed.as_secs_f64();
        self.samples = self.samples.saturating_add(1);
        let now = Instant::now();
        let observed_unix_ms = now_unix_ms();
        let sample = sample_process_group(process_group);
        let mut error = None;
        let mut delta_ns = 0_u128;
        let mut partial = false;
        match sample {
            Ok((observed, truncated)) => {
                partial |= truncated;
                let mut current = HashMap::with_capacity(observed.len().min(MAX_TRACKED_PROCESSES));
                let mut rss_total = 0_u64;
                for process in observed.into_iter().take(MAX_TRACKED_PROCESSES) {
                    rss_total = rss_total.saturating_add(process.rss_bytes);
                    if current.len() >= MAX_TRACKED_PROCESSES {
                        partial = true;
                        break;
                    }
                    if let Some(previous) = self.previous.get(&process.pid) {
                        if previous.start_time == process.start_time
                            && process.cpu_time_ns >= previous.cpu_time_ns
                        {
                            delta_ns = delta_ns.saturating_add(u128::from(
                                process.cpu_time_ns - previous.cpu_time_ns,
                            ));
                        } else {
                            partial = true;
                        }
                    } else {
                        // The first observation is a baseline; earlier CPU use is unknown.
                        partial = true;
                    }
                    current.insert(
                        process.pid,
                        ProcessIdentity {
                            start_time: process.start_time,
                            cpu_time_ns: process.cpu_time_ns,
                        },
                    );
                }
                if self.previous.keys().any(|pid| !current.contains_key(pid)) {
                    partial = true;
                }
                self.previous = current;
                let interval = self
                    .last_sample_at
                    .map(|last| now.saturating_duration_since(last));
                if let (Some(interval), Some(previous_rss)) = (interval, self.last_rss) {
                    let seconds = interval.as_secs_f64();
                    self.memory_time_gib_seconds +=
                        ((previous_rss as f64 + rss_total as f64) / 2.0 / 1_073_741_824.0)
                            * seconds;
                    self.covered_memory_seconds += seconds;
                    self.interval_ms = Some(interval.as_millis().min(u64::MAX as u128) as u64);
                    let cpu_percent = if interval.is_zero() {
                        None
                    } else {
                        Some(delta_ns as f64 / interval.as_nanos() as f64 * 100.0)
                    };
                    self.latest_cpu_percent = cpu_percent.filter(|value| value.is_finite());
                } else {
                    self.latest_cpu_percent = None;
                    if let Some(interval) = interval {
                        self.missing_memory_seconds += interval.as_secs_f64();
                    }
                    self.interval_ms = None;
                }
                self.cpu_time_ns = self.cpu_time_ns.saturating_add(delta_ns);
                self.memory_peak_sampled_bytes = self.memory_peak_sampled_bytes.max(rss_total);
                self.last_rss = Some(rss_total);
                self.latest_rss = Some(rss_total);
                self.last_sample_at = Some(now);
            }
            Err(reason) => {
                self.missed_process_queries = self.missed_process_queries.saturating_add(1);
                if let Some(interval) = self
                    .last_sample_at
                    .map(|last| now.saturating_duration_since(last))
                {
                    self.interval_ms = Some(interval.as_millis().min(u64::MAX as u128) as u64);
                    self.missing_memory_seconds += interval.as_secs_f64();
                } else {
                    self.interval_ms = None;
                }
                self.last_sample_at = Some(now);
                self.last_rss = None;
                self.previous.clear();
                self.latest_cpu_percent = None;
                self.latest_rss = None;
                error = Some(reason);
                partial = true;
            }
        }
        let (cpu_quality, memory_quality) = if error.is_some() {
            ("unavailable", "unavailable")
        } else if partial {
            ("partial", "partial")
        } else {
            ("partial", "partial")
        };
        ResourceSample {
            schema_version: 1,
            observed_unix_ms,
            elapsed_seconds: self.elapsed_seconds,
            interval_ms: self.interval_ms,
            cpu_percent: self.latest_cpu_percent,
            rss_bytes: self.latest_rss,
            runner_rss_bytes: None,
            cpu_time_seconds: self.cpu_time_ns as f64 / 1_000_000_000.0,
            memory_time_gib_seconds: self.memory_time_gib_seconds,
            memory_peak_sampled_bytes: self.memory_peak_sampled_bytes,
            covered_memory_seconds: self.covered_memory_seconds,
            missing_memory_seconds: self.missing_memory_seconds,
            process_count: self.previous.len(),
            missed_process_queries: self.missed_process_queries,
            cpu_quality,
            memory_quality,
            error,
        }
    }

    fn summary(&self, elapsed: Duration) -> AccountingSummary {
        let has_process_observation = self.samples > self.missed_process_queries;
        AccountingSummary {
            cpu_time_seconds: self.cpu_time_ns as f64 / 1_000_000_000.0,
            memory_time_gib_seconds: self.memory_time_gib_seconds,
            memory_peak_sampled_bytes: self.memory_peak_sampled_bytes,
            covered_memory_seconds: self.covered_memory_seconds,
            missing_memory_seconds: self
                .missing_memory_seconds
                .max(elapsed.as_secs_f64() - self.covered_memory_seconds),
            cpu_quality: if has_process_observation {
                "partial"
            } else {
                "unavailable"
            },
            memory_quality: if self.covered_memory_seconds > 0.0 {
                "partial"
            } else {
                "unavailable"
            },
        }
    }
}

struct ProcessObservation {
    pid: i32,
    start_time: u64,
    cpu_time_ns: u64,
    rss_bytes: u64,
}

#[cfg(target_vendor = "apple")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listpids(kind: u32, info: u32, buffer: *mut libc::c_void, size: i32) -> i32;
    fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut *mut libc::c_void) -> i32;
}

#[cfg(target_vendor = "apple")]
fn process_rusage_words(pid: i32) -> Option<[u64; 24]> {
    const RUSAGE_INFO_V2: i32 = 2;
    // Despite the void** C declaration, Apple's implementation writes the
    // result directly into the address supplied by the caller.
    let mut words = [0_u64; 24];
    let result = unsafe {
        proc_pid_rusage(
            pid,
            RUSAGE_INFO_V2,
            words.as_mut_ptr().cast::<*mut libc::c_void>(),
        )
    };
    (result == 0).then_some(words)
}

#[cfg(target_vendor = "apple")]
fn sample_process_group(process_group: u32) -> Result<(Vec<ProcessObservation>, bool), String> {
    const PROC_PGRP_ONLY: u32 = 2;
    let mut pids = vec![0_i32; MAX_TRACKED_PROCESSES + 1];
    let bytes = std::mem::size_of_val(pids.as_slice());
    let bytes = i32::try_from(bytes).map_err(|error| error.to_string())?;
    let listed = unsafe {
        proc_listpids(
            PROC_PGRP_ONLY,
            process_group,
            pids.as_mut_ptr().cast(),
            bytes,
        )
    };
    if listed < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let count = usize::try_from(listed).unwrap_or_default() / std::mem::size_of::<i32>();
    let truncated = listed == bytes || count > MAX_TRACKED_PROCESSES;
    let mut observations = Vec::with_capacity(count.min(MAX_TRACKED_PROCESSES));
    for pid in pids.into_iter().take(count.min(MAX_TRACKED_PROCESSES)) {
        if pid <= 0 {
            continue;
        }
        // rusage_info_v2 has a 152-byte stable v2 layout; words provide a
        // naturally aligned, bounded result buffer.
        let Some(words) = process_rusage_words(pid) else {
            continue;
        };
        // The stable v2 prefix is UUID, user ns, system ns, six counters,
        // resident bytes, physical footprint, then process start time.
        observations.push(ProcessObservation {
            pid,
            start_time: words[10],
            cpu_time_ns: words[2].saturating_add(words[3]),
            rss_bytes: words[8],
        });
    }
    Ok((observations, truncated))
}

#[cfg(not(target_vendor = "apple"))]
fn sample_process_group(_process_group: u32) -> Result<(Vec<ProcessObservation>, bool), String> {
    Err("task process accounting is available on macOS only".into())
}

#[derive(Clone, Copy, Default)]
struct ProcessUsage {
    user_seconds: f64,
    system_seconds: f64,
}

fn current_process_usage() -> ProcessUsage {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return ProcessUsage::default();
    }
    let timeval_seconds =
        |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
    ProcessUsage {
        user_seconds: timeval_seconds(usage.ru_utime),
        system_seconds: timeval_seconds(usage.ru_stime),
    }
}

#[cfg(target_vendor = "apple")]
fn current_process_rss_bytes() -> Option<u64> {
    let pid = i32::try_from(std::process::id()).ok()?;
    let words = process_rusage_words(pid)?;
    Some(words[8])
}

#[cfg(not(target_vendor = "apple"))]
fn current_process_rss_bytes() -> Option<u64> {
    None
}

fn format_gib(bytes: u64) -> String {
    format!("{:.2}GiB", bytes as f64 / 1_073_741_824.0)
}

fn stream_index(stream: OutputStream) -> usize {
    match stream {
        OutputStream::Stdout => 0,
        OutputStream::Stderr => 1,
        OutputStream::Pty => 2,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(target_vendor = "apple")]
fn format_timestamp(unix_ms: u64) -> String {
    let seconds = (unix_ms / 1000) as libc::time_t;
    let milliseconds = unix_ms % 1000;
    let mut broken_down = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::localtime_r(&seconds, &mut broken_down) }.is_null() {
        return format!("{unix_ms}");
    }
    let timestamp_format = b"%Y-%m-%dT%H:%M:%S\0";
    let timezone_format = b"%z\0";
    let mut timestamp = [0_i8; 32];
    let mut timezone = [0_i8; 8];
    let timestamp_len = unsafe {
        libc::strftime(
            timestamp.as_mut_ptr(),
            timestamp.len(),
            timestamp_format.as_ptr().cast(),
            &broken_down,
        )
    };
    let timezone_len = unsafe {
        libc::strftime(
            timezone.as_mut_ptr(),
            timezone.len(),
            timezone_format.as_ptr().cast(),
            &broken_down,
        )
    };
    if timestamp_len == 0 || timezone_len == 0 {
        return format!("{unix_ms}");
    }
    let timestamp = unsafe { std::ffi::CStr::from_ptr(timestamp.as_ptr()) }.to_string_lossy();
    let timezone = unsafe { std::ffi::CStr::from_ptr(timezone.as_ptr()) }.to_string_lossy();
    if timezone.len() == 5 {
        format!(
            "{timestamp}.{milliseconds:03}{}:{}",
            &timezone[..3],
            &timezone[3..]
        )
    } else {
        format!("{timestamp}.{milliseconds:03}{timezone}")
    }
}

#[cfg(not(target_vendor = "apple"))]
fn format_timestamp(unix_ms: u64) -> String {
    format!("{unix_ms}")
}

fn create_empty_file(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.sync_all()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("atomic file destination has no parent"))?;
    let temp = parent.join(format!(
        ".summary-{}-{}-{}.tmp",
        std::process::id(),
        now_unix_ms(),
        Id128::random()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, path))
        .and_then(|()| File::open(parent)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::current_process_rss_bytes;

    #[test]
    fn process_rusage_reports_nonzero_current_process_memory() {
        assert!(
            current_process_rss_bytes().is_some_and(|bytes| bytes > 0),
            "proc_pid_rusage should fill the aligned result buffer"
        );
    }
}
