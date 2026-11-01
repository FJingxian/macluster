//! Bounded, execution-fenced task observations. No shell/top and no history.
use crate::runner::task_logs::{ProcessObservation, sample_process_group};
use crate::{ProcessIdentity, StateLock, protocol_failed, read_store, validate_receipt};
use macluster_protocol::{
    identifiers::StartToken,
    resources::{TASK_RESOURCE_INTERVAL_MS, TaskResourceSample},
    types::{ControllerEpoch, ProtocolError},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[derive(Serialize, Deserialize)]
struct Cache {
    token: String,
    monotonic_ms: u64,
    processes: Vec<ProcessObservation>,
    sample: TaskResourceSample,
}
#[derive(Deserialize)]
struct Published {
    start_token: String,
    sample: TaskResourceSample,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let mut raw = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut raw).ok()?;
    if raw.len() > 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&raw).ok()
}
fn write_json(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    let temp = path.with_extension(format!("{}.next", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn publish_verbose(dir: &Path, token: &str, sample: &impl Serialize) {
    // Telemetry failure must not fail or delay the workload. Output-driven
    // verbose samples overwrite one bounded local file at most twice per
    // second, with a five-second idle fallback; this is never a shared NFS write.
    let _ = write_json(
        &dir.join("resource-verbose.json"),
        &serde_json::json!({"start_token":token,"sample":sample}),
    );
}
fn monotonic_ms() -> u64 {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(time.tv_nsec as u64 / 1_000_000)
}
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
fn observe(
    previous: Option<&Cache>,
    processes: Vec<ProcessObservation>,
    truncated: bool,
    mono: u64,
    wall: u64,
    token: String,
) -> Cache {
    // An idle/disconnected interval is not a continuously observed accounting
    // window. Re-establish a baseline instead of integrating a long gap.
    let previous = previous.filter(|old| {
        mono.checked_sub(old.monotonic_ms)
            .is_some_and(|gap| gap <= TASK_RESOURCE_INTERVAL_MS * 3)
    });
    let rss = processes
        .iter()
        .fold(0u64, |sum, p| sum.saturating_add(p.rss_bytes));
    let interval_ms = previous
        .and_then(|p| mono.checked_sub(p.monotonic_ms))
        .filter(|ms| *ms > 0);
    let mut delta_ns = 0u128;
    let mut partial = truncated;
    if let Some(old) = previous {
        let old_by_pid = old
            .processes
            .iter()
            .map(|p| (p.pid, p))
            .collect::<std::collections::HashMap<_, _>>();
        for p in &processes {
            match old_by_pid.get(&p.pid) {
                Some(before)
                    if before.start_time == p.start_time && p.cpu_time_ns >= before.cpu_time_ns =>
                {
                    delta_ns =
                        delta_ns.saturating_add(u128::from(p.cpu_time_ns - before.cpu_time_ns))
                }
                _ => partial = true,
            }
        }
        let current = processes
            .iter()
            .map(|p| (p.pid, p.start_time))
            .collect::<std::collections::HashSet<_>>();
        if old
            .processes
            .iter()
            .any(|p| !current.contains(&(p.pid, p.start_time)))
        {
            partial = true;
        }
    }
    let cpu = interval_ms.map(|ms| delta_ns as f64 / (ms as f64 * 1_000_000.0) * 100.0);
    let memory_time = previous.map_or(0.0, |old| {
        old.sample.memory_time_gib_seconds
            + interval_ms.map_or(0.0, |ms| {
                ((old.sample.rss_bytes.unwrap_or(0) as f64 + rss as f64) / 2.0 / 1_073_741_824.0)
                    * (ms as f64 / 1000.0)
            })
    });
    let sample = TaskResourceSample {
        schema_version: 1,
        observed_unix_ms: wall,
        age_ms: 0,
        interval_ms,
        cpu_percent: cpu,
        rss_bytes: Some(rss),
        cpu_time_seconds: previous.map_or(0.0, |old| old.sample.cpu_time_seconds)
            + delta_ns as f64 / 1_000_000_000.0,
        memory_time_gib_seconds: memory_time,
        memory_peak_sampled_bytes: previous
            .map_or(rss, |old| old.sample.memory_peak_sampled_bytes.max(rss)),
        process_count: processes.len(),
        source: "on_demand".into(),
        coverage: if cpu.is_none() {
            "baseline"
        } else if partial {
            "partial"
        } else {
            "observed_intervals"
        }
        .into(),
        error: None,
    };
    Cache {
        token,
        monotonic_ms: mono,
        processes,
        sample,
    }
}

pub(crate) fn query(
    state_dir: &Path,
    controller: ControllerEpoch,
    token: StartToken,
    job_id: u64,
    node_id: &str,
) -> Result<TaskResourceSample, ProtocolError> {
    let _guard = StateLock::acquire_existing(state_dir).map_err(protocol_failed)?;
    let store = read_store(state_dir).map_err(protocol_failed)?;
    let record = store.active.as_ref().ok_or(ProtocolError::NotFound)?;
    validate_receipt(record, controller, token, job_id, node_id)?;
    if record.boot_id != crate::boot_id() {
        return Err(ProtocolError::Conflict);
    }
    let dir = state_dir.join("jobs").join(job_id.to_string());
    let wall = wall_ms();
    if record
        .spec
        .env
        .get(macluster_protocol::types::VERBOSE_TASK_LOG_ENV)
        .is_some_and(|value| value == "1")
        && let Some(published) = read_json::<Published>(&dir.join("resource-verbose.json"))
    {
        if published.start_token == token.to_string()
            && wall
                .checked_sub(published.sample.observed_unix_ms)
                .is_some_and(|age| age <= TASK_RESOURCE_INTERVAL_MS * 2)
        {
            let mut sample = published.sample;
            sample.age_ms = wall.saturating_sub(sample.observed_unix_ms);
            sample.source = "verbose_log_sampler".into();
            sample.coverage = "partial_process_group".into();
            return Ok(sample);
        }
    }
    let cache_path = dir.join("resource-cache.json");
    let previous = read_json::<Cache>(&cache_path).filter(|c| c.token == token.to_string());
    let mono = monotonic_ms();
    if record.terminal() {
        return previous.map(|c| c.sample).ok_or(ProtocolError::NotFound);
    }
    let pid = record.child_pid.ok_or(ProtocolError::Busy)?;
    let start = record
        .child_start_id
        .as_deref()
        .ok_or(ProtocolError::Busy)?;
    if crate::process_identity(pid, start) != ProcessIdentity::Match {
        return Err(ProtocolError::Conflict);
    }
    if let Some(cached) = &previous {
        if mono
            .checked_sub(cached.monotonic_ms)
            .is_some_and(|age| age < TASK_RESOURCE_INTERVAL_MS)
        {
            let mut sample = cached.sample.clone();
            sample.age_ms = mono.saturating_sub(cached.monotonic_ms);
            return Ok(sample);
        }
    }
    let (processes, truncated) = sample_process_group(pid).map_err(ProtocolError::Failed)?;
    if crate::process_identity(pid, start) != ProcessIdentity::Match {
        return Err(ProtocolError::Conflict);
    }
    let cache = observe(
        previous.as_ref(),
        processes,
        truncated,
        mono,
        wall,
        token.to_string(),
    );
    write_json(&cache_path, &cache).map_err(protocol_failed)?;
    Ok(cache.sample)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(start: u64, cpu: u64) -> ProcessObservation {
        ProcessObservation {
            pid: 10,
            start_time: start,
            cpu_time_ns: cpu,
            rss_bytes: 1024,
        }
    }
    #[test]
    fn first_observation_has_no_cpu_and_pid_reuse_is_not_charged() {
        let first = observe(
            None,
            vec![p(1, 9_000_000_000)],
            false,
            1000,
            1000,
            "token".into(),
        );
        assert_eq!(first.sample.cpu_percent, None);
        let second = observe(
            Some(&first),
            vec![p(1, 14_000_000_000)],
            false,
            6000,
            6000,
            "token".into(),
        );
        assert_eq!(second.sample.cpu_percent, Some(100.0));
        assert_eq!(second.sample.cpu_time_seconds, 5.0);
        let reused = observe(
            Some(&second),
            vec![p(2, 99_000_000_000)],
            false,
            11000,
            11000,
            "token".into(),
        );
        assert_eq!(reused.sample.cpu_time_seconds, 5.0);
        assert_eq!(reused.sample.coverage, "partial");
        let resumed = observe(
            Some(&second),
            vec![p(1, 99_000_000_000)],
            false,
            100_000,
            100_000,
            "token".into(),
        );
        assert_eq!(resumed.sample.cpu_percent, None);
        assert_eq!(resumed.sample.cpu_time_seconds, 0.0);
        assert_eq!(resumed.sample.coverage, "baseline");
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod live_tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn fenced_query_reuses_verbose_and_native_caches_without_top() {
        let (root, state, token, _) =
            crate::tests::status_fixture("resources", &crate::boot_id(), None, false);
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let start = crate::wait_for_process_start_identity(pid).unwrap();
        let mut store = read_store(&state).unwrap();
        let record = store.active.as_mut().unwrap();
        record.spec.env.insert(
            macluster_protocol::types::VERBOSE_TASK_LOG_ENV.into(),
            "1".into(),
        );
        record.child_pid = Some(pid);
        record.child_start_id = Some(start);
        let controller = record.controller;
        crate::write_store(&state, &store).unwrap();
        let began = std::time::Instant::now();
        let first = query(&state, controller, token, 1, "mini01-a").unwrap();
        eprintln!("task resource baseline query: {:?}", began.elapsed());
        assert!(first.rss_bytes.unwrap() > 0);
        assert_eq!(first.cpu_percent, None);
        let cached = query(&state, controller, token, 1, "mini01-a").unwrap();
        assert_eq!(first.observed_unix_ms, cached.observed_unix_ms);
        std::thread::sleep(std::time::Duration::from_millis(5050));
        let interval = query(&state, controller, token, 1, "mini01-a").unwrap();
        assert!(
            interval
                .cpu_percent
                .is_some_and(|cpu| cpu.is_finite() && cpu >= 0.0)
        );
        assert!(
            interval
                .interval_ms
                .is_some_and(|ms| ms >= TASK_RESOURCE_INTERVAL_MS)
        );
        assert!(
            query(
                &state,
                controller,
                StartToken(macluster_protocol::identifiers::Id128::random()),
                1,
                "mini01-a"
            )
            .is_err()
        );
        assert!(query(&state, controller, token, 2, "mini01-a").is_err());
        assert!(query(&state, controller, token, 1, "other-node").is_err());
        let mut foreign = controller;
        foreign.controller_uuid = macluster_protocol::identifiers::ControllerUuid(
            macluster_protocol::identifiers::Id128::random(),
        );
        assert!(query(&state, foreign, token, 1, "mini01-a").is_err());
        let mut verbose = first.clone();
        verbose.cpu_percent = Some(42.0);
        verbose.observed_unix_ms = wall_ms();
        publish_verbose(&state.join("jobs/1"), &token.to_string(), &verbose);
        let reused = query(&state, controller, token, 1, "mini01-a").unwrap();
        assert_eq!(reused.cpu_percent, Some(42.0));
        assert_eq!(reused.source, "verbose_log_sampler");
        publish_verbose(&state.join("jobs/1"), "wrong-token", &verbose);
        assert_eq!(
            query(&state, controller, token, 1, "mini01-a")
                .unwrap()
                .cpu_percent,
            interval.cpu_percent
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(query(&state, controller, token, 1, "mini01-a").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
