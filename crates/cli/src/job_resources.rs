//! mjob task telemetry. JSON follow mode is newline-delimited records.
use crate::control_client::ControlClient;
use macluster_core::service::ServiceBinding;
use macluster_protocol::{
    control::{ControlCommand, ControlPayload},
    resources::{JobResourceSnapshot, TASK_RESOURCE_FEATURE},
};
use std::{
    io::{self, Write},
    path::Path,
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, (i32, String)>;

#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    pub job_id: u64,
    pub follow: bool,
    pub json: bool,
}
pub(crate) fn parse(args: &[String]) -> Result<Options> {
    let mut job_id = None;
    let mut follow = false;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--metrics" if job_id.is_none() => {
                index += 1;
                let id = args
                    .get(index)
                    .ok_or((2, "--metrics requires a job ID".into()))?
                    .parse::<u64>()
                    .map_err(|_| (2, "invalid metrics job ID".into()))?;
                if id == 0 {
                    return Err((2, "job ID must be positive".into()));
                }
                job_id = Some(id);
            }
            "--follow" if !follow => follow = true,
            "--json" if !json => json = true,
            other => {
                return Err((
                    2,
                    format!("unsupported or conflicting job metrics argument '{other}'"),
                ));
            }
        }
        index += 1;
    }
    Ok(Options {
        job_id: job_id.ok_or((2, "--metrics requires a job ID".into()))?,
        follow,
        json,
    })
}
pub(crate) fn run(config: &Path, state: &Path, options: Options) -> Result<()> {
    let binding = ServiceBinding::load(config, state).map_err(|e| (1, e.to_string()))?;
    let mut client=ControlClient::connect(&binding,Duration::from_secs(2)).map_err(|e|(1,format!("task resource subscriptions need a running controller: {e}; run `macluster controller start`")))?;
    if !client
        .hello()
        .capabilities
        .iter()
        .any(|c| c == TASK_RESOURCE_FEATURE)
    {
        return Err((1,"running controller lacks task.resources.v1; update/restart it with this macluster build when idle, then retry".into()));
    }
    if !matches!(
        client
            .request(ControlCommand::SubscribeJobResources {
                job_id: options.job_id
            })
            .map_err(|e| (1, e.to_string()))?,
        ControlPayload::JobResourcesSubscribed
    ) {
        return Err((1, "unexpected job resource subscription response".into()));
    }
    let mut output = io::stdout().lock();
    let mut previous = None;
    let deadline = Instant::now() + Duration::from_secs(12);
    let result = (|| {
        loop {
            let snapshot = match client
                .request(ControlCommand::JobResourceSnapshot {
                    job_id: options.job_id,
                })
                .map_err(|e| (1, format!("resource subscription interrupted: {e}")))?
            {
                ControlPayload::JobResourceSnapshot(snapshot) => snapshot,
                _ => return Err((1, "unexpected job resource snapshot response".into())),
            };
            let finished = snapshot.state.is_terminal();
            let key = (
                snapshot.start_token,
                snapshot.state,
                snapshot.sample.as_ref().map(|s| s.observed_unix_ms),
                snapshot.error.clone(),
                snapshot.stale,
            );
            let ready = options.follow
                || finished
                || snapshot.sample.is_some()
                || snapshot.state == macluster_protocol::types::JobState::Pending
                || Instant::now() >= deadline;
            if ready && previous.as_ref() != Some(&key) {
                let line = if options.json {
                    serde_json::to_string(&snapshot).map_err(|e| (1, e.to_string()))?
                } else {
                    format_snapshot(&snapshot)
                };
                if let Err(error) = writeln!(output, "{line}").and_then(|_| output.flush()) {
                    if error.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err((1, error.to_string()));
                }
                previous = Some(key);
            }
            if finished || (!options.follow && ready) {
                break;
            }
            thread::sleep(Duration::from_millis(if options.follow {
                1000
            } else {
                100
            }));
        }
        Ok(())
    })();
    let _ = client.request(ControlCommand::UnsubscribeJobResources);
    result
}
fn format_snapshot(snapshot: &JobResourceSnapshot) -> String {
    let sample = snapshot.sample.as_ref();
    let cpu = sample
        .and_then(|s| s.cpu_percent)
        .map_or("N/A".into(), |n| format!("{n:.1}"));
    let mem = sample.and_then(|s| s.rss_bytes).map_or("N/A".into(), |n| {
        format!("{:.3}", n as f64 / 1_073_741_824.0)
    });
    let cpu_time = sample.map_or("N/A".into(), |s| format!("{:.3}", s.cpu_time_seconds));
    let age = snapshot
        .age_ms
        .map_or("N/A".into(), |n| format!("{:.1}s", n as f64 / 1000.0));
    let quality = sample.map_or("waiting", |s| s.coverage.as_str());
    format!(
        "JOB {}  {:?}  NODE {}  CPU% {cpu}  RSS(GiB) {mem}  CPU(s) {cpu_time}  AGE {age}  {quality}{}{}",
        snapshot.job_id,
        snapshot.state,
        snapshot.node_id.as_ref().map_or("-", |n| n.as_str()),
        if snapshot.stale { " [stale]" } else { "" },
        snapshot
            .error
            .as_ref()
            .map_or(String::new(), |e| format!("  {e}"))
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metrics_options_do_not_mix_with_job_or_log_queries() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            parse(&args("--metrics 42 --follow --json")).unwrap(),
            Options {
                job_id: 42,
                follow: true,
                json: true
            }
        );
        for s in [
            "--metrics",
            "--metrics 0",
            "--metrics 1 --log 1",
            "--metrics 1 --all",
            "--metrics 1 --metrics 2",
            "--metrics 1 2",
        ] {
            assert!(parse(&args(s)).is_err(), "{s}");
        }
    }
}
