use std::{
    collections::BTreeMap,
    io::{self, Read},
    process::{self, Child},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::config::{NodeConfig, Transport};

const PROCESS_TABLE_MARKER: &str = "__MACLUSTER_PS_NAMES__";
const PROCESS_COMMAND: &str = "top_output=$(/usr/bin/top -l 2 -n 32 -s 1 -stats pid,cpu,mem,time,command -o cpu) || exit $?; printf '%s\\n' \"$top_output\"; printf '\\n__MACLUSTER_PS_NAMES__\\n'; pids=$(printf '%s\\n' \"$top_output\" | /usr/bin/awk '/^[[:space:]]*PID[[:space:]]+%CPU[[:space:]]+MEM[[:space:]]+TIME[[:space:]]+COMMAND/ { table=1; count=0; next } table && $1 ~ /^[0-9]+$/ { pids[++count]=$1 } END { for (i=1; i<=count; i++) { if (i > 1) printf \",\"; printf \"%s\", pids[i] } }'); if [ -n \"$pids\" ]; then /bin/ps -p \"$pids\" -o pid=,ucomm=; fi";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_STALE_AFTER: Duration = Duration::from_secs(10);
const MAX_PROCESS_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ProcessInfo {
    pub pid: u32,
    pub cpu_percent: f64,
    pub memory: String,
    pub cpu_time: String,
    pub command: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum ProcessSort {
    #[default]
    Cpu,
    Memory,
}

pub(super) fn sort_processes(rows: &mut [ProcessInfo], sort: ProcessSort) {
    rows.sort_by(|left, right| {
        let order = match sort {
            ProcessSort::Cpu => compare_cpu_descending(left.cpu_percent, right.cpu_percent),
            ProcessSort::Memory => {
                compare_optional_descending(memory_bytes(&left.memory), memory_bytes(&right.memory))
            }
        };
        order.then_with(|| left.pid.cmp(&right.pid))
    });
}

fn valid_cpu(value: f64) -> Option<f64> {
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn compare_cpu_descending(left: f64, right: f64) -> std::cmp::Ordering {
    match (valid_cpu(left), valid_cpu(right)) {
        (Some(left), Some(right)) => right.total_cmp(&left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn compare_optional_descending<T: Ord>(left: Option<T>, right: Option<T>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => right.cmp(&left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn memory_bytes(value: &str) -> Option<u64> {
    let value = value.trim().trim_end_matches(|ch| ch == '+' || ch == '-');
    let unit_start = value
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit() && *ch != '.' && *ch != ',')
        .map_or(value.len(), |(index, _)| index);
    let number = value[..unit_start].replace(',', "").parse::<f64>().ok()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    let unit = value[unit_start..].trim().to_ascii_uppercase();
    let multiplier = match unit.as_str() {
        "" | "B" => 1.0,
        "K" | "KB" => 1024.0,
        "M" | "MB" => 1024.0_f64.powi(2),
        "G" | "GB" => 1024.0_f64.powi(3),
        "T" | "TB" => 1024.0_f64.powi(4),
        "P" | "PB" => 1024.0_f64.powi(5),
        _ => return None,
    };
    let bytes = number * multiplier;
    (bytes.is_finite() && bytes <= u64::MAX as f64).then_some(bytes.round() as u64)
}

#[derive(Clone, Debug, Default)]
pub(super) enum ProcessView {
    #[default]
    Loading,
    Unavailable {
        reason: String,
    },
    Available {
        rows: Vec<ProcessInfo>,
        age: Duration,
        stale: bool,
        warning: Option<String>,
    },
}

#[derive(Default)]
pub(super) struct ProcessCache {
    last_success: Option<(Vec<ProcessInfo>, Instant)>,
    last_error: Option<String>,
}

impl ProcessCache {
    pub fn apply_success(&mut self, rows: Vec<ProcessInfo>, at: Instant) {
        self.last_success = Some((rows, at));
        self.last_error = None;
    }

    pub fn apply_error(&mut self, reason: String) {
        self.last_error = Some(reason);
    }

    pub fn view_at(&self, now: Instant) -> ProcessView {
        if let Some((rows, sampled_at)) = &self.last_success {
            let age = now.saturating_duration_since(*sampled_at);
            return ProcessView::Available {
                rows: rows.clone(),
                age,
                stale: age >= PROCESS_STALE_AFTER,
                warning: self.last_error.clone(),
            };
        }
        match &self.last_error {
            Some(reason) => ProcessView::Unavailable {
                reason: reason.clone(),
            },
            None => ProcessView::Loading,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum ProcessTarget {
    Local,
    Ssh {
        node_id: String,
        namespace: String,
        node: NodeConfig,
    },
}

impl ProcessTarget {
    pub fn for_node(node_id: &str, namespace: &str, node: &NodeConfig) -> Self {
        match node.transport {
            Transport::Local => Self::Local,
            Transport::Ssh => Self::Ssh {
                node_id: node_id.to_owned(),
                namespace: namespace.to_owned(),
                node: node.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub(super) struct ProcessResult {
    pub id: String,
    pub received_at: Instant,
    pub result: Result<Vec<ProcessInfo>, String>,
}

pub(super) struct ProcessSampler {
    result_sender: Sender<ProcessResult>,
    result_receiver: Receiver<ProcessResult>,
    in_flight: Option<String>,
    stop: Arc<AtomicBool>,
}

impl ProcessSampler {
    pub fn new() -> Self {
        let (result_sender, result_receiver) = mpsc::channel();
        Self {
            result_sender,
            result_receiver,
            in_flight: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request(&mut self, id: impl Into<String>, target: ProcessTarget) -> bool {
        if self.in_flight.is_some() {
            return false;
        }
        let id = id.into();
        let sender = self.result_sender.clone();
        let stop = Arc::clone(&self.stop);
        self.in_flight = Some(id.clone());
        thread::spawn(move || {
            let result = sample_target(&target, &stop);
            let _ = sender.send(ProcessResult {
                id,
                received_at: Instant::now(),
                result,
            });
        });
        true
    }

    pub fn is_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    pub fn poll(&mut self) -> Vec<ProcessResult> {
        let mut completed = Vec::new();
        loop {
            match self.result_receiver.try_recv() {
                Ok(result) => {
                    if self.in_flight.as_deref() == Some(result.id.as_str()) {
                        self.in_flight = None;
                    }
                    completed.push(result);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        completed
    }
}

impl Drop for ProcessSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn sample_target(target: &ProcessTarget, stop: &AtomicBool) -> Result<Vec<ProcessInfo>, String> {
    if stop.load(Ordering::SeqCst) {
        return Err("process sample cancelled".into());
    }
    let output = match target {
        ProcessTarget::Local => run_local(stop)?,
        ProcessTarget::Ssh {
            node_id,
            namespace,
            node,
        } => run_remote(node_id, namespace, node, stop)?,
    };
    parse_top_processes(&output)
}

fn run_local(stop: &AtomicBool) -> Result<String, String> {
    let mut child = process::Command::new("/bin/sh")
        .args(["-c", PROCESS_COMMAND])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start local top/ps: {error}"))?;
    collect_child(&mut child, PROCESS_TIMEOUT, stop, "local process sample")
}

fn run_remote(
    node_id: &str,
    namespace: &str,
    node: &NodeConfig,
    stop: &AtomicBool,
) -> Result<String, String> {
    let mut command = process::Command::new("/usr/bin/ssh");
    command.args([
        "-T",
        "-oLogLevel=ERROR",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=4",
        "-oConnectionAttempts=1",
    ]);
    node.add_ssh_identity_args(&mut command);
    super::ssh::add_control_args(namespace, node_id, node, &mut command);
    let mut child = command
        .arg(&node.host)
        .arg(PROCESS_COMMAND)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start ssh process sample: {error}"))?;
    collect_child(&mut child, PROCESS_TIMEOUT, stop, "remote process sample")
}

fn collect_child(
    child: &mut Child,
    timeout: Duration,
    stop: &AtomicBool,
    description: &str,
) -> Result<String, String> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{description}: stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{description}: stderr pipe was unavailable"))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    match wait_child(child, timeout, stop) {
        Ok(ChildWait::Exited) => {}
        Ok(ChildWait::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!(
                "{description} timed out after {}s",
                timeout.as_secs()
            ));
        }
        Ok(ChildWait::Cancelled) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("{description} cancelled"));
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("{description}: {error}"));
        }
    }
    let output = stdout_reader
        .join()
        .map_err(|_| format!("{description}: stdout reader stopped unexpectedly"))?
        .map_err(|error| format!("{description}: could not read stdout: {error}"))?;
    let error_output = stderr_reader
        .join()
        .map_err(|_| format!("{description}: stderr reader stopped unexpectedly"))?
        .map_err(|error| format!("{description}: could not read stderr: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("{description}: could not collect exit status: {error}"))?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&error_output).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("{description} exited with {status}")
        } else {
            detail
        });
    }
    String::from_utf8(output)
        .map_err(|error| format!("{description} returned invalid UTF-8: {error}"))
}

fn read_bounded(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(MAX_PROCESS_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)?;
    if output.len() as u64 > MAX_PROCESS_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process sample output exceeded 4 MiB",
        ));
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWait {
    Exited,
    Timeout,
    Cancelled,
}

fn wait_child(
    child: &mut Child,
    timeout: Duration,
    stop: &AtomicBool,
) -> Result<ChildWait, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("could not wait for child: {error}"))?
            .is_some()
        {
            return Ok(ChildWait::Exited);
        }
        if stop.load(Ordering::SeqCst) {
            return Ok(ChildWait::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(ChildWait::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn parse_top_processes(input: &str) -> Result<Vec<ProcessInfo>, String> {
    let (top_output, process_output) = input
        .split_once(PROCESS_TABLE_MARKER)
        .ok_or_else(|| "process sample is missing its ps name table".to_owned())?;
    let lines: Vec<_> = top_output.lines().collect();
    let table_start = lines
        .iter()
        .rposition(|line| is_top_header(line))
        .ok_or_else(|| "could not find the process table in top output".to_owned())?;
    let names = parse_process_names(process_output);
    let mut rows = Vec::new();
    for line in &lines[table_start + 1..] {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (Ok(pid), Ok(cpu_percent)) = (fields[0].parse::<u32>(), fields[1].parse::<f64>())
        else {
            continue;
        };
        if !cpu_percent.is_finite() || cpu_percent < 0.0 {
            continue;
        }
        let top_command = fields.get(4..).unwrap_or_default().join(" ");
        let command = if top_command.is_empty() || top_command == "?" {
            names.get(&pid).cloned().unwrap_or_else(|| "unknown".into())
        } else {
            top_command
        };
        rows.push(ProcessInfo {
            pid,
            cpu_percent,
            memory: fields[2].to_owned(),
            cpu_time: fields[3].to_owned(),
            command,
        });
    }
    rows.sort_by(|left, right| {
        right
            .cpu_percent
            .total_cmp(&left.cpu_percent)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    Ok(rows)
}

fn is_top_header(line: &str) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    fields.starts_with(&["PID", "%CPU", "MEM", "TIME", "COMMAND"])
}

fn parse_process_names(input: &str) -> BTreeMap<u32, String> {
    input
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim_start().splitn(2, char::is_whitespace);
            let pid = fields.next()?.parse::<u32>().ok()?;
            let name = fields.next()?.trim();
            (!name.is_empty()).then(|| (pid, name.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        PROCESS_COMMAND, ProcessCache, ProcessInfo, ProcessSort, ProcessView, parse_top_processes,
        sort_processes,
    };
    use std::time::{Duration, Instant};

    const SAMPLE: &str = "top first sample\nPID    %CPU MEM   TIME     COMMAND\n11 90.0 2M 00:00.01 first_low\n12 2.0 4M 00:00.02 first_busy\nProcesses: 8 total\nPID    %CPU MEM   TIME     COMMAND\n11 1.5 2M 00:00.03 top_low_worker\n12 82.0 4M 00:00.04 top_busy_worker (Renderer)\n13 35.0 1M 00:00.02 top_middle_worker\n__MACLUSTER_PS_NAMES__\n   11 low_worker\n   12 busy_worker\n   13 middle_worker\n";

    #[test]
    fn process_name_lookup_is_limited_to_top_rows() {
        assert!(PROCESS_COMMAND.contains("/bin/ps -p \"$pids\" -o pid=,ucomm="));
        assert!(!PROCESS_COMMAND.contains("/bin/ps -axo pid=,ucomm="));
        assert!(PROCESS_COMMAND.contains("{ table=1; count=0; next }"));
    }

    #[test]
    fn parses_the_second_top_sample_joins_names_and_sorts_by_cpu() {
        let rows = parse_top_processes(SAMPLE).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, 12);
        assert_eq!(rows[0].cpu_percent, 82.0);
        assert_eq!(rows[0].command, "top_busy_worker (Renderer)");
        assert_eq!(rows[0].memory, "4M");
        assert_eq!(rows[0].cpu_time, "00:00.04");
        assert_eq!(rows[1].command, "top_middle_worker");
        assert_eq!(rows[2].pid, 11);
    }

    #[test]
    fn skips_malformed_rows_and_uses_unknown_when_both_name_sources_are_empty() {
        let input = "PID %CPU MEM TIME COMMAND\ninvalid row\n31 nan 1M 00:00 bad_sample\n32 4.0 1M 00:01\n__MACLUSTER_PS_NAMES__\n";
        let rows = parse_top_processes(input).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 32);
        assert_eq!(rows[0].command, "unknown");
    }

    #[test]
    fn uses_ps_name_when_the_top_command_column_is_empty() {
        let input = "PID %CPU MEM TIME COMMAND\n32 4.0 1M 00:01\n__MACLUSTER_PS_NAMES__\n   32 ps_fallback\n";
        let rows = parse_top_processes(input).unwrap();
        assert_eq!(rows[0].command, "ps_fallback");
    }

    #[test]
    fn uses_top_command_when_pid_is_missing_from_the_later_ps_snapshot() {
        let input = "PID %CPU MEM TIME COMMAND\n0 20.5 604M 01:57:09 kernel_task\n42 6.6 4224K 00:00.18 short_worker\n__MACLUSTER_PS_NAMES__\n";
        let rows = parse_top_processes(input).unwrap();
        assert_eq!(rows[0].command, "kernel_task");
        assert_eq!(rows[1].command, "short_worker");
    }

    #[test]
    fn memory_sort_compares_mixed_units_descending_and_puts_unknown_last() {
        let mut rows = vec![
            process(10, 1.0, "4096K+"),
            process(11, 1.0, "512M-"),
            process(12, 1.0, "2G"),
            process(13, 1.0, "unknown"),
        ];

        sort_processes(&mut rows, ProcessSort::Memory);

        assert_eq!(
            rows.iter().map(|row| row.pid).collect::<Vec<_>>(),
            [12, 11, 10, 13]
        );
    }

    #[test]
    fn cpu_sort_is_descending_and_uses_pid_to_break_ties() {
        let mut rows = vec![
            process(10, 5.0, "1M"),
            process(12, 80.0, "1M"),
            process(11, 80.0, "1M"),
        ];

        sort_processes(&mut rows, ProcessSort::Cpu);

        assert_eq!(
            rows.iter().map(|row| row.pid).collect::<Vec<_>>(),
            [11, 12, 10]
        );
    }

    fn process(pid: u32, cpu_percent: f64, memory: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            cpu_percent,
            memory: memory.into(),
            cpu_time: "00:00.00".into(),
            command: format!("process-{pid}"),
        }
    }

    #[test]
    fn process_cache_keeps_last_rows_when_refresh_fails_and_marks_them_stale() {
        let at = Instant::now();
        let mut cache = ProcessCache::default();
        cache.apply_success(
            vec![ProcessInfo {
                pid: 12,
                cpu_percent: 82.0,
                memory: "4M".into(),
                cpu_time: "00:00.04".into(),
                command: "busy_worker".into(),
            }],
            at,
        );
        cache.apply_error("ssh timed out".into());
        match cache.view_at(at + Duration::from_secs(11)) {
            ProcessView::Available {
                rows,
                stale,
                warning,
                ..
            } => {
                assert!(stale);
                assert_eq!(rows[0].command, "busy_worker");
                assert_eq!(warning.as_deref(), Some("ssh timed out"));
            }
            _ => panic!("expected retained process rows"),
        }
    }

    #[test]
    fn process_cache_reports_initial_loading_and_first_error() {
        let mut cache = ProcessCache::default();
        assert!(matches!(
            cache.view_at(Instant::now()),
            ProcessView::Loading
        ));
        cache.apply_error("top failed".into());
        assert!(matches!(
            cache.view_at(Instant::now()),
            ProcessView::Unavailable { reason } if reason == "top failed"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_mac_process_sampling_returns_cpu_sorted_rows() {
        let rows = super::sample_target(
            &super::ProcessTarget::Local,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert!(!rows.is_empty());
        assert!(rows.iter().any(|row| row.command != "unknown"));
        assert!(rows.windows(2).all(|pair| {
            pair[0].cpu_percent >= pair[1].cpu_percent
                || pair[0].cpu_percent == pair[1].cpu_percent && pair[0].pid <= pair[1].pid
        }));
    }
}
