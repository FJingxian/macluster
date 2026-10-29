use std::{
    collections::{BTreeMap, HashSet},
    process::Command,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread,
    time::Duration,
};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::{
    control::{MAX_MONITOR_PROCESS_ROWS, ProcessRow},
    identifiers::NodeId,
};

use crate::{
    ssh::{ConnectionKey, SshPool},
    transport::run_child_bounded,
};

const PROCESS_COMMAND: &str = "top_output=$(/usr/bin/top -l 2 -n 32 -s 1 -stats pid,cpu,mem,time,command -o cpu) || exit $?; printf '%s\\n' \"$top_output\"; printf '\\n__MACLUSTER_PS_NAMES__\\n'; pids=$(printf '%s\\n' \"$top_output\" | /usr/bin/awk '/^[[:space:]]*PID[[:space:]]+%CPU[[:space:]]+MEM[[:space:]]+TIME[[:space:]]+COMMAND/ { table=1; count=0; next } table && $1 ~ /^[0-9]+$/ { pids[++count]=$1 } END { for (i=1; i<=count; i++) { if (i > 1) printf \",\"; printf \"%s\", pids[i] } }'); if [ -n \"$pids\" ]; then /bin/ps -p \"$pids\" -o pid=,ucomm=; fi";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_WORKERS: usize = 2;
const PROCESS_MARKER: &str = "__MACLUSTER_PS_NAMES__";

struct ProcessTask {
    node_id: NodeId,
    node: NodeConfig,
}

pub(super) struct ProcessResult {
    pub(super) node_id: NodeId,
    pub(super) result: Result<Vec<ProcessRow>, String>,
    pub(super) completed_at: std::time::Instant,
}

pub(super) struct ProcessSampler {
    sender: SyncSender<ProcessTask>,
    receiver: Receiver<ProcessResult>,
    in_flight: HashSet<NodeId>,
}

impl ProcessSampler {
    pub fn new(sample: Arc<super::ProcessSampleFn>) -> Self {
        let (sender, tasks) = mpsc::sync_channel::<ProcessTask>(PROCESS_WORKERS);
        let tasks = Arc::new(Mutex::new(tasks));
        let (results, receiver) = mpsc::channel();
        for index in 0..PROCESS_WORKERS {
            let tasks = Arc::clone(&tasks);
            let results = results.clone();
            let sample = Arc::clone(&sample);
            let _ = thread::Builder::new()
                .name(format!("monitor-processes-{index}"))
                .spawn(move || {
                    loop {
                        let task = match tasks.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else { return };
                        if results
                            .send(ProcessResult {
                                node_id: task.node_id.clone(),
                                result: sample(&task.node_id, &task.node),
                                completed_at: std::time::Instant::now(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                });
        }
        drop(results);
        Self {
            sender,
            receiver,
            in_flight: HashSet::new(),
        }
    }

    pub fn request(&mut self, node_id: NodeId, node: NodeConfig) -> bool {
        if self.in_flight.len() >= PROCESS_WORKERS || self.in_flight.contains(&node_id) {
            return false;
        }
        match self.sender.try_send(ProcessTask {
            node_id: node_id.clone(),
            node,
        }) {
            Ok(()) => {
                self.in_flight.insert(node_id);
                true
            }
            Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn has_capacity(&self) -> bool {
        self.in_flight.len() < PROCESS_WORKERS
    }

    pub fn poll(&mut self) -> Vec<ProcessResult> {
        let mut completed = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(result) => {
                    self.in_flight.remove(&result.node_id);
                    completed.push(result);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        completed
    }
}

pub(super) fn sample_node(
    node_id: &NodeId,
    node: &NodeConfig,
    pool: &SshPool,
) -> Result<Vec<ProcessRow>, String> {
    let command = if node.transport == Transport::Local {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", PROCESS_COMMAND]);
        command
    } else {
        let mut command = Command::new("/usr/bin/ssh");
        command.args([
            "-T",
            "-oLogLevel=ERROR",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oConnectTimeout=4",
            "-oConnectionAttempts=1",
        ]);
        node.add_ssh_identity_args(&mut command);
        if let Ok(key) = ConnectionKey::for_node(pool.namespace(), node_id.as_str(), node) {
            let _ = pool.append_args(&key, &mut command);
        }
        command.arg(&node.host).arg(PROCESS_COMMAND);
        command
    };
    let output = run_child_bounded(command, None, PROCESS_TIMEOUT)
        .map_err(|error| format!("process sample failed: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("process sample exited with {}", output.status)
        } else {
            detail
        });
    }
    parse_processes(&String::from_utf8_lossy(&output.stdout))
}

fn parse_processes(input: &str) -> Result<Vec<ProcessRow>, String> {
    let (top_output, process_output) = input
        .split_once(PROCESS_MARKER)
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
        let mut command = if top_command.is_empty() || top_command == "?" {
            names.get(&pid).cloned().unwrap_or_else(|| "unknown".into())
        } else {
            top_command
        };
        truncate_utf8(&mut command, 512);
        rows.push(ProcessRow {
            pid,
            cpu_percent,
            memory_bytes: parse_memory_bytes(fields[2]),
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
    rows.truncate(MAX_MONITOR_PROCESS_ROWS);
    Ok(rows)
}

fn parse_memory_bytes(memory: &str) -> Option<u64> {
    let value = memory.trim_end_matches('+');
    let (number, multiplier) = match value.chars().last()? {
        'B' | 'b' => (&value[..value.len() - 1], 1_f64),
        'K' | 'k' => (&value[..value.len() - 1], 1024_f64),
        'M' | 'm' => (&value[..value.len() - 1], 1024_f64.powi(2)),
        'G' | 'g' => (&value[..value.len() - 1], 1024_f64.powi(3)),
        'T' | 't' => (&value[..value.len() - 1], 1024_f64.powi(4)),
        _ => return value.parse::<u64>().ok(),
    };
    let bytes = number.parse::<f64>().ok()? * multiplier;
    (bytes.is_finite() && bytes >= 0.0 && bytes <= u64::MAX as f64).then_some(bytes.round() as u64)
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
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
    use super::PROCESS_COMMAND;

    #[test]
    fn process_name_lookup_is_limited_to_top_rows() {
        assert!(PROCESS_COMMAND.contains("/bin/ps -p \"$pids\" -o pid=,ucomm="));
        assert!(!PROCESS_COMMAND.contains("/bin/ps -axo pid=,ucomm="));
        assert!(PROCESS_COMMAND.contains("{ table=1; count=0; next }"));
    }
}
