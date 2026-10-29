---
name: macluster
description: Operate a macluster macOS cluster to submit jobs, profile task CPU and memory, inspect nodes and NFS shares, use shared toolchains, and diagnose scheduling or environment failures. Use when the user names macluster or its msub/mjob/mqueue/mtop workflow on Macs; not for Slurm clusters or similarly named Linux schedulers.
---

# macluster

Use the installed `macluster` CLI on the configured login Mac. Prefer full subcommands so command aliases are not required. Work within the user's requested job or maintenance operation; inspecting a cluster does not authorize resetting it, killing jobs, changing fan policy, or publishing new NFS shares.

## Establish the actual context

- Locate the executable with `command -v macluster`; in a source checkout, `target/release/macluster` may be available. Do not assume a checkout binary is the installed build.
- Inspect `macluster --help` and relevant subcommand help when needed. Installed behavior takes precedence over examples in this skill.
- Read `macluster controller status`, `macluster node -l`, `macluster queue`, and, when relevant, `macluster job --all`. Respect explicit `--config PATH` / `--state-dir PATH`; put global options before the subcommand.
- Read-only job/queue queries use saved state and do not prove the controller is running or the nodes are currently reachable. Known Agent mismatches can trigger an update workflow even from inspection commands; do not answer maintenance prompts blindly.
- If configuration is missing, report that discovery result. Use `init` only for requested initialization/reset, since an existing configuration turns it into a reset workflow.

The login Mac runs the controller and normally hosts primary NFS storage; it does not accept compute jobs. Each compute Mac runs one job at a time with no core/memory quota. There is no standalone `mupdate`: normal operations trigger Agent updates when needed.

## Submit the intended workload

Determine the command/script, registered shared working directory, queue or node preference, and intended environment from the user's request and current shell. Inspect mappings using `node -l`; do not guess private cluster IDs, addresses, or project paths.

```sh
macluster submit --cwd /SHARED/PROJECT -q QUEUE python analysis.py
macluster submit --wrap 'python analysis.py > analysis.log 2>&1'
macluster submit -Is python --version
macluster submit -v python analysis.py
```

Replace the uppercase example values before executing. Task arguments after the command belong to the task. Quote shell operators or use `--wrap` to prevent the login shell from interpreting them. For example, unquoted `submit echo yes > log` redirects the submitting CLI's stdout locally, not the compute command's stdout.

- Inside a registered share, submission preserves the shared working directory. Outside all shares, an inline command defaults to the primary shared root. Use `--cwd` to make placement explicit.
- Relative results are written in that job working directory; they are not automatically copied to an arbitrary unshared submission directory. Default captured logs synchronize to primary shared storage after completion.
- Use batch submission in automation. `-Is` requires real terminal stdin/stdout; use it only when the user wants an attached shell/command and a suitable TTY is available.
- Detailed timestamp/resource logging costs extra work and is off by default. Enable `-v` for a requested resource record or an investigation that needs it.
- Capture job ID and request ID. If an acknowledgement is lost, inspect `job --request-id UUID` before resubmitting. `submit --request-id UUID` replays a cached submission; do not create duplicate work to diagnose a slow response.

## Preserve software and environment semantics

`submit` forwards exported environment variables and translates registered paths. It does not transfer software merely because PATH mentions it. Node-specific HOME/user/temp/SSH-agent values and shell aliases/functions are not inherited as login-shell behavior; jobs do not source compute-node shell startup files.

- When a task uses an activated `VIRTUAL_ENV` or `CONDA_PREFIX`, its installation must be shared and resolve at the same absolute path across nodes. Shared compiler symlinks and their targets must be accessible too.
- Unshared toolchains are not silently replaced with compute-local installations. Standard macOS commands remain usable; a simple command outside an active environment need not use its interpreter.
- Check the actual exported environment (`printenv PATH`, relevant compiler variables), `command -v python`, compiler paths, and NFS mappings. Do not dump all environment variables into reports or logs: they may contain credentials.
- When asked to share a directory, preserve shell expansion by quoting `"local:$HOME/path"`; `local:~/path` does not expand `~` as intended. Adding a share is a cluster change, not a harmless environment fix.
- Share only requested paths. Mounting over `/opt/homebrew` or another populated software path can hide existing files while mounted; do not bypass collision checks or edit `/etc/exports` by hand as an automatic retry.
- For compilation failures, inspect the first compiler/Cargo error in the complete log, not just pip/maturin's final exit code. Distinguish missing toolchain files, network/index failures, and source errors. Do not automatically add `--break-system-packages`, clear shared caches, or reinstall software as a generic fix.
- Avoid concurrent package installs into one shared environment. Cargo normally uses a reusable node-local build target cache unless explicitly overridden.

## Follow a job through completion

```sh
macluster job JOBID
macluster job --log JOBID
macluster job --log JOBID --stderr
macluster job --log JOBID --follow
macluster job --all --json
```

A submitted or allocated job is not a successful job. Check terminal state, exit status, relevant logs, and requested result files. If output synchronization is pending, distinguish workload completion from log availability. Report job/node IDs, exit status, working directory, and output locations without exposing private environment values.

For pending jobs, inspect the job's waiting reason, controller state, queue membership, node readiness, and maintenance/update messages. If scheduling is expected and the service is stopped, use `controller start` within the authorized task. Do not launch competing foreground controllers or reset state to clear a wait. Stop retrying a repeated maintenance failure and report its operation/phase and concrete error rather than mutating journals or the database.

## Subscribe to task resources

Use `macluster job --metrics JOBID [--follow] [--json]` to inspect a task's process-group CPU/RSS. JSON follow output is one object per line, and ends at terminal state. It needs the running controller and `task.resources.v1` support; report an older-controller capability error rather than restarting it during active work. Closing a metrics stream does not cancel its job.

The controller shares approximately five-second observations across subscribers. `submit -v` is not required for live monitoring; verbose jobs reuse fresh logger samples. Check outer `age_ms`, `stale`, `error`, sample `coverage` and `source`. First CPU is null (baseline), not zero. RSS sums can double-count shared pages; short-lived processes can be missed, and sampled peaks are not guaranteed maxima. Late subscriptions do not recover earlier history. Use `submit -v` when the user needs persistent resource records.

Use this stream for ongoing workload observation instead of repeatedly running SSH/top. Do not confuse node totals or process previews with the task-group measurements. `job --log --follow` waits for output publication after completion; it is not a live log stream. A broken subscription must be reconnected; do not resubmit the job to recover monitoring.

## Investigate workload performance

When asked to debug a slow workload or inspect its resource use:

1. Identify its job ID, allocated node, working directory, command and execution state. Distinguish queue waiting, environment/build/network failures, and slow execution before attributing a delay to CPU or memory.
2. Subscribe to the existing job with `macluster job --metrics JOBID --follow --json`. Do not resubmit an already running job merely to enable monitoring. Use a bounded observation window appropriate to the user's question and stop that subscription after collecting sufficient evidence; the task continues.
3. Wait for at least two distinct valid observations before interpreting interval CPU. Compare `observed_unix_ms`/`interval_ms`, discard stale or errored samples from current-load conclusions, and retain their gaps in any report. Null CPU means unavailable/baseline, not idle. After an on-demand gap longer than 15 seconds, accounting restarts with a baseline.
4. Inspect CPU%, RSS, sampled memory peak, process count, observed CPU seconds and memory-time together. CPU% is summed across logical CPUs. High sustained CPU suggests compute activity; low CPU alone cannot distinguish disk/network waits, synchronization, or application idleness. RSS is resident memory, not an allocation/leak measurement; require a sustained trend and application evidence before diagnosing a leak.
5. Check terminal job state, exit status and requested results. Report the observation interval, sample count, node, sampling source/coverage, CPU range, RSS range and largest observed RSS, plus missing/stale intervals. Distinguish sampled measurements from hypotheses about the bottleneck. Do not label a sampled peak as the true maximum or observed CPU-time as full lifetime CPU-time.

For a new task requiring a persistent resource record, use `macluster submit -v COMMAND` before execution. `monitor.log`, `resources.jsonl` and `summary.json` are the verbose artifacts, published with task output; their history is bounded and may rotate. Ordinary live observation does not require `-v` and does not enable output annotation. Do not enable verbose logging for every submission by default.

For before/after comparisons, keep the dataset, node, toolchain, thread settings, sampling/logging mode and cache conditions comparable; separate build/setup time from measured execution. Run repetitions only within the user's authorized benchmark scope. Tasks shorter than the sampling interval may have insufficient observations: report that limitation instead of interpreting missing samples as zero usage.

Multiple viewers share roughly one five-second sample per watched task. Repeatedly opening subscriptions or polling faster does not improve the measurement window. Monitoring has nonzero process-query, SSH and local metadata I/O cost; output annotation adds further costs for verbose jobs. Do not claim a fixed overhead percentage from a single query-latency test. Measuring the monitor's own overhead requires a controlled monitored/unmonitored comparison, not the workload's CPU% alone.

## Monitor and maintain

- `macluster top --once` is suitable for noninteractive resource inspection; `top` opens the TUI. Enter toggles process details, `c`/`m` sort descending. Initial process previews use ps average CPU and RSS; later samples show interval usage. Do not treat preview numbers as instantaneous CPU.
- CPU totals can exceed 100% (eight logical CPUs allow 800%). Hardware/helper-dependent power, GPU, temperature, and fan values can be unavailable.
- `controller run --web` opens the read-only localhost browser monitor; `--no-open` prints its link. Do not expose its authenticated link or change its network binding without a request.
- `node -a USER@IP[:PORT]` enrolls a compute node. `node -a local:PATH --share-id ID --mount-root PATH` registers a local share; `local` itself is the login node, not a compute queue member.
- `node -rm NODE_ID --connect USER@IP[:PORT]` can remove a moved node after identity verification. `node -rm share:ID` cancels incomplete share setup. Active jobs/output sync or hosted storage can block removal.
- Preserve strict SSH host-key checks. A matching MAC address alone does not establish identity. Never remove trusted keys or accept replacement fingerprints without verification.
- Initial privileged setup or helper upgrades/repair may ask once per affected Mac. SSH login and administrator passwords serve different purposes. Do not store passwords in shell scripts, files, or job environments; let the user enter authorization at the prompt.
- `macluster fans --status` inspects fan support. Changing policies (`--auto`, `--power`, `--reset`) applies to all nodes unless `--node ID` is specified; honor the requested scope.
- `init` resets an existing cluster after confirmation and preserves shared data files. `init --force` may abandon pending output from finished jobs; active jobs still block it. Neither is a routine repair command.

For NFS failures, distinguish export filesystem support, server-side nfsd privacy permission, exact mount source, and path collisions. Protected folders/external volumes may require Full Disk Access for `/sbin/nfsd` on the storage Mac. A service restart does not grant that permission. Prefer resuming the original operation after its actual cause is addressed.
