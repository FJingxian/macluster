# Task resource subscriptions

[English README](../README.md) · [简体中文](README.zh-CN.md)

Observe a running task without enabling detailed output logging or resubmitting it:

```sh
macluster job --metrics 42
macluster job --metrics 42 --follow
macluster job --metrics 42 --follow --json
```

Replace `42` with your job ID. This requires a running controller and Agents built with `task.resources.v1` support. An older controller reports that the feature is missing; upgrade it when idle rather than interrupting active work.

`--json` prints one JSON object. With `--follow`, each line is a JSON object (JSON Lines), suitable for an agent or script. Follow mode emits changes in sample, job state, error, or staleness; it stops when the job reaches a terminal state. Ctrl-C closes the subscription without cancelling the job. A controller restart or connection failure ends the stream with an error; subscribe again to resume.

A one-shot query waits up to 12 seconds for its first observation while a task is starting/running. Pending and finished jobs can return immediately without a sample. A terminal job returns the last observation if it is still retained in that subscription cache. This live interface is not a historical database; use `submit -v` for persistent resource records.

## Sampling and performance

- The controller samples a watched task about every five seconds; network/worker delays can lengthen that interval. Every client of the same task reads one shared cache. Polling snapshots faster does not start more node samples.
- Each connection subscribes to one job. The controller permits at most 128 resource subscriptions and uses two bounded sampling workers. Subscription leases last 30 seconds and renew on snapshot requests. Disconnect/expiry stops future sampling; an already running request may finish.
- Without a subscription or `submit -v`, there is no periodic task resource sampling. A subscription does not enable output annotation or large diagnostic logs.
- For verbose jobs, the Agent reuses a fresh existing resource sample. Otherwise it uses macOS libproc to inspect the task's process group, with a five-second Agent cache as a second guard against duplicate sampling. It does not launch `top` or require sudo.
- No network or process query runs synchronously on the controller's request handler. Slow probes preserve the last sample and expose an error/stale flag.
- Sampling enumerates at most 4,096 processes per task. The Agent keeps bounded local metadata rather than appending a stream to NFS; metadata participates in existing job-log retention.

There is still CPU, memory, file I/O, and SSH overhead. It grows with the number of watched jobs/processes, not with the number of viewers of the same job. Runtime configuration remains unchanged when no subscription is active. Local test latency is not a guarantee of production overhead or remote response time.

## Meaning of the data

The outer record contains `job_id`, `node_id`, execution `start_token`, current `state`, `sample`, `age_ms`, `stale`, and `error`. The sample is null until an observation is available. `age_ms` includes Agent cache age and time in the controller cache; clients should honor `stale`/`error` instead of treating old data as current.

| Sample field | Meaning |
| --- | --- |
| `schema_version` | Payload schema version, currently 1 |
| `observed_unix_ms` | Observation timestamp on the compute Mac |
| `age_ms` | Sample age at the Agent response; prefer outer `age_ms` for display |
| `interval_ms` | CPU observation window; null for the first baseline |
| `cpu_percent` | CPU-time delta divided by elapsed time, summed across matching task processes; may exceed 100% |
| `rss_bytes` | Sum of observed processes' resident memory, not unique physical memory |
| `cpu_time_seconds` | Accumulated observed CPU-time deltas |
| `memory_time_gib_seconds` | Integral of sampled RSS over observed intervals |
| `memory_peak_sampled_bytes` | Largest sampled RSS sum, not the guaranteed instantaneous peak |
| `process_count` | Processes successfully observed in the task's process group |
| `source` | `on_demand` or `verbose_log_sampler` |
| `coverage` | `baseline`, `observed_intervals`, `partial`, or `partial_process_group` |
| `error` | Sampling failure, if present |

The first observation provides RSS but no interval CPU value: `cpu_percent` and `interval_ms` are null. Normally the next observation supplies CPU after about five seconds. Late subscriptions do not reconstruct the task's earlier resource history. On-demand accounting begins with its first observation; verbose accounting begins with the logger's first observation. Changing sample source can change the accounting window. After an on-demand observation gap longer than 15 seconds, a new baseline starts instead of integrating the unobserved gap.

CPU time of processes that start and exit entirely between observations can be missed. PID reuse is checked using process start identity; it is not charged to the previous process. Processes that deliberately leave the task's process group are outside this measurement. Shared pages can be counted in more than one process's RSS. These records support performance investigation, not exact billing or an interactive source debugger.

## Controller IPC

Other clients can use the exported Rust types in `macluster_protocol::resources` and `macluster_protocol::control` over the existing authenticated, framed Unix-socket control connection:

1. Perform the existing `ClientHello` handshake and check the server's `task.resources.v1` capability.
2. Send `SubscribeJobResources { job_id }`; expect `JobResourcesSubscribed`.
3. Request `JobResourceSnapshot { job_id }` periodically on that same connection. Requests renew its lease; snapshots contain cached data and schedule shared asynchronous probes.
4. Send `UnsubscribeJobResources`, or close the connection.

Existing peer UID, cluster binding and configuration generation checks apply. Queries to the Agent also verify controller identity, job ID, start token, boot identity, and the task leader's process identity. A subscription cannot accidentally read the next job that reuses a node/PID. Reconnect and resubscribe after a controller generation change. No new unauthenticated HTTP endpoint is added.
