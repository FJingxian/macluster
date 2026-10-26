#!/usr/bin/env python3
"""Measure local msub/mjob/mqueue latency against large SQLite job histories.

This is a test-only harness. It creates isolated temporary state directories,
seeds terminal history directly, and invokes the built macluster binary. It
does not contact or mutate a configured cluster.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


SHARE_UUID = "00000000-0000-4000-8000-000000000001"
SNAPSHOT = {"sha256": "0" * 64, "size_bytes": 0}


def job_record(job_id: int, state: str) -> str:
    record = {
        "id": job_id,
        "spec": {
            "queue": "mini01",
            "node": None,
            "name": f"bench-{job_id}",
            "cwd": "/tmp/macluster-benchmark",
            "stdout_path": "/tmp/macluster-benchmark/%j.out",
            "stderr_path": "/tmp/macluster-benchmark/%j.err",
            "walltime_secs": None,
            "env": {},
            "mode": "batch",
            "snapshot": SNAPSHOT,
        },
        "state": state,
        "node": None,
        "start_token": None,
        "cancel_force": False,
        "created_unix_ms": job_id,
        "started_unix_ms": None,
        "finished_unix_ms": job_id if state != "PENDING" else None,
        "exit_code": 0 if state == "COMPLETED" else None,
        "end_reason": None,
        "snapshot_sync_pending": False,
        "log_sync_pending": False,
        "waiting_reason": None,
    }
    return json.dumps(record, separators=(",", ":"))


def seed_database(state_dir: Path, historical_jobs: int, active_jobs: int = 100) -> None:
    state_dir.mkdir(parents=True)
    connection = sqlite3.connect(state_dir / "controller.sqlite3")
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', '3');
        CREATE TABLE jobs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id TEXT NOT NULL UNIQUE,
          request_digest TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          state TEXT NOT NULL,
          cancel_requested INTEGER NOT NULL DEFAULT 0,
          assigned_node TEXT,
          created_unix_ms INTEGER NOT NULL,
          queue TEXT NOT NULL,
          snapshot_sync_pending INTEGER NOT NULL DEFAULT 0,
          log_sync_pending INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE state_events(
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          job_id INTEGER NOT NULL REFERENCES jobs(id),
          state TEXT NOT NULL,
          at_unix_ms INTEGER NOT NULL,
          reason TEXT
        );
        CREATE INDEX jobs_state_created ON jobs(state, created_unix_ms, id);
        CREATE INDEX jobs_state_id ON jobs(state, id DESC);
        CREATE INDEX jobs_queue_state ON jobs(queue, state);
        CREATE INDEX jobs_queue_work ON jobs(queue, id)
          WHERE state IN ('PENDING','STARTING','RUNNING','CANCELLING') OR log_sync_pending=1;
        CREATE UNIQUE INDEX active_node_occupation ON jobs(assigned_node)
          WHERE assigned_node IS NOT NULL AND state IN ('STARTING','RUNNING','CANCELLING');
        """
    )

    rows = []
    for job_id in range(1, historical_jobs + active_jobs + 1):
        state = "COMPLETED" if job_id <= historical_jobs else "PENDING"
        payload = job_record(job_id, state)
        rows.append(
            (
                f"00000000-0000-4000-8000-{job_id:012x}",
                "0" * 64,
                payload,
                state,
                job_id,
                "mini01",
                0,
                0,
            )
        )
        if len(rows) == 1000:
            insert_rows(connection, rows)
            rows.clear()
    if rows:
        insert_rows(connection, rows)
    connection.commit()
    connection.close()


def insert_rows(connection: sqlite3.Connection, rows: list[tuple[object, ...]]) -> None:
    connection.executemany(
        """INSERT INTO jobs(
             request_id, request_digest, payload_json, state, created_unix_ms,
             queue, snapshot_sync_pending, log_sync_pending
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )


def write_config(path: Path, shared_root: Path) -> None:
    path.write_text(
        f'''[cluster]
name = "benchmark"
default_queue = "mini01"
shared_root = "{shared_root}"
share_uuid = "{SHARE_UUID}"
storage_server = "mini01-a"
protocol_version = 1

[queues.mini01]
nodes = ["mini01-a"]
scheduler = "fifo"

[nodes.mini01-a]
host = "192.0.2.1"
transport = "ssh"
''',
        encoding="utf-8",
    )


def invoke(binary: Path, config: Path, state_dir: Path, args: list[str]) -> float:
    command = [
        str(binary),
        "--config",
        str(config),
        "--state-dir",
        str(state_dir),
        *args,
    ]
    started = time.perf_counter()
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")
    return elapsed_ms


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(label: str, samples: list[float]) -> str:
    return (
        f"{label}: n={len(samples)} "
        f"p50={statistics.median(samples):.2f}ms "
        f"p95={percentile(samples, 0.95):.2f}ms"
    )


def run_case(binary: Path, historical_jobs: int, iterations: int) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="macluster-perf-") as temp:
        root = Path(temp)
        state_dir = root / "state"
        shared_root = root / "shared"
        (shared_root / "projects").mkdir(parents=True)
        config = root / "config.toml"
        write_config(config, shared_root)
        seed_database(state_dir, historical_jobs)

        job_samples = [
            invoke(binary, config, state_dir, ["mjob"])
            for _ in range(iterations)
        ]
        queue_samples = [
            invoke(binary, config, state_dir, ["mqueue"])
            for _ in range(iterations)
        ]
        submit_samples = [
            invoke(
                binary,
                config,
                state_dir,
                [
                    "msub",
                    "--cwd",
                    str(shared_root / "projects"),
                    "--wrap",
                    f"printf {index}",
                ],
            )
            for index in range(iterations)
        ]
        return [
            summarize(f"history={historical_jobs} mjob", job_samples),
            summarize(f"history={historical_jobs} mqueue", queue_samples),
            summarize(f"history={historical_jobs} msub durable→return", submit_samples),
        ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="path to a built macluster binary")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--history", type=int, nargs="+", default=[10_000, 100_000])
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    if args.iterations < 1 or any(count < 0 for count in args.history):
        parser.error("iterations must be positive and history counts non-negative")

    print("Local synthetic benchmark; no controller or compute node is contacted.")
    for historical_jobs in args.history:
        for line in run_case(binary, historical_jobs, args.iterations):
            print(line, flush=True)


if __name__ == "__main__":
    main()
