#!/usr/bin/env python3
"""Measure local macluster command latency without recording command output."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time


DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "target" / "controller-bench"
COMMAND_TIMEOUT_SECONDS = 45


def build_probe_commands(binary, config, state_dir):
    """Return local, read-only query commands; never submit or administer nodes."""
    prefix = [str(binary), "--config", str(config), "--state-dir", str(state_dir)]
    return {
        "jobs": prefix[:1] + ["mjob", "--all", "--json"] + prefix[1:],
        "queues": prefix[:1] + ["mqueue", "--json"] + prefix[1:],
        "controller_status": prefix[:1] + ["controller", "status"] + prefix[1:],
        "mtop_once": prefix[:1] + ["mtop", "--once", "--json"] + prefix[1:],
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_system_value(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def count_configured_nodes(config):
    try:
        content = config.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    return sum(1 for line in content.splitlines() if re.match(r"^\s*\[nodes(?:\.|\])", line))


def collect_metadata(binary, config):
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mac_model": read_system_value(["/usr/sbin/sysctl", "-n", "hw.model"]),
        "macos_version": read_system_value(["/usr/bin/sw_vers", "-productVersion"]),
        "architecture": platform.machine(),
        "node_count": count_configured_nodes(config),
        "binary_sha256": sha256_file(binary),
    }


def snapshot_state_database(state_dir, scratch_state_dir):
    """Copy a consistent SQLite snapshot so probes cannot mutate user state."""
    source_path = state_dir / "controller.sqlite3"
    destination_path = scratch_state_dir / "controller.sqlite3"
    source = sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True, timeout=5)
    destination = sqlite3.connect(destination_path, timeout=5)
    try:
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    destination_path.chmod(0o600)


def prepare_benchmark_binary(binary, scratch_dir):
    """Use a non-production executable name to skip auto-update preflight."""
    copy = scratch_dir / "macluster-benchmark"
    shutil.copy2(binary, copy)
    copy.chmod(0o700)
    return copy


def run_sample(argv, timeout=COMMAND_TIMEOUT_SECONDS):
    started = time.perf_counter_ns()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"duration_ms": (time.perf_counter_ns() - started) / 1_000_000, "status": "timeout"}
    except OSError:
        return {"duration_ms": (time.perf_counter_ns() - started) / 1_000_000, "status": "spawn_error"}
    return {
        "duration_ms": (time.perf_counter_ns() - started) / 1_000_000,
        "status": "ok" if result.returncode == 0 else "command_error",
        "exit_code": result.returncode,
    }


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summarize(samples):
    durations = [sample["duration_ms"] for sample in samples]
    ok = sum(sample["status"] == "ok" for sample in samples)
    return {
        "samples": len(samples),
        "successful": ok,
        "failed": len(samples) - ok,
        "p50_ms": percentile(durations, 0.50),
        "p95_ms": percentile(durations, 0.95),
    }


def run_probe_set(commands, cold_count, warm_count, warmup_count):
    results = {}
    failed = False
    for name, argv in commands.items():
        cold = [run_sample(argv) for _ in range(cold_count)]
        for _ in range(warmup_count):
            run_sample(argv)
        warm = [run_sample(argv) for _ in range(warm_count)]
        results[name] = {"cold_process": summarize(cold), "warm_process": summarize(warm)}
        failed = failed or any(sample["status"] != "ok" for sample in cold + warm)
    return results, failed


def atomic_write_json(output_dir, document):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = output_dir / f"controller-benchmark-{stamp}-{os.getpid()}.json"
    temporary = destination.with_suffix(".json.tmp")
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    return destination


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline",), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--samples", type=int, default=30, help="warm process samples per query")
    parser.add_argument("--cold-samples", type=int, default=10, help="fresh process samples per query")
    parser.add_argument("--warmups", type=int, default=1, help="discarded invocations before warm samples")
    parser.add_argument(
        "--submit-smoke",
        action="store_true",
        help="submit one `true` batch job to the configured cluster and keep its job history",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    binary = args.binary.expanduser().resolve()
    config = args.config.expanduser().resolve()
    state_dir = args.state_dir.expanduser().resolve()
    output_dir = args.output.expanduser()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print("benchmark binary must be an executable file", file=sys.stderr)
        return 2
    if not config.is_file():
        print("benchmark config must be an existing file", file=sys.stderr)
        return 2
    if not state_dir.is_dir() or not (state_dir / "controller.sqlite3").is_file():
        print("benchmark state directory must contain an existing controller.sqlite3", file=sys.stderr)
        return 2
    if args.samples < 1 or args.cold_samples < 1 or args.warmups < 0:
        print("sample counts must be positive; warmups may be zero", file=sys.stderr)
        return 2

    try:
        with tempfile.TemporaryDirectory(prefix="macluster-controller-bench-") as scratch:
            scratch_dir = Path(scratch)
            scratch_state_dir = Path(scratch) / "state"
            scratch_state_dir.mkdir(mode=0o700)
            snapshot_state_database(state_dir, scratch_state_dir)
            benchmark_binary = prepare_benchmark_binary(binary, scratch_dir)
            commands = build_probe_commands(benchmark_binary, config, scratch_state_dir)
            probes, failed = run_probe_set(
                commands, args.cold_samples, args.samples, args.warmups
            )
            if args.submit_smoke:
                print("Submitting one `true` smoke job; it will be kept in the cluster job history.")
                sys.stdout.flush()
                submit_argv = [
                    str(benchmark_binary),
                    "--config",
                    str(config),
                    "--state-dir",
                    str(state_dir),
                    "msub",
                    "--wrap",
                    "true",
                ]
                submit_result = run_sample(submit_argv, timeout=300)
                probes["submit_smoke"] = {"sample": submit_result}
                failed = failed or submit_result["status"] != "ok"
    except (OSError, sqlite3.Error) as error:
        print(f"could not create an isolated benchmark state snapshot: {error}", file=sys.stderr)
        return 2
    document = {
        "schema_version": 1,
        "mode": args.mode,
        "measurement": {
            "cold_definition": "fresh CLI process; the OS file cache is not flushed",
            "outputs_recorded": False,
            "configured_samples": {"cold_process": args.cold_samples, "warm_process": args.samples},
        },
        "metadata": collect_metadata(binary, config),
        "probes": probes,
    }
    try:
        destination = atomic_write_json(output_dir, document)
    except OSError as error:
        print(f"could not write benchmark results: {error}", file=sys.stderr)
        return 2
    print(f"Benchmark results: {destination}")
    if args.submit_smoke:
        status = probes["submit_smoke"]["sample"]["status"]
        if status == "ok":
            print("Measured local queries and one smoke submission; command output was discarded.")
        else:
            print("Measured local queries; smoke submission failed and command output was discarded.")
    else:
        print("Measured local read-only queries; no task was submitted and command output was discarded.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
