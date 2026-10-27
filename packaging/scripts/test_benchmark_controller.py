#!/usr/bin/env python3
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("benchmark-controller.py")


class BenchmarkControllerTests(unittest.TestCase):
    def test_default_run_only_executes_local_read_only_commands(self):
        self.assertTrue(SCRIPT.is_file(), "read-only controller benchmark script is missing")
        spec = importlib.util.spec_from_file_location("benchmark_controller", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="macluster-bench-test-") as temp:
            root = Path(temp)
            invocations = root / "invocations.jsonl"
            binary = root / "fake-macluster"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['BENCH_INVOCATIONS'], 'a') as stream:\n"
                "    stream.write(json.dumps({'program': sys.argv[0], 'args': sys.argv[1:]}) + '\\n')\n"
                "print(os.environ.get('BENCH_SECRET', 'ordinary-output'))\n"
            )
            binary.chmod(0o755)
            config = root / "config.toml"
            state = root / "state"
            output = root / "results"
            config.write_text("placeholder; the fake binary never reads it\n")
            state.mkdir()
            database = state / "controller.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE preserved(value TEXT)")
                connection.execute("INSERT INTO preserved VALUES ('keep')")
            original_database_hash = hashlib.sha256(database.read_bytes()).hexdigest()

            environment = os.environ.copy()
            environment["BENCH_INVOCATIONS"] = str(invocations)
            environment["BENCH_SECRET"] = "do-not-write-this-to-results"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--mode",
                    "baseline",
                    "--binary",
                    str(binary),
                    "--config",
                    str(config),
                    "--state-dir",
                    str(state),
                    "--output",
                    str(output),
                    "--cold-samples",
                    "1",
                    "--samples",
                    "1",
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no task was submitted", result.stdout)
            calls = [json.loads(line) for line in invocations.read_text().splitlines()]
            commands = {call["args"][0] for call in calls}
            self.assertEqual(commands, {"mjob", "mqueue", "controller", "mtop"})
            self.assertTrue(all(Path(call["program"]).name == "macluster-benchmark" for call in calls))
            state_arguments = [call["args"][call["args"].index("--state-dir") + 1] for call in calls]
            self.assertTrue(all(value != str(state) for value in state_arguments))
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(), original_database_hash
            )
            self.assertFalse(any(command in {"msub", "submit", "mnode", "node"} for command in commands))
            result_files = list(output.glob("*.json"))
            self.assertEqual(len(result_files), 1)
            result_text = result_files[0].read_text()
            self.assertNotIn("do-not-write-this-to-results", result_text)
            self.assertNotIn("ordinary-output", result_text)
            self.assertNotIn("config.toml", result_text)
            self.assertNotIn("state-dir", result_text)

            smoke_result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--mode",
                    "baseline",
                    "--binary",
                    str(binary),
                    "--config",
                    str(config),
                    "--state-dir",
                    str(state),
                    "--output",
                    str(root / "smoke-results"),
                    "--cold-samples",
                    "1",
                    "--samples",
                    "1",
                    "--submit-smoke",
                ],
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )
            self.assertEqual(smoke_result.returncode, 0, smoke_result.stderr)
            self.assertIn("one `true` smoke job", smoke_result.stdout)
            self.assertNotIn("no task was submitted", smoke_result.stdout)
            calls = [json.loads(line) for line in invocations.read_text().splitlines()]
            smoke_calls = [call for call in calls if "msub" in call["args"]]
            self.assertEqual(len(smoke_calls), 1)
            self.assertEqual(smoke_calls[0]["args"][-2:], ["--wrap", "true"])


if __name__ == "__main__":
    unittest.main()
