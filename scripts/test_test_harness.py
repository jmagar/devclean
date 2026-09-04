"""Failure-contract tests for the devclean test harness."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("test-harness.py")
SPEC = importlib.util.spec_from_file_location("devclean_test_harness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class HarnessContractTests(unittest.TestCase):
    def test_timeout_terminates_descendant_processes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = pathlib.Path(raw) / "orphan-ran"
            ready = pathlib.Path(raw) / "child-ready"
            child_code = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).write_text('ready'); "
                "time.sleep(0.5); "
                f"pathlib.Path({str(marker)!r}).write_text('alive')"
            )
            parent_code = (
                "import pathlib,subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                f"ready=pathlib.Path({str(ready)!r}); "
                "deadline=time.monotonic()+2; "
                "\nwhile not ready.exists() and time.monotonic() < deadline: time.sleep(0.01)\n"
                "time.sleep(5)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                HARNESS.run_captured([sys.executable, "-c", parent_code], timeout=0.5)
            self.assertTrue(
                ready.exists(), "child did not start before timeout cleanup"
            )
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_release_build_uses_isolated_target_and_repository_root(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(HARNESS, "run_command", return_value=completed) as run,
            mock.patch.object(pathlib.Path, "is_file", return_value=True),
        ):
            binary = HARNESS.build_release([])
        self.assertEqual(binary, HARNESS.HARNESS_TARGET / "release" / "devclean")
        self.assertEqual(run.call_args.kwargs["cwd"], HARNESS.ROOT)
        self.assertEqual(
            run.call_args.kwargs["env"]["CARGO_TARGET_DIR"], str(HARNESS.HARNESS_TARGET)
        )

    def test_result_enforces_state_and_command_immutability(self) -> None:
        result = HARNESS.Result("pass", "passed", ["true"], 0.1, 0, "pass.log")
        self.assertEqual(result.command, ("true",))
        with self.assertRaises((AttributeError, TypeError)):
            result.command[0] = "false"
        with self.assertRaises(ValueError):
            HARNESS.Result("bad", "passed", ["false"], 0.1, 9, "bad.log")
        with self.assertRaises(ValueError):
            HARNESS.Result("bad", "failed", ["false"], 0.1, 1, "bad.log")
        with self.assertRaises(ValueError):
            HARNESS.Result("bad", "skipped", ["false"], 0.0, 0, "", "reason")

    def test_step_records_success_nonzero_timeout_and_missing_tool(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = pathlib.Path(raw)
            success = HARNESS.run_step(
                HARNESS.Step("success", [sys.executable, "-c", "print('ok')"]), run_dir
            )
            failure = HARNESS.run_step(
                HARNESS.Step("failure", [sys.executable, "-c", "raise SystemExit(7)"]),
                run_dir,
            )
            timeout = HARNESS.run_step(
                HARNESS.Step(
                    "timeout",
                    [sys.executable, "-c", "import time; time.sleep(1)"],
                    timeout=0.01,
                ),
                run_dir,
            )
            missing = HARNESS.run_step(
                HARNESS.Step(
                    "missing", ["missing-devclean-tool"], ("missing-devclean-tool",)
                ),
                run_dir,
            )

            self.assertEqual((success.status, success.exit_code), ("passed", 0))
            self.assertEqual((failure.status, failure.exit_code), ("failed", 7))
            self.assertIn("timed out", timeout.message)
            self.assertIn("missing required tool", missing.message)
            for result in (success, failure, timeout, missing):
                self.assertTrue(pathlib.Path(result.log).is_file())

    def test_fail_fast_records_remaining_steps_as_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            steps = [
                HARNESS.Step("failure", [sys.executable, "-c", "raise SystemExit(1)"]),
                HARNESS.Step(
                    "never-run", [sys.executable, "-c", "raise SystemExit(99)"]
                ),
            ]
            results = HARNESS.execute_steps(steps, pathlib.Path(raw), fail_fast=True)
            self.assertEqual(
                [result.status for result in results], ["failed", "skipped"]
            )
            self.assertIn("fail-fast stopped after failure", results[1].message)

    def test_json_and_junit_describe_failures_and_skips(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = pathlib.Path(raw)
            results = [
                HARNESS.Result("pass", "passed", ["true"], 0.1, 0, "pass.log"),
                HARNESS.Result("fail", "failed", ["false"], 0.2, 1, "fail.log", "bad"),
                HARNESS.Result(
                    "skip", "skipped", ["later"], 0.0, None, "", "fail-fast"
                ),
            ]
            HARNESS.write_reports("all", run_dir, results, "2026-01-01T00:00:00+00:00")

            summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["passed"])
            self.assertEqual(
                [item["status"] for item in summary["results"]],
                ["passed", "failed", "skipped"],
            )
            suite = ET.parse(run_dir / "junit.xml").getroot()
            self.assertEqual(suite.attrib["tests"], "3")
            self.assertEqual(suite.attrib["failures"], "1")
            self.assertEqual(suite.attrib["skipped"], "1")
            self.assertEqual(len(suite.findall("testcase/skipped")), 1)

    def test_report_schema_validation_rejects_malformed_contracts(self) -> None:
        target = pathlib.Path("/private/fixture/target")
        valid_candidate = {
            "identity": {"kind": "filesystem", "path": str(target)},
            "category": "build",
            "physical_bytes_estimate": 42,
        }
        valid_report = {
            "schema_version": 1,
            "scan_id": "harness-smoke",
            "candidates": [valid_candidate],
        }
        self.assertEqual(
            HARNESS.validate_stored_report(valid_report, target), valid_candidate
        )

        for malformed in (
            {**valid_report, "schema_version": 2},
            {**valid_report, "schema_version": True},
            {**valid_report, "candidates": []},
            {
                **valid_report,
                "candidates": [{**valid_candidate, "physical_bytes_estimate": True}],
            },
            {
                **valid_report,
                "candidates": [{**valid_candidate, "physical_bytes_estimate": -1}],
            },
        ):
            with self.assertRaises((TypeError, RuntimeError)):
                HARNESS.validate_stored_report(malformed, target)

        HARNESS.validate_redacted_export(
            {"schema_version": 1, "usable_for_cleanup": False},
            "{}",
            pathlib.Path("/private"),
        )
        with self.assertRaises(RuntimeError):
            HARNESS.validate_redacted_export(
                {"schema_version": 1, "usable_for_cleanup": False},
                '{"path":"/private/reports"}',
                pathlib.Path("/private"),
            )
        with self.assertRaises(TypeError):
            HARNESS.validate_redacted_export(
                {"schema_version": 2, "usable_for_cleanup": False},
                "{}",
                pathlib.Path("/private"),
            )
        with self.assertRaises(TypeError):
            HARNESS.validate_redacted_export(
                {"schema_version": True, "usable_for_cleanup": False},
                "{}",
                pathlib.Path("/private"),
            )

    def test_tree_digest_detects_permission_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            path = root / "artifact"
            path.write_text("same content", encoding="utf-8")
            path.chmod(0o600)
            before = HARNESS.tree_digest(root)
            path.chmod(0o644)
            self.assertNotEqual(HARNESS.tree_digest(root), before)
            root.chmod(0o755)
            before_root_change = HARNESS.tree_digest(root)
            root.chmod(0o700)
            self.assertNotEqual(HARNESS.tree_digest(root), before_root_change)

    def test_report_finalization_failure_leaves_no_partial_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = pathlib.Path(raw)
            results = [HARNESS.Result("pass", "passed", ["true"], 0.1, 0, "pass.log")]
            with (
                mock.patch.object(
                    HARNESS.tempfile, "mkstemp", side_effect=OSError("disk full")
                ),
                self.assertRaisesRegex(OSError, "disk full"),
            ):
                HARNESS.write_reports(
                    "fast", run_dir, results, "2026-01-01T00:00:00+00:00"
                )
            self.assertFalse((run_dir / "summary.json").exists())
            self.assertFalse((run_dir / "junit.xml").exists())


if __name__ == "__main__":
    unittest.main()
