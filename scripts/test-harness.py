#!/usr/bin/env python3
"""Repeatable local and CI qualification harness for devclean."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from typing import Literal

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "test-harness"
HARNESS_TARGET = ROOT / "target" / "test-harness"
Status = Literal["passed", "failed", "skipped"]


def harness_env() -> dict[str, str]:
    return {
        **os.environ,
        "CARGO_TERM_COLOR": "never",
        "NO_COLOR": "1",
        "CARGO_TARGET_DIR": str(HARNESS_TARGET),
    }


@dataclasses.dataclass(frozen=True)
class Step:
    name: str
    command: Sequence[str]
    required_tools: tuple[str, ...] = ()
    timeout: float = 900

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))


@dataclasses.dataclass(frozen=True)
class Result:
    name: str
    status: Status
    command: Sequence[str]
    duration_seconds: float
    exit_code: int | None
    log: str
    message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))
        if self.status not in ("passed", "failed", "skipped"):
            raise ValueError(f"unsupported result status: {self.status}")
        if self.status == "passed" and self.exit_code != 0:
            raise ValueError("passed results require exit_code 0")
        if self.status == "failed" and (self.exit_code == 0 or not self.message):
            raise ValueError("failed results require a failure exit code and message")
        if self.status == "skipped" and (
            self.exit_code is not None or not self.message
        ):
            raise ValueError("skipped results require no exit code and a reason")


def command_steps(profile: str) -> list[Step]:
    fast = [
        Step(
            "harness-self-tests",
            [
                "python3",
                "-m",
                "unittest",
                "discover",
                "-s",
                "scripts",
                "-p",
                "test_test_harness.py",
            ],
            ("python3",),
        ),
        Step("format", ["cargo", "fmt", "--all", "--", "--check"], ("cargo",)),
        Step(
            "clippy",
            [
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            ("cargo",),
        ),
        Step("debug-tests", ["cargo", "test", "--workspace"], ("cargo",)),
    ]
    full = fast + [
        Step(
            "release-tests", ["cargo", "test", "--workspace", "--release"], ("cargo",)
        ),
        Step("dependency-policy", ["cargo", "deny", "check"], ("cargo", "cargo-deny")),
    ]
    stress = [
        Step(
            "ignored-stress-tests",
            [
                "cargo",
                "test",
                "--workspace",
                "--release",
                "--",
                "--ignored",
                "--nocapture",
            ],
            ("cargo",),
            1200,
        )
    ]
    return {
        "fast": fast,
        "full": full,
        "stress": stress,
        "smoke": [],
        "all": full + stress,
    }[profile]


def decode_output(value: str | bytes | None) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")


def run_captured(
    command: list[str] | tuple[str, ...],
    timeout: float,
    *,
    cwd: pathlib.Path | None = None,
    env: Mapping[str, str] | None = None,
    combine_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if combine_output else subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = terminate_process_group(process)
        raise subprocess.TimeoutExpired(command, timeout, stdout, stderr) from error
    except KeyboardInterrupt:
        terminate_process_group(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def terminate_process_group(
    process: subprocess.Popen[str],
) -> tuple[str, str | None]:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    else:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    return stdout, stderr


def run_step(step: Step, run_dir: pathlib.Path) -> Result:
    log_path = run_dir / f"{step.name}.log"
    missing = [tool for tool in step.required_tools if shutil.which(tool) is None]
    if missing:
        message = f"missing required tool(s): {', '.join(missing)}"
        log_path.write_text(message + "\n", encoding="utf-8")
        return Result(
            step.name, "failed", step.command, 0.0, None, str(log_path), message
        )

    started = time.monotonic()
    try:
        completed = run_captured(
            step.command,
            step.timeout,
            cwd=ROOT,
            env=harness_env(),
            combine_output=True,
        )
        output, code = completed.stdout, completed.returncode
        status: Status = "passed" if code == 0 else "failed"
        message = "" if code == 0 else f"command exited {code}"
    except subprocess.TimeoutExpired as error:
        output = decode_output(error.stdout) + decode_output(error.stderr)
        status, code, message = "failed", None, f"timed out after {step.timeout}s"
    except OSError as error:
        output = f"unable to execute command: {error}\n"
        status, code, message = "failed", None, str(error)
    duration = time.monotonic() - started
    log_path.write_text(output, encoding="utf-8")
    return Result(
        step.name, status, step.command, duration, code, str(log_path), message
    )


def run_command(
    command: list[os.PathLike[str] | str],
    timeout: float,
    lines: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    printable = [os.fspath(part) for part in command]
    lines.append(f"$ {shlex.join(printable)}\n")
    try:
        completed = run_captured(
            printable,
            timeout,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired as error:
        lines.extend([decode_output(error.stdout), decode_output(error.stderr)])
        label = printable[1] if len(printable) > 1 else printable[0]
        raise RuntimeError(f"{label} timed out after {timeout}s") from error
    lines.extend([completed.stdout, completed.stderr])
    return completed


def build_release(lines: list[str]) -> pathlib.Path:
    build = run_command(
        ["cargo", "build", "--release", "--locked"],
        900,
        lines,
        cwd=ROOT,
        env=harness_env(),
    )
    if build.returncode:
        raise RuntimeError(f"release build exited {build.returncode}")
    binary = HARNESS_TARGET / "release" / "devclean"
    if not binary.is_file():
        raise RuntimeError(f"release build did not create {binary}")
    return binary


def tree_digest(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    root_mode = root.lstat().st_mode
    digest.update(
        f"root:mode={stat.S_IFMT(root_mode):o}:{stat.S_IMODE(root_mode):o}:".encode()
    )
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        mode = path.lstat().st_mode
        digest.update(f":mode={stat.S_IFMT(mode):o}:{stat.S_IMODE(mode):o}:".encode())
        if path.is_symlink():
            digest.update(b"symlink:")
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def require_unchanged(fixture: pathlib.Path, expected: str, command: str) -> None:
    if tree_digest(fixture) != expected:
        raise RuntimeError(f"{command} mutated fixture")


def validate_stored_report(report: object, target: pathlib.Path) -> dict[str, object]:
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
    ):
        raise TypeError("stored report has unsupported schema")
    if report.get("scan_id") != "harness-smoke" or not isinstance(
        report.get("candidates"), list
    ):
        raise TypeError("stored report has invalid identity or candidates schema")
    found = [
        candidate
        for candidate in report["candidates"]
        if isinstance(candidate, dict)
        and isinstance(candidate.get("identity"), dict)
        and candidate["identity"].get("kind") == "filesystem"
        and candidate["identity"].get("path") == str(target)
        and candidate.get("category") == "build"
    ]
    if len(found) != 1:
        raise RuntimeError("Rust target candidate missing or malformed")
    size = found[0].get("physical_bytes_estimate")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise TypeError("recursive size missing or invalid")
    return found[0]


def validate_redacted_export(
    exported: object, raw_output: str, private_root: pathlib.Path
) -> None:
    if (
        not isinstance(exported, dict)
        or type(exported.get("schema_version")) is not int
        or exported["schema_version"] != 1
    ):
        raise TypeError("redacted export has unsupported schema")
    if (
        exported.get("usable_for_cleanup") is not False
        or str(private_root) in raw_output
    ):
        raise RuntimeError("unsafe redacted export")


def smoke_test(run_dir: pathlib.Path) -> Result:
    name, started = "read-only-cli-smoke", time.monotonic()
    log_path, lines = run_dir / "read-only-cli-smoke.log", []
    try:
        binary = build_release(lines)
        harness_tmp = ROOT / "target" / "harness-tmp"
        harness_tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(harness_tmp, 0o700)
        with tempfile.TemporaryDirectory(
            prefix="devclean-harness-", dir=harness_tmp
        ) as raw:
            base, fixture = pathlib.Path(raw), pathlib.Path(raw) / "fixture"
            target, nested = fixture / "target", fixture / "target/debug/deps"
            nested.mkdir(parents=True)
            (fixture / "Cargo.toml").write_text(
                '[package]\nname="harness-fixture"\nversion="0.1.0"\n', encoding="utf-8"
            )
            (nested / "generated.bin").write_bytes(b"devclean-smoke" * 4096)
            config, store = base / "config.toml", base / "reports"
            config.write_text(
                f"approved_roots=[{json.dumps(str(fixture))}]\napproved_caches=[]\nexclusions=[]\n[presentation]\nterminal_rows=10\n",
                encoding="utf-8",
            )
            before = tree_digest(fixture)

            init = run_command([binary, "init", store], 30, lines)
            if init.returncode:
                raise RuntimeError(f"init exited {init.returncode}")
            require_unchanged(fixture, before, "init")

            scan = run_command(
                [binary, "scan", config, store, "harness-smoke"], 60, lines
            )
            if scan.returncode not in (0, 2):
                raise RuntimeError(f"scan exited {scan.returncode}")
            require_unchanged(fixture, before, "scan")

            report_data = json.loads(
                (store / "harness-smoke.json").read_text(encoding="utf-8")
            )
            validate_stored_report(report_data, target)

            rendered = run_command(
                [binary, "report", store, "harness-smoke"], 30, lines
            )
            if rendered.returncode != scan.returncode:
                raise RuntimeError("report/scan exit mismatch")
            if (
                "scan harness-smoke" not in rendered.stdout
                or str(target) not in rendered.stdout
            ):
                raise RuntimeError("terminal report omitted run or candidate identity")
            require_unchanged(fixture, before, "report")

            redacted = run_command(
                [binary, "report", "export", "--redacted", store, "harness-smoke"],
                30,
                lines,
            )
            if redacted.returncode:
                raise RuntimeError(f"redacted export exited {redacted.returncode}")
            exported = json.loads(redacted.stdout)
            validate_redacted_export(exported, redacted.stdout, base)
            require_unchanged(fixture, before, "redacted export")
        status, code, message = "passed", 0, ""
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        status, code, message = "failed", None, str(error)
        lines.append(f"HARNESS ERROR: {error}\n")
    log_path.write_text("".join(lines), encoding="utf-8")
    return Result(
        name,
        status,
        ["internal", "read-only-smoke"],
        time.monotonic() - started,
        code,
        str(log_path),
        message,
    )


def execute_steps(
    steps: list[Step], run_dir: pathlib.Path, fail_fast: bool
) -> list[Result]:
    results: list[Result] = []
    stopped_after: str | None = None
    for step in steps:
        if stopped_after is not None:
            results.append(
                Result(
                    step.name,
                    "skipped",
                    step.command,
                    0.0,
                    None,
                    "",
                    f"not run because fail-fast stopped after {stopped_after}",
                )
            )
            continue
        print(f"[run] {step.name} ...", flush=True)
        result = run_step(step, run_dir)
        results.append(result)
        print(
            f"[{result.status.upper()}] {result.name} ({result.duration_seconds:.2f}s)"
        )
        if fail_fast and result.status == "failed":
            stopped_after = step.name
    return results


def skipped_smoke(after: str) -> Result:
    return Result(
        "read-only-cli-smoke",
        "skipped",
        ["internal", "read-only-smoke"],
        0.0,
        None,
        "",
        f"not run because fail-fast stopped after {after}",
    )


def write_reports(
    profile: str, run_dir: pathlib.Path, results: list[Result], started: str
) -> None:
    if not results or all(result.status == "skipped" for result in results):
        raise ValueError("reports require at least one executed result")
    passed = bool(results) and all(result.status == "passed" for result in results)
    payload = {
        "schema_version": 1,
        "profile": profile,
        "started_at": started,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": passed,
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "architecture": platform.machine(),
        },
        "results": [dataclasses.asdict(result) for result in results],
    }
    summary_bytes = (json.dumps(payload, indent=2) + "\n").encode()
    failures = sum(result.status == "failed" for result in results)
    skipped = sum(result.status == "skipped" for result in results)
    suite = ET.Element(
        "testsuite",
        name=f"devclean-{profile}",
        tests=str(len(results)),
        failures=str(failures),
        skipped=str(skipped),
        time=f"{sum(result.duration_seconds for result in results):.3f}",
    )
    for result in results:
        case = ET.SubElement(
            suite, "testcase", name=result.name, time=f"{result.duration_seconds:.3f}"
        )
        if result.status == "failed":
            ET.SubElement(case, "failure", message=result.message or "failed").text = (
                f"See {result.log}" if result.log else result.message
            )
        elif result.status == "skipped":
            ET.SubElement(case, "skipped", message=result.message)
        ET.SubElement(
            case, "system-out"
        ).text = (
            f"command: {shlex.join(result.command)}\nlog: {result.log or 'not created'}"
        )
    junit_bytes = ET.tostring(suite, encoding="utf-8", xml_declaration=True)
    staged: list[tuple[pathlib.Path, pathlib.Path]] = []
    committed: list[pathlib.Path] = []
    try:
        for destination, content in (
            (run_dir / "summary.json", summary_bytes),
            (run_dir / "junit.xml", junit_bytes),
        ):
            descriptor, raw_temp = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=run_dir
            )
            temporary = pathlib.Path(raw_temp)
            staged.append((temporary, destination))
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        for temporary, destination in staged:
            os.replace(temporary, destination)
            committed.append(destination)
    except OSError:
        for destination in committed:
            destination.unlink(missing_ok=True)
        raise
    finally:
        for temporary, _destination in staged:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=("fast", "full", "stress", "smoke", "all"), default="fast"
    )
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    steps = command_steps(args.profile)
    includes_smoke = args.profile in ("smoke", "all")
    names = [step.name for step in steps] + (
        ["read-only-cli-smoke"] if includes_smoke else []
    )
    if args.list:
        print("\n".join(names))
        return 0

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.output_dir.resolve() / f"{timestamp}-{args.profile}"
    run_dir.mkdir(parents=True, exist_ok=False)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    results = execute_steps(steps, run_dir, args.fail_fast)
    failed = next(
        (result.name for result in results if result.status == "failed"), None
    )
    if includes_smoke:
        if args.fail_fast and failed is not None:
            results.append(skipped_smoke(failed))
        else:
            print("[run] read-only-cli-smoke ...", flush=True)
            result = smoke_test(run_dir)
            results.append(result)
            print(
                f"[{result.status.upper()}] {result.name} ({result.duration_seconds:.2f}s)"
            )
    passed = bool(results) and all(result.status == "passed" for result in results)
    try:
        write_reports(args.profile, run_dir, results, started)
    except OSError as error:
        print(
            f"HARNESS FINALIZATION ERROR: unable to write reports in {run_dir}: {error}; "
            f"test outcome was {'PASS' if passed else 'FAIL'}",
            file=sys.stderr,
        )
        return 1
    print(f"results: {run_dir}\n{'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
