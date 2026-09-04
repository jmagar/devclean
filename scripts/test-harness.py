#!/usr/bin/env python3
"""Repeatable local and CI qualification harness for devclean."""
from __future__ import annotations
import argparse, dataclasses, datetime as dt, hashlib, json, os, pathlib, platform, shutil, subprocess, tempfile, time
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "test-harness"
HARNESS_TARGET = ROOT / "target" / "test-harness"

def harness_env() -> dict[str, str]:
    return {**os.environ, "CARGO_TERM_COLOR": "never", "NO_COLOR": "1", "CARGO_TARGET_DIR": str(HARNESS_TARGET)}

@dataclasses.dataclass
class Step:
    name: str
    command: list[str]
    required_tools: tuple[str, ...] = ()
    timeout: int = 900

@dataclasses.dataclass
class Result:
    name: str
    status: str
    command: list[str]
    duration_seconds: float
    exit_code: int | None
    log: str
    message: str = ""

def command_steps(profile: str) -> list[Step]:
    fast = [
        Step("format", ["cargo", "fmt", "--all", "--", "--check"], ("cargo",)),
        Step("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], ("cargo",)),
        Step("debug-tests", ["cargo", "test", "--workspace"], ("cargo",)),
    ]
    full = fast + [
        Step("release-tests", ["cargo", "test", "--workspace", "--release"], ("cargo",)),
        Step("dependency-policy", ["cargo", "deny", "check"], ("cargo", "cargo-deny")),
    ]
    stress = [Step("ignored-stress-tests", ["cargo", "test", "--workspace", "--release", "--", "--ignored", "--nocapture"], ("cargo",), 1200)]
    return {"fast": fast, "full": full, "stress": stress, "smoke": [], "all": full + stress}[profile]

def run_step(step: Step, run_dir: pathlib.Path) -> Result:
    log_path = run_dir / f"{step.name}.log"
    missing = [tool for tool in step.required_tools if shutil.which(tool) is None]
    if missing:
        message = f"missing required tool(s): {', '.join(missing)}"
        log_path.write_text(message + "\n")
        return Result(step.name, "failed", step.command, 0.0, None, str(log_path), message)
    started = time.monotonic()
    try:
        completed = subprocess.run(step.command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=step.timeout, env=harness_env())
        output, code = completed.stdout, completed.returncode
        status, message = ("passed", "") if code == 0 else ("failed", f"command exited {code}")
    except subprocess.TimeoutExpired as error:
        def decoded(value: str | bytes | None) -> str:
            return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")

        output = decoded(error.stdout) + decoded(error.stderr)
        status, code, message = "failed", None, f"timed out after {step.timeout}s"
    duration = time.monotonic() - started
    log_path.write_text(output, encoding="utf-8")
    return Result(step.name, status, step.command, duration, code, str(log_path), message)

def tree_digest(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file() and not path.is_symlink(): digest.update(path.read_bytes())
    return digest.hexdigest()

def smoke_test(run_dir: pathlib.Path) -> Result:
    name, started = "read-only-cli-smoke", time.monotonic()
    log_path, lines = run_dir / "read-only-cli-smoke.log", []
    try:
        build = subprocess.run(["cargo", "build", "--release", "--locked"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, env=harness_env())
        lines.append(build.stdout)
        if build.returncode: raise RuntimeError(f"release build exited {build.returncode}")
        binary = HARNESS_TARGET / "release" / "devclean"
        harness_tmp = ROOT / "target" / "harness-tmp"
        harness_tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(harness_tmp, 0o700)
        with tempfile.TemporaryDirectory(prefix="devclean-harness-", dir=harness_tmp) as raw:
            base, fixture = pathlib.Path(raw), pathlib.Path(raw) / "fixture"
            target, nested = fixture / "target", fixture / "target/debug/deps"
            nested.mkdir(parents=True)
            (fixture / "Cargo.toml").write_text('[package]\nname="harness-fixture"\nversion="0.1.0"\n')
            (nested / "generated.bin").write_bytes(b"devclean-smoke" * 4096)
            config, store = base / "config.toml", base / "reports"
            config.write_text(f'approved_roots=[{json.dumps(str(fixture))}]\napproved_caches=[]\nexclusions=[]\n[presentation]\nterminal_rows=10\n')
            before = tree_digest(fixture)
            init = subprocess.run([binary, "init", store], text=True, capture_output=True, timeout=30)
            lines += [init.stdout, init.stderr]
            if init.returncode: raise RuntimeError(f"init exited {init.returncode}")
            scan = subprocess.run([binary, "scan", config, store, "harness-smoke"], text=True, capture_output=True, timeout=60)
            lines += [scan.stdout, scan.stderr]
            if scan.returncode not in (0, 2): raise RuntimeError(f"scan exited {scan.returncode}")
            if before != tree_digest(fixture): raise RuntimeError("scan mutated fixture")
            report = json.loads((store / "harness-smoke.json").read_text())
            found = [c for c in report["candidates"] if c.get("identity", {}).get("path") == str(target)]
            if len(found) != 1 or found[0].get("category") != "build": raise RuntimeError("Rust target candidate missing")
            if not isinstance(found[0].get("physical_bytes_estimate"), int): raise RuntimeError("recursive size missing")
            rendered = subprocess.run([binary, "report", store, "harness-smoke"], text=True, capture_output=True, timeout=30)
            if rendered.returncode != scan.returncode: raise RuntimeError("report/scan exit mismatch")
            redacted = subprocess.run([binary, "report", "export", "--redacted", store, "harness-smoke"], text=True, capture_output=True, timeout=30)
            exported = json.loads(redacted.stdout)
            if redacted.returncode or exported.get("usable_for_cleanup") is not False or str(fixture) in redacted.stdout: raise RuntimeError("unsafe redacted export")
        status, code, message = "passed", 0, ""
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        status, code, message = "failed", None, str(error); lines.append(f"HARNESS ERROR: {error}\n")
    log_path.write_text("".join(lines), encoding="utf-8")
    return Result(name, status, ["internal", "read-only-smoke"], time.monotonic()-started, code, str(log_path), message)

def write_reports(profile: str, run_dir: pathlib.Path, results: list[Result], started: str) -> None:
    payload = {"schema_version": 1, "profile": profile, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "passed": all(r.status == "passed" for r in results), "host": {"platform": platform.platform(), "python": platform.python_version(), "architecture": platform.machine()}, "results": [dataclasses.asdict(r) for r in results]}
    (run_dir / "summary.json").write_text(json.dumps(payload, indent=2) + "\n")
    suite = ET.Element("testsuite", name=f"devclean-{profile}", tests=str(len(results)), failures=str(sum(r.status == "failed" for r in results)), time=f"{sum(r.duration_seconds for r in results):.3f}")
    for result in results:
        case = ET.SubElement(suite, "testcase", name=result.name, time=f"{result.duration_seconds:.3f}")
        if result.status == "failed": ET.SubElement(case, "failure", message=result.message or "failed").text = f"See {result.log}"
        ET.SubElement(case, "system-out").text = f"command: {' '.join(result.command)}\nlog: {result.log}"
    ET.ElementTree(suite).write(run_dir / "junit.xml", encoding="utf-8", xml_declaration=True)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("fast","full","stress","smoke","all"), default="fast")
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fail-fast", action="store_true"); parser.add_argument("--list", action="store_true")
    args = parser.parse_args(); steps = command_steps(args.profile)
    names = [s.name for s in steps] + (["read-only-cli-smoke"] if args.profile in ("smoke","all") else [])
    if args.list: print("\n".join(names)); return 0
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.output_dir.resolve() / f"{timestamp}-{args.profile}"
    run_dir.mkdir(parents=True, exist_ok=False); started = dt.datetime.now(dt.timezone.utc).isoformat(); results=[]
    for step in steps:
        print(f"[{args.profile}] {step.name} ...", flush=True); result=run_step(step, run_dir); results.append(result); print(f"[{result.status.upper()}] {result.name} ({result.duration_seconds:.2f}s)")
        if args.fail_fast and result.status == "failed": break
    if (not args.fail_fast or all(r.status == "passed" for r in results)) and args.profile in ("smoke","all"):
        print(f"[{args.profile}] read-only-cli-smoke ...", flush=True); result=smoke_test(run_dir); results.append(result); print(f"[{result.status.upper()}] {result.name} ({result.duration_seconds:.2f}s)")
    write_reports(args.profile, run_dir, results, started); passed=bool(results) and all(r.status == "passed" for r in results)
    print(f"results: {run_dir}\n{'PASS' if passed else 'FAIL'}"); return 0 if passed else 1

if __name__ == "__main__": raise SystemExit(main())
