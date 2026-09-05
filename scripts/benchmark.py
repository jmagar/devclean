#!/usr/bin/env python3
"""Repeatable end-to-end benchmarks for devclean scans."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks"
METRIC_PREFIX = "warning: metrics "


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires samples")
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def parse_metrics(report_text: str) -> dict[str, int]:
    line = next(
        (line for line in report_text.splitlines() if line.startswith(METRIC_PREFIX)),
        None,
    )
    if line is None:
        raise ValueError("report omitted metrics warning")
    metrics: dict[str, int] = {}
    for field in line.removeprefix(METRIC_PREFIX).split():
        key, separator, value = field.partition("=")
        if not separator or not value.isdigit():
            raise ValueError(f"malformed metrics field: {field}")
        metrics[key] = int(value)
    return metrics


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        raise ValueError("summary requires samples")
    walls = [float(sample["wall_seconds"]) for sample in samples]
    users = [float(sample["user_seconds"]) for sample in samples]
    systems = [float(sample["system_seconds"]) for sample in samples]
    entries = {int(sample["metrics"]["entries"]) for sample in samples}
    spool = {int(sample["metrics"]["observation_spool_bytes"]) for sample in samples}
    unique = {int(sample["metrics"]["unique_bytes"]) for sample in samples}
    if len(entries) != 1 or len(spool) != 1 or len(unique) != 1:
        raise ValueError("benchmark samples produced inconsistent scan results")
    entry_count = entries.pop()
    spool_bytes = spool.pop()
    return {
        "sample_count": len(samples),
        "median_wall_seconds": statistics.median(walls),
        "p95_wall_seconds": percentile(walls, 0.95),
        "min_wall_seconds": min(walls),
        "median_user_seconds": statistics.median(users),
        "median_system_seconds": statistics.median(systems),
        "entries": entry_count,
        "entries_per_second": entry_count / statistics.median(walls),
        "observation_spool_bytes": spool_bytes,
        "spool_bytes_per_entry": spool_bytes / entry_count if entry_count else 0,
        "unique_bytes": unique.pop(),
    }


def compare(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, float]:
    current_wall = float(current["median_wall_seconds"])
    baseline_wall = float(baseline["median_wall_seconds"])
    if baseline_wall <= 0:
        raise ValueError("baseline median must be positive")
    return {
        "wall_change_percent": (current_wall / baseline_wall - 1) * 100,
        "throughput_change_percent": (
            float(current["entries_per_second"])
            / float(baseline["entries_per_second"])
            - 1
        )
        * 100,
        "spool_change_percent": (
            float(current["observation_spool_bytes"])
            / max(1, float(baseline["observation_spool_bytes"]))
            - 1
        )
        * 100,
    }


def create_fixture(root: pathlib.Path, entries: int) -> None:
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname="devclean-benchmark"\nversion="0.1.0"\n', encoding="utf-8"
    )
    buckets = [
        root / "target/debug/deps",
        root / "target/incremental",
        root / "node_modules/package/dist",
        root / ".cache/tool",
    ]
    for bucket in buckets:
        bucket.mkdir(parents=True)
    payload = b"devclean-benchmark\n"
    for index in range(entries):
        bucket = buckets[index % len(buckets)] / f"shard-{index % 128:03d}"
        bucket.mkdir(exist_ok=True)
        (bucket / f"entry-{index:08d}.bin").write_bytes(payload)


def tree_metadata_digest(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        stat = path.lstat()
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(f":{stat.st_mode}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    return digest.hexdigest()


def configured_roots(config: pathlib.Path) -> list[pathlib.Path]:
    payload = tomllib.loads(config.read_text(encoding="utf-8"))
    configured = [
        pathlib.Path(value).resolve(strict=True)
        for key in ("approved_caches", "approved_roots")
        for value in payload.get(key, [])
    ]
    roots: list[pathlib.Path] = []
    for root in configured:
        if any(root.is_relative_to(parent) for parent in roots):
            continue
        roots = [child for child in roots if not child.is_relative_to(root)]
        roots.append(root)
    return roots


def build_binary() -> pathlib.Path:
    subprocess.run(
        ["cargo", "build", "--release", "--locked"], cwd=ROOT, check=True
    )
    return ROOT / "target/release/devclean"


def run_sample(
    binary: pathlib.Path,
    config: pathlib.Path,
    run_dir: pathlib.Path,
    index: int,
    measured: bool,
) -> dict[str, Any]:
    store = run_dir / (f"sample-{index}" if measured else f"warmup-{index}")
    stdout_path = store.with_suffix(".stdout.log")
    stderr_path = store.with_suffix(".stderr.log")
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        completed = subprocess.run(
            [str(binary), "scan", str(config), str(store), "benchmark"],
            stdout=stdout,
            stderr=stderr,
            timeout=1800,
            check=False,
        )
    wall = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if completed.returncode not in (0, 2):
        raise RuntimeError(
            f"scan exited {completed.returncode}; inspect {stderr_path}"
        )
    report = subprocess.run(
        [str(binary), "report", str(store), "benchmark"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if report.returncode not in (0, 2):
        raise RuntimeError(f"report exited {report.returncode}: {report.stderr}")
    return {
        "index": index,
        "wall_seconds": wall,
        "user_seconds": after.ru_utime - before.ru_utime,
        "system_seconds": after.ru_stime - before.ru_stime,
        "exit_code": completed.returncode,
        "metrics": parse_metrics(report.stdout),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }


def atomic_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--binary", type=pathlib.Path)
    existing = parser.add_mutually_exclusive_group()
    existing.add_argument("--root", type=pathlib.Path, help="existing read-only scan root")
    existing.add_argument(
        "--config",
        type=pathlib.Path,
        help="existing devclean config whose complete real root set is benchmarked",
    )
    parser.add_argument("--entries", type=int)
    parser.add_argument("--root-count", type=int, default=2)
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--samples", type=int)
    parser.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--max-regression-percent", type=float)
    parser.add_argument("--keep-fixture", action="store_true")
    args = parser.parse_args()
    defaults = {"quick": (10_000, 1, 3), "full": (100_000, 2, 5)}[args.profile]
    entries = args.entries if args.entries is not None else defaults[0]
    warmups = args.warmups if args.warmups is not None else defaults[1]
    samples = args.samples if args.samples is not None else defaults[2]
    if entries < 1 or warmups < 0 or samples < 1 or args.root_count < 1:
        parser.error("entries and samples must be positive; warmups may be zero")
    if args.max_regression_percent is not None and args.baseline is None:
        parser.error("--max-regression-percent requires --baseline")

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.output_dir.resolve() / f"{timestamp}-{args.profile}"
    run_dir.mkdir(parents=True, exist_ok=False)
    binary = (args.binary.resolve() if args.binary else build_binary())
    if not binary.is_file():
        raise FileNotFoundError(binary)

    fixture_owner: tempfile.TemporaryDirectory[str] | None = None
    config = run_dir / "benchmark.toml"
    if args.config:
        source_config = args.config.resolve(strict=True)
        scan_roots = configured_roots(source_config)
        if not scan_roots:
            parser.error("--config must approve at least one existing root")
        fixture_digests = None
        source = "existing-config"
        shutil.copyfile(source_config, config)
    elif args.root:
        scan_roots = [args.root.resolve(strict=True)]
        fixture_digests = None
        source = "existing-root"
    else:
        fixture_owner = tempfile.TemporaryDirectory(prefix="fixture-", dir=run_dir)
        fixture_base = pathlib.Path(fixture_owner.name)
        scan_roots = [fixture_base / f"project-{index}" for index in range(args.root_count)]
        quotient, remainder = divmod(entries, args.root_count)
        for index, scan_root in enumerate(scan_roots):
            create_fixture(scan_root, quotient + int(index < remainder))
        fixture_digests = {
            scan_root: tree_metadata_digest(scan_root) for scan_root in scan_roots
        }
        source = "synthetic"
    if not args.config:
        config.write_text(
            f"approved_roots={json.dumps([str(root) for root in scan_roots])}\n"
            "approved_caches=[]\nexclusions=[]\n[presentation]\nterminal_rows=0\n"
            "[limits]\nmax_observations=5000000\nmax_elapsed_seconds=900\n"
            "min_free_bytes=67108864\n",
            encoding="utf-8",
        )

    for index in range(warmups):
        print(f"warmup {index + 1}/{warmups}", flush=True)
        run_sample(binary, config, run_dir, index, False)
    measured_samples = []
    for index in range(samples):
        print(f"sample {index + 1}/{samples}", flush=True)
        measured_samples.append(run_sample(binary, config, run_dir, index, True))
    if fixture_digests is not None:
        for scan_root, expected in fixture_digests.items():
            if tree_metadata_digest(scan_root) != expected:
                raise RuntimeError(f"devclean mutated benchmark fixture {scan_root}")

    aggregate = summarize(measured_samples)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": args.profile,
        "source": source,
        "roots": [str(root) for root in scan_roots],
        "binary": str(binary),
        "host": {
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
        "warmups": warmups,
        "samples": measured_samples,
        "aggregate": aggregate,
    }
    failed = False
    if args.baseline:
        baseline_payload = json.loads(args.baseline.read_text(encoding="utf-8"))
        comparison = compare(aggregate, baseline_payload["aggregate"])
        payload["baseline"] = str(args.baseline.resolve())
        payload["comparison"] = comparison
        if args.max_regression_percent is not None:
            failed = comparison["wall_change_percent"] > args.max_regression_percent
            payload["max_regression_percent"] = args.max_regression_percent
            payload["passed"] = not failed
    atomic_json(run_dir / "summary.json", payload)
    if fixture_owner is not None and args.keep_fixture:
        retained = run_dir / "retained-fixture"
        shutil.move(fixture_owner.name, retained)
    if fixture_owner is not None:
        fixture_owner.cleanup()
    print(json.dumps(aggregate, indent=2))
    print(f"results: {run_dir / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
