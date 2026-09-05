"""Contract tests for the devclean benchmark harness."""

from __future__ import annotations

import importlib.util
import pathlib
import os
import sys
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("benchmark.py")
SPEC = importlib.util.spec_from_file_location("devclean_benchmark", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


class BenchmarkContractTests(unittest.TestCase):
    def test_metrics_parser_and_summary_are_deterministic(self) -> None:
        metrics = BENCHMARK.parse_metrics(
            "scan x\nwarning: metrics entries=100 observation_spool_bytes=2500 "
            "unique_bytes=9000\n"
        )
        samples = [
            {"wall_seconds": wall, "user_seconds": 1, "system_seconds": 2, "metrics": metrics}
            for wall in (4.0, 2.0, 3.0)
        ]
        summary = BENCHMARK.summarize(samples)
        self.assertEqual(summary["median_wall_seconds"], 3.0)
        self.assertEqual(summary["entries_per_second"], 100 / 3)
        self.assertEqual(summary["spool_bytes_per_entry"], 25)

    def test_comparison_reports_regression_and_improvement_direction(self) -> None:
        baseline = {
            "median_wall_seconds": 10,
            "entries_per_second": 100,
            "observation_spool_bytes": 1000,
        }
        current = {
            "median_wall_seconds": 8,
            "entries_per_second": 125,
            "observation_spool_bytes": 500,
        }
        comparison = BENCHMARK.compare(current, baseline)
        self.assertAlmostEqual(comparison["wall_change_percent"], -20)
        self.assertAlmostEqual(comparison["throughput_change_percent"], 25)
        self.assertAlmostEqual(comparison["spool_change_percent"], -50)

    def test_comparison_rejects_zero_throughput_baseline(self) -> None:
        current = {
            "median_wall_seconds": 1,
            "entries_per_second": 1,
            "observation_spool_bytes": 0,
        }
        baseline = dict(current, entries_per_second=0)
        with self.assertRaisesRegex(ValueError, "throughput"):
            BENCHMARK.compare(current, baseline)

    def test_private_outputs_and_minimized_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw)
            source = base / "source.toml"
            source.write_text(
                'approved_roots=["/tmp/project"]\napproved_caches=[]\n'
                'exclusions=[]\n[presentation]\nterminal_rows=4\n',
                encoding="utf-8",
            )
            destination = base / "benchmark.toml"
            BENCHMARK.write_private(destination, BENCHMARK.minimized_config(source))
            self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
            self.assertNotIn("source.toml", destination.read_text(encoding="utf-8"))

    def test_percentile_interpolates_and_rejects_empty_samples(self) -> None:
        self.assertEqual(BENCHMARK.percentile([1, 2, 3], 0.5), 2)
        with self.assertRaises(ValueError):
            BENCHMARK.percentile([], 0.95)

    def test_configured_roots_deduplicates_overlapping_real_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = pathlib.Path(raw)
            parent = base / "parent"
            child = parent / "child"
            cache = base / "cache"
            child.mkdir(parents=True)
            cache.mkdir()
            config = base / "config.toml"
            config.write_text(
                f'approved_roots=["{parent}", "{child}"]\n'
                f'approved_caches=["{cache}"]\nexclusions=[]\n',
                encoding="utf-8",
            )

            self.assertEqual(
                BENCHMARK.configured_roots(config),
                [cache.resolve(), parent.resolve()],
            )


if __name__ == "__main__":
    unittest.main()
