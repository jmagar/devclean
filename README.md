# devclean

`devclean` is a conservative, detection-first inventory tool for developer
artifacts. It discovers generated files and external resources, explains why
they were classified, and writes private, versioned JSON reports.

The current release is intentionally read-only. It does not delete, prune,
trash, or otherwise modify detected resources.

## Desktop app

Devclean includes a native, GPU-rendered GPUI desktop app for macOS. It keeps
the scanner's conservative safety boundary while making the inventory easy to
configure and explore:

- add or remove explicitly approved scan locations with the native folder picker
- run scans in the background without blocking the interface
- filter findings by Safe, Review, Protected, or Unknown tier
- inspect size estimates, positive evidence, and protection signals
- reopen the latest local report and export a privacy-preserving redacted copy

Build both the scanner and app, then launch the app:

```sh
cargo build --workspace
cargo run -p devclean-gui --bin devclean-app
```

To create a normal macOS application bundle:

```sh
./scripts/package-macos.sh release
open target/release/Devclean.app
```

The app expects the `devclean` scanner beside `devclean-app`. For custom bundles,
set `DEVCLEAN_BIN` to an absolute scanner path. App data is stored privately in
`~/Library/Application Support/devclean` with owner-only permissions.

GPUI uses Metal on macOS. The `runtime_shaders` feature keeps development builds
working with Command Line Tools alone; a full Xcode installation is not required.

## Detectors

- Docker images, containers, volumes, networks, layers, and build cache
- Rust, Python, Node.js, Go, JVM/Android, Elixir/Erlang, and Apple build output
- Git worktrees
- Browser-testing, editor, agent, cache, log, diagnostic, and general generated artifacts

## Build

```sh
cargo build --release
```

The binary is written to `target/release/devclean`.

## Commands

```text
devclean init STORE
devclean init --macos [STORE]
devclean scan CONFIG STORE SCAN_ID
devclean report STORE SCAN_ID
devclean report export --redacted STORE SCAN_ID
devclean explain STORE SCAN_ID CANDIDATE_ID
```

A scan configuration explicitly approves project roots, cache roots,
exclusions, and optionally a pinned Docker daemon identity. Reports are
advisory and cannot authorize cleanup.

`init --macos` creates a useful, reviewable starting configuration from
existing paths on the current Mac. It includes well-known re-downloadable
cache roots such as `~/Library/Caches`, `~/.cache`, npm, Cargo registry/Git
caches, and Xcode DerivedData. It also discovers recognizable project roots at
a bounded depth below `~/workspace` and `~/unraid`, plus `~/u8`. Project roots
are scanned with bounded root concurrency and progress on stderr; an incomplete root withholds
only its own size estimates, not estimates for complete siblings. The preset
intentionally does not approve stateful roots such as all of `~/.rustup` or
`~/.local/share`. Approved cache roots are emitted as top-level candidates so
their complete recursive size is visible even when their children have
tool-specific names. When `STORE` is omitted, it defaults to `~/.devclean`.

Project discovery is best-effort and records its inspected, included, skipped,
and truncated counts in the generated configuration. It searches only the
documented roots to depth two, inspects at most 4,096 directories, ignores
symlinks and unreadable entries, and stops descending after recognizing a
project. Approved traversal roots are canonicalized and overlapping descendants
are removed before scanning, so a child project is not scanned twice beneath an
already-approved parent. Cache roots are scheduled first. Two independent roots
and up to four metadata operations are processed concurrently through bounded
queues and one shared observation/deadline budget.

Scans are deliberately bounded for low-disk operation. Defaults allow at most
50,000,000 filesystem observations across the entire scan, 900 seconds of
filesystem traversal, a 2 GiB fallback observation spool, a 256 MiB candidate spool,
and require a 3 GiB free-space reserve at the report store. The reserve exceeds
the combined worst-case bounded temporary/report files. Override the
admission/work limits in `[limits]` only after reviewing the impact:

```toml
[limits]
max_observations = 50000000
max_elapsed_seconds = 900
min_free_bytes = 3221225472
```

Progress is emitted as JSON events on stderr for scan limits, root starts,
every 100,000 entries, and root completion. Completion events include entry and
metadata-read counts, queue high-water, elapsed time, remaining observation
budget, coverage, and bounded diagnostic reasons. Metadata is resolved lazily
only for candidate-like paths, so there is no separate silent recursive
metadata pass.

Root-local traversal failure withholds only estimates beneath that root. Global
accounting, candidate-sink, or spool limits can still withhold estimates for all
filesystem candidates; the report warnings identify these global invalidators.
Cancellation is currently all-or-nothing: completed roots are not persisted for
resume. The global observation and elapsed-time limits bound repeated work until
durable resumable checkpoints are implemented.

## Development

The comprehensive harness provides consistent local and CI profiles:

```sh
python3 scripts/test-harness.py --profile fast    # harness, format, Clippy, debug tests
python3 scripts/test-harness.py --profile full    # fast + release + dependency policy
python3 scripts/test-harness.py --profile stress  # ignored scale qualifications
python3 scripts/test-harness.py --profile smoke   # disposable read-only CLI fixture
python3 scripts/test-harness.py --profile all     # complete qualification
```

Each run writes per-step logs, `summary.json`, and `junit.xml` beneath
`artifacts/test-harness/`. Use `--fail-fast` to stop at the first failure or
`--list` to inspect a profile. The smoke profile operates only on a temporary
fixture, verifies the fixture remains byte-for-byte unchanged, and confirms
that redacted output cannot authorize cleanup.

The equivalent checks remain available directly:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace performance_contract
cargo test --workspace
cargo test --workspace --release
cargo deny check
```

The ignored stress qualifications can be run with:

```sh
cargo test --workspace --release -- --ignored --nocapture
```

## Benchmarks

The benchmark harness builds an optimized binary, creates a deterministic
read-only fixture outside the timed region, warms filesystem caches, and writes
every sample plus aggregate throughput and spool metrics to
`artifacts/benchmarks/`:

```sh
python3 scripts/benchmark.py --profile quick
python3 scripts/benchmark.py --profile full
python3 scripts/benchmark.py --profile full --root-count 4
python3 scripts/benchmark.py --root ~/.cargo/registry --samples 5
python3 scripts/benchmark.py --config ~/.devclean/config.toml --samples 3
```

Compare a run with a saved result, optionally failing when median wall time
regresses beyond an explicitly chosen tolerance:

```sh
python3 scripts/benchmark.py \
  --baseline artifacts/benchmarks/PREVIOUS/summary.json \
  --max-regression-percent 10
```

Timing gates are opt-in because shared CI machines and filesystem caches add
noise. Deterministic performance contracts remain part of the required test
profile.

## License

Licensed under either Apache-2.0 or MIT, at your option.
