# devclean

`devclean` is a conservative, detection-first inventory tool for developer
artifacts. It discovers generated files and external resources, explains why
they were classified, and writes private, versioned JSON reports.

The current release is intentionally read-only. It does not delete, prune,
trash, or otherwise modify detected resources.

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
devclean scan CONFIG STORE SCAN_ID
devclean report STORE SCAN_ID
devclean report export --redacted STORE SCAN_ID
devclean explain STORE SCAN_ID CANDIDATE_ID
```

A scan configuration explicitly approves project roots, cache roots,
exclusions, and optionally a pinned Docker daemon identity. Reports are
advisory and cannot authorize cleanup.

## Development

The comprehensive harness provides consistent local and CI profiles:

```sh
python3 scripts/test-harness.py --profile fast    # format, Clippy, debug tests
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
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --release
cargo deny check
```

The ignored stress qualifications can be run with:

```sh
cargo test --workspace --release -- --ignored --nocapture
```

## License

Licensed under either Apache-2.0 or MIT, at your option.
