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
