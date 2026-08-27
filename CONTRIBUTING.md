# Contributing

Read [AGENT.md](AGENT.md), [the progress log](docs/RUST_REWRITE_PROGRESS.md),
and [the design](docs/RUST_REWRITE_DESIGN.md) before making substantial
changes.

Keep changes small and evidence-driven. Query semantics, rendering, and error
behavior should remain deterministic. The Rust implementation must not acquire
a build, runtime, or test dependency on a Python/Cython SETools checkout.

Before submitting a change, run:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p setools-xtask -- check
python3 scripts/benchmark-cli.py --list
cargo build --release -p setools-cli --bin sesearch
```

Library code and derived library behavior remain LGPL-2.1-only; CLI and test
code remain GPL-2.0-only. New source files must have the appropriate SPDX
identifier.
