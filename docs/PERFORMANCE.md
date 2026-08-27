# Performance benchmarks

The product repository owns a versioned set of end-to-end CLI benchmark
scenarios in [`benchmarks/cli-v1.toml`](../benchmarks/cli-v1.toml). The suite
covers policy loading, exact/regex/indirect search, selected/full semantic
diff, and both graph constructors. It does not call or require legacy SETools.

Build optimized binaries, then run the suite against a representative binary
policy:

```bash
cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
python3 scripts/benchmark-cli.py --policy /path/to/policy
```

Use `--output result.json` to retain the versioned JSON result and `--list` to
inspect scenario IDs. Positional IDs select a subset. `--warmups N` and
`--runs N` override the per-scenario defaults when a different sampling policy
is intentional.

The runner requires Python 3.11 or newer but no third-party packages. It is
Linux-specific because it obtains
each child process's peak resident set directly from `wait4(2)`. It measures
the complete command process, discards successful stdout/stderr, records every
sample, and reports min/median/max wall time and peak RSS. Default scenarios
have one warm-up and three measured runs. `sediff-full` remains part of the v1
contract but is marked manual because it is a heavyweight scenario; run it
explicitly with `python3 scripts/benchmark-cli.py --policy POLICY sediff-full`.
It uses one measured run and no dedicated warm-up.

Results identify the policy and binaries by SHA-256 and record the host, CPU,
tool version, sample counts, and exact placeholder command. They are a baseline,
not a CI pass/fail threshold: compare results only on equivalent hardware,
policy content, build profile, native libraries, cache procedure, and scenario
manifest. Historical Python comparisons and their adapter scripts belong in an
external development/oracle repository, not this standalone product.

## Retained 2026-08-27 baseline

[`docs/benchmarks/2026-08-27-cli-v1-rust.json`](benchmarks/2026-08-27-cli-v1-rust.json)
contains the raw Rust samples from the 1,947,827-byte policy identified by
SHA-256 `6f24f378b14b0cd175c9e34f75b6a173b6cf73d30541962c7e5303cb24d62eee`.
The host used an Intel Xeon Cascadelake virtual CPU and Linux 6.12.101. Median
results were:

| Scenario | Wall time | Peak RSS |
| --- | ---: | ---: |
| `policy-load` | 0.322 s | 30.5 MiB |
| `sesearch-exact` | 0.376 s | 30.3 MiB |
| `sesearch-regex` | 0.330 s | 30.6 MiB |
| `sesearch-indirect` | 0.561 s | 61.3 MiB |
| `sediff-selected` | 0.691 s | 46.6 MiB |
| `sedta-graph` | 0.434 s | 39.1 MiB |
| `seinfoflow-graph` | 1.660 s | 224.4 MiB |

The matching external 4.7.1 oracle run found lower Rust peak RSS in all seven
default scenarios. Rust was faster in six; `sediff-selected` was 0.84x the
legacy speed. The largest observed speedups were 14.0x for the indirect search
and 12.8x for information-flow graph construction. Those ratios are retained
outside this product repository with the legacy adapter and raw oracle samples.

An explicit `sediff-full` run against the same policy did not complete in the
current managed execution environment: the process received SIGKILL after
prolonged analysis. The environment did not expose enough kernel/cgroup data to
attribute the signal to a specific resource limit. No successful wall-time or
peak-RSS result is claimed for that scenario; diagnosing full semantic-diff
retention and computation is the next performance work package.
