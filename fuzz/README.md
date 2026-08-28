# Binary-policy fuzzing

This directory is a separate, non-published cargo-fuzz workspace so normal
workspace builds and release archives do not depend on libFuzzer.

Install a nightly toolchain and `cargo-fuzz`, then run:

```text
cargo +nightly fuzz run parse_policy
```

For a bounded local coverage run, for example:

```text
cargo +nightly fuzz run parse_policy -- -max_total_time=60 -max_len=2097152 -rss_limit_mb=1024 -timeout=10
```

Some restricted containers prevent LeakSanitizer from initializing at process
exit. In that environment, use `ASAN_OPTIONS=detect_leaks=0` for this command;
the parser coverage test itself is unchanged.

If a managed runner also imposes a short per-command wall-time or memory limit,
split a longer campaign into finite batches and use a fresh temporary corpus for
each batch. For example:

```text
cargo +nightly fuzz run --sanitizer none parse_policy /tmp/setools-rs-corpus -- -runs=2000 -max_len=262144 -rss_limit_mb=512 -timeout=10
```

This mode still uses libFuzzer coverage feedback. Run the default address
sanitizer configuration in an environment that has sufficient headroom.

The target exercises fixed-header parsing, complete bounded policy parsing,
and owned `Policy` reconstruction for every input that passes validation and
the peak-model budget. It caps input at 2 MiB and peak logical retained
allocation at 64 MiB. Reproducer files
belong in `fuzz/artifacts/` during local work and should be promoted to regular
unit-test fixtures before a bug is considered fixed.
