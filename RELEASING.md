# Releasing

The project currently supports standalone source releases and Linux binaries
for `sesearch`, `seinfo`, `sediff`, `sedta`, `seinfoflow`, and `sechecker`.
Crates.io publication remains disabled until the public library APIs stabilize.

## Release checklist

1. Update `docs/RUST_REWRITE_PROGRESS.md` and decide the release version. The
   current `4.7.1` package version preserves the compatible CLI version string.
2. From a clean checkout, run:

   ```bash
   cargo fmt --all --check
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo run -p setools-xtask -- check
   cargo build --release -p setools-cli --bin sesearch --bin seinfo --bin sediff --bin sedta --bin seinfoflow --bin sechecker
   ```

3. Inspect the dynamic requirements with
   `ldd target/release/sesearch` (and each other published binary) and record
   the build distribution and libsepol/libselinux versions in the release notes.
4. On the benchmark host, run the default suite against the retained
   representative policy and archive the JSON with the release evidence:

   ```bash
   python3 scripts/benchmark-cli.py \
     --policy /path/to/policy \
     --output setools-rs-performance.json
   ```

   Review `docs/PERFORMANCE.md` before comparing results. Run the manual
   `sediff-full` scenario separately because it is intentionally excluded from
   the default suite.
5. Commit the release state and create a signed or annotated tag:

   ```bash
   git tag -a v4.7.1 -m "setools-rs v4.7.1"
   git push origin main v4.7.1
   ```

6. Create a source archive directly from the tag:

   ```bash
   git archive --format=tar.gz --prefix=setools-rs-4.7.1/ \
     --output=setools-rs-4.7.1.tar.gz v4.7.1
   sha256sum setools-rs-4.7.1.tar.gz
   ```

If a binary archive is published, include `README.md`, `COPYING`, the two files
under `LICENSES/`, all six files under `man/man1/`, and the Bash/Zsh/Fish files
under `completions/` beside the published binaries. Do not label binaries from
untested platforms as supported.
