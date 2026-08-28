# Releasing

The project currently supports standalone source releases and a portable
x86_64 Linux pure Rust static archive for `sesearch`, `seinfo`, `sediff`,
`sedta`, `seinfoflow`, and `sechecker`. A static native-libsepol compatibility
archive is also available as an explicit secondary flavor.
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

3. Build and smoke-test the portable archive against a representative policy:

   ```bash
   scripts/build-portable-release.sh --policy /path/to/policy
   ```

   This must create
   `dist/setools-rs-4.7.1-x86_64-linux-pure-rust-static.tar.gz` and its
   checksum. Extract it into a fresh directory, run `sha256sum --check
   SHA256SUMS`, and confirm `readelf -d bin/TOOL` has no `NEEDED` entry for all
   six tools. Record the rustc, target, loader, and linkage from
   `BUILD-INFO.txt` in the release notes.

   When a release needs the native compatibility flavor too, run the same
   command with `--native-libsepol`. It retains the historic
   `setools-rs-4.7.1-x86_64-linux-static.tar.gz` name and records its pinned
   libsepol version and C compiler in `BUILD-INFO.txt`.
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

7. Attach the pure Rust portable archive and its `.sha256` file to the release.
   The packaging script already includes `README.md`, `COPYING`, both license
   texts, man pages, Bash/Zsh/Fish completions, and the setools-rs corresponding
   source with locked Cargo dependencies vendored for offline rebuilds. A native
   compatibility archive additionally includes the exact libsepol source. Do
   not label untested architectures or platforms as supported.

The static artifact is intentionally separate from the default dynamic source
build. Updating `LIBSEPOL_VERSION` or `LIBSEPOL_SHA256` requires a source,
license, ABI, full-workspace, and real-policy review.
