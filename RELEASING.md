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
   `dist/setools-rs-4.7.1-linux-x86_64.tar.gz` and its
   external `.sha256` file. Verify that checksum, extract the archive into a
   fresh directory, and confirm its only regular files are the six executables
   under `bin/`. Confirm `readelf -d bin/TOOL` has no `NEEDED` entry for each
   tool.

   When a release needs the native compatibility flavor too, run the same
   command with `--native-libsepol`. Its distinct archive name is
   `setools-rs-4.7.1-linux-x86_64-native.tar.gz`. The pinned libsepol version,
   source URL, and checksum remain recorded in the packaging script and ADR
   0004 rather than being copied into the binary archive.
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

   Pushing the `v4.7.1` tag starts `.github/workflows/release.yml`. It first
   runs the same full Fedora workspace verification as CI, then builds the
   pure Rust static archive on x86_64 Linux and creates or updates GitHub
   Release `v4.7.1`. The workflow checks that the tag exactly matches the
   Cargo workspace version before it can publish, and uploads both the archive
   and its `.sha256` file. Re-running the same tag workflow replaces those two
   assets rather than creating a second release.

   If the tag was pushed before this workflow existed, or a release currently
   shows only GitHub's generated source archives, use **Actions → Release → Run
   workflow**, enter the existing tag, and run it manually. It checks out that
   tag, verifies its version, then uploads or replaces the binary archive and
   checksum on the existing release.

   The release job grants only `contents: write` to its `GITHUB_TOKEN`, which
   is required to create a GitHub Release. If an organization policy prevents
   that permission, enable Actions write access for this repository or provide
   an equivalent narrowly scoped release credential before pushing the tag.

6. GitHub automatically exposes source archives for the release tag. For an
   independently generated source archive, run:

   ```bash
   git archive --format=tar.gz --prefix=setools-rs-4.7.1/ \
     --output=setools-rs-4.7.1.tar.gz v4.7.1
   sha256sum setools-rs-4.7.1.tar.gz
   ```

7. Check the automated GitHub Release and its uploaded pure Rust archive. The
   binary archive must contain only the six files under `bin/`; use the tagged
   repository or GitHub's generated source archives for `README.md`, licenses,
   man pages, completions, and source. Do not label untested architectures or
   platforms as supported.

The static artifact is intentionally separate from the default dynamic source
build. Updating `LIBSEPOL_VERSION` or `LIBSEPOL_SHA256` requires a source,
license, ABI, full-workspace, and real-policy review.
