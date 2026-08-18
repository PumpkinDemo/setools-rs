# Releasing

The project currently supports standalone source releases and a Linux
`sesearch` binary. The remaining commands are scaffolds, and crates.io
publication is disabled until their public APIs stabilize.

## Release checklist

1. Update `docs/RUST_REWRITE_PROGRESS.md` and decide the release version. The
   current `4.7.1` package version preserves the compatible CLI version string.
2. From a clean checkout, run:

   ```bash
   cargo fmt --all --check
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo build --release -p setools-cli --bin sesearch
   ```

3. Inspect the dynamic requirements with
   `ldd target/release/sesearch` and record the build distribution and
   libsepol/libselinux versions in the release notes.
4. Commit the release state and create a signed or annotated tag:

   ```bash
   git tag -a v4.7.1 -m "setools-rs v4.7.1"
   git push origin main v4.7.1
   ```

5. Create a source archive directly from the tag:

   ```bash
   git archive --format=tar.gz --prefix=setools-rs-4.7.1/ \
     --output=setools-rs-4.7.1.tar.gz v4.7.1
   sha256sum setools-rs-4.7.1.tar.gz
   ```

If a binary archive is published, include `README.md`, `COPYING`, and the two
files under `LICENSES/` beside `sesearch`. Do not label binaries from untested
platforms as supported.
