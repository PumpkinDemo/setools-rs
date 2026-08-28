#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly PROJECT_VERSION="4.7.1"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PORTABLE_ROOT="${PROJECT_ROOT}/target/portable"
readonly DIST_DIR="${PROJECT_ROOT}/dist"
readonly BINARIES=(sesearch seinfo sediff sedta seinfoflow sechecker)

policy_path=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --policy)
            if [[ $# -lt 2 || -n $policy_path ]]; then
                printf 'usage: %s [--policy BINARY_POLICY]\n' "$0" >&2
                exit 2
            fi
            policy_path=$2
            shift 2
            ;;
        --help|-h)
            printf 'usage: %s [--policy BINARY_POLICY]\n' "$0"
            exit 0
            ;;
        *)
            printf 'usage: %s [--policy BINARY_POLICY]\n' "$0" >&2
            exit 2
            ;;
    esac
done

if [[ $(uname -s) != "Darwin" ]]; then
    printf 'macOS release packaging must run on macOS\n' >&2
    exit 1
fi

case $(uname -m) in
    x86_64)
        readonly RELEASE_ARCH="x86_64"
        ;;
    arm64)
        readonly RELEASE_ARCH="arm64"
        ;;
    *)
        printf 'macOS release packaging supports x86_64 and arm64 only\n' >&2
        exit 1
        ;;
esac

for command in awk cargo codesign file find grep install lipo mv otool sed shasum sort strip tail tar; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command is missing: %s\n' "$command" >&2
        exit 1
    fi
done

mkdir -p "$PORTABLE_ROOT" "$DIST_DIR"
build_dir=$(mktemp -d "${PORTABLE_ROOT}/macos-build.XXXXXX")
if [[ -z ${build_dir:-} || ! -d "$build_dir" || $build_dir != "$PORTABLE_ROOT"/macos-build.* ]]; then
    printf 'refusing unexpected build directory: %s\n' "${build_dir:-<empty>}" >&2
    exit 1
fi

cleanup() {
    if [[ -n ${build_dir:-} && -d "$build_dir" && $build_dir == "$PORTABLE_ROOT"/macos-build.* ]]; then
        rm -rf -- "$build_dir"
    fi
}
trap cleanup EXIT

readonly CARGO_TARGET_DIR="${build_dir}/cargo-target"
export CARGO_TARGET_DIR
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

cargo build --locked --release -p setools-cli \
    --bin sesearch --bin seinfo --bin sediff \
    --bin sedta --bin seinfoflow --bin sechecker

readonly PACKAGE_NAME="setools-rs-${PROJECT_VERSION}-macos-${RELEASE_ARCH}"
readonly PACKAGE_ROOT="${build_dir}/${PACKAGE_NAME}"
install -d "$PACKAGE_ROOT/bin"

for binary in "${BINARIES[@]}"; do
    artifact="${CARGO_TARGET_DIR}/release/${binary}"
    strip -x "$artifact"
    codesign --force --sign - "$artifact"
    codesign --verify --strict "$artifact"
    if [[ $(lipo -archs "$artifact") != "$RELEASE_ARCH" ]]; then
        printf 'unexpected Mach-O architecture for %s: ' "$binary" >&2
        lipo -archs "$artifact" >&2
        exit 1
    fi
    if ! file "$artifact" | grep -q "Mach-O 64-bit executable ${RELEASE_ARCH}"; then
        printf 'release binary is not the expected Mach-O executable: %s\n' "$binary" >&2
        file "$artifact" >&2
        exit 1
    fi
    unexpected_dependencies=$(otool -L "$artifact" \
        | tail -n +2 \
        | awk '{print $1}' \
        | grep -Ev '^(/usr/lib/|/System/Library/)' || true)
    if [[ -n $unexpected_dependencies ]]; then
        printf 'macOS binary has a non-system dynamic dependency: %s\n%s\n' \
            "$binary" "$unexpected_dependencies" >&2
        exit 1
    fi
    if [[ $("$artifact" --version) != "$PROJECT_VERSION" ]]; then
        printf 'unexpected version output from %s\n' "$binary" >&2
        exit 1
    fi
    install -m 0755 "$artifact" "$PACKAGE_ROOT/bin/$binary"
done

if [[ -n "$policy_path" ]]; then
    if [[ ! -f "$policy_path" ]]; then
        printf 'smoke-test policy does not exist: %s\n' "$policy_path" >&2
        exit 1
    fi
    "$PACKAGE_ROOT/bin/seinfo" "$policy_path" >/dev/null
    "$PACKAGE_ROOT/bin/sesearch" --allow "$policy_path" >/dev/null
fi

expected_entries=$(printf 'bin/%s\n' "${BINARIES[@]}" | LC_ALL=C sort)
actual_entries=$(cd "$PACKAGE_ROOT" && find . -type f -print | sed 's|^\./||' | LC_ALL=C sort)
if [[ $actual_entries != "$expected_entries" ]]; then
    printf 'macOS archive must contain only the six CLI binaries\n' >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected_entries" "$actual_entries" >&2
    exit 1
fi

readonly ARTIFACT="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
COPYFILE_DISABLE=1 tar -czf "${ARTIFACT}.part" -C "$build_dir" "$PACKAGE_NAME"
mv -- "${ARTIFACT}.part" "$ARTIFACT"
(
    cd "$DIST_DIR"
    shasum -a 256 "${PACKAGE_NAME}.tar.gz" >"${PACKAGE_NAME}.tar.gz.sha256"
)

printf 'macOS release: %s\n' "$ARTIFACT"
printf 'checksum: '
cat "${ARTIFACT}.sha256"
