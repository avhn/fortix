#!/usr/bin/env bash
# Check Swift tests and the release executable without relying on a Go Makefile.
# Usage: bash macos/check.sh [scratch-directory]
# The optional directory retains build output; otherwise a private temporary directory is cleaned.
set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PACKAGE_DIR
if [[ $# -gt 1 ]]; then
    printf 'usage: bash macos/check.sh [scratch-directory]\n' >&2
    exit 2
fi
if [[ $# -eq 1 ]]; then
    SCRATCH_DIR="${1}"
else
    SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fortix-swift-check.XXXXXX")"
    trap 'rm -rf "${SCRATCH_DIR}"' EXIT
fi
readonly SCRATCH_DIR

# An inherited alarm survives exec, bounding each Swift command on stock macOS.
/usr/bin/perl -e 'alarm 180; exec @ARGV; die "could not start Swift\n"' \
    swift test --package-path "${PACKAGE_DIR}" --scratch-path "${SCRATCH_DIR}" --jobs 2
/usr/bin/perl -e 'alarm 180; exec @ARGV; die "could not start Swift\n"' \
    swift build --package-path "${PACKAGE_DIR}" --scratch-path "${SCRATCH_DIR}" --jobs 2 -c release
