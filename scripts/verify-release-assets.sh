#!/usr/bin/env bash
# Verify downloaded release assets against the final, complete checksum manifest.
# Usage: verify-release-assets.sh VERSION ARTIFACT_DIRECTORY
# VERSION may start with v; the directory must contain exactly eight assets and checksums.txt.
set -euo pipefail

# die rejects incomplete, substituted or version-mismatched release downloads.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 2 ]] || die "usage: verify-release-assets.sh VERSION ARTIFACT_DIRECTORY"
VERSION="${1#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "invalid release version"
[[ -d "${2}" && ! -L "${2}" ]] || die "invalid artifact directory"
ARTIFACTS="$(cd "${2}" && pwd)"
[[ -f "${ARTIFACTS}/checksums.txt" && ! -L "${ARTIFACTS}/checksums.txt" && -s "${ARTIFACTS}/checksums.txt" ]] || die "invalid checksum file"
shopt -s nullglob dotglob
FILES=("${ARTIFACTS}"/*)
[[ ${#FILES[@]} -eq 9 ]] || die "incomplete release artifact set"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-release-verify.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
for SUFFIX in darwin_amd64.tar.gz darwin_arm64.tar.gz linux_amd64.tar.gz linux_arm64.tar.gz \
    linux_amd64.deb linux_arm64.deb darwin_arm64.dmg darwin_arm64.app.zip; do
    NAME="fortix_${VERSION}_${SUFFIX}"
    [[ -f "${ARTIFACTS}/${NAME}" && ! -L "${ARTIFACTS}/${NAME}" && -s "${ARTIFACTS}/${NAME}" ]] || die "missing or invalid release asset: ${NAME}"
    cp "${ARTIFACTS}/${NAME}" "${STAGING}/${NAME}"
done
# Regenerating the canonical manifest also rejects unsafe names and duplicate entries.
"${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}"
cmp -s "${STAGING}/checksums.txt" "${ARTIFACTS}/checksums.txt" || die "release checksums do not match"
printf '%s\n' 'Final release assets and checksums verified.'
