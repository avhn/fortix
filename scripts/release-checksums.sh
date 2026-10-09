#!/usr/bin/env bash
# Validate the complete release asset set and emit one sorted SHA-256 manifest.
# Usage: release-checksums.sh ARTIFACT_DIRECTORY
# The directory must contain four CLI archives, two debs, one app zip and one DMG.
set -euo pipefail

# die fails closed rather than publishing a release with missing or unexpected assets.
die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: release-checksums.sh ARTIFACT_DIRECTORY"
[[ -d "${1}" && ! -L "${1}" ]] || die "artifact directory is missing or a symlink"
ARTIFACTS="$(cd "${1}" && pwd)"
[[ ! -e "${ARTIFACTS}/checksums.txt" && ! -L "${ARTIFACTS}/checksums.txt" ]] || die "checksums.txt already exists"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-checksums.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
ARCHIVES=0 DEBS=0 DMGS=0 APPS=0
shopt -s nullglob dotglob
FILES=("${ARTIFACTS}"/*)
for FILE in "${FILES[@]}"; do
    [[ -f "${FILE}" && ! -L "${FILE}" && -s "${FILE}" ]] || die "invalid asset: ${FILE}"
    NAME="$(basename "${FILE}")"
    [[ "${NAME}" =~ ^[A-Za-z0-9_.+-]+$ && "${NAME}" != -* ]] || die "unsafe asset name: ${NAME}"
    case "${NAME}" in
        fortix_*_darwin_amd64.tar.gz | fortix_*_darwin_arm64.tar.gz | fortix_*_linux_amd64.tar.gz | fortix_*_linux_arm64.tar.gz) ARCHIVES=$((ARCHIVES + 1)) ;;
        fortix_*_linux_amd64.deb | fortix_*_linux_arm64.deb) DEBS=$((DEBS + 1)) ;;
        fortix_*_darwin_arm64.dmg) DMGS=$((DMGS + 1)) ;;
        fortix_*_darwin_arm64.app.zip) APPS=$((APPS + 1)) ;;
        *) die "unexpected asset: ${NAME}" ;;
    esac
    printf '%s\n' "${NAME}" >>"${STAGING}/names"
done
[[ "${ARCHIVES}" -eq 4 && "${DEBS}" -eq 2 && "${DMGS}" -eq 1 && "${APPS}" -eq 1 ]] || die "incomplete release artifact set"
# A repeated platform cannot stand in for a missing architecture, even with eight files.
for TARGET in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
    [[ "$(grep -c "_${TARGET}\.tar\.gz$" "${STAGING}/names")" -eq 1 ]] || die "missing or duplicate CLI archive: ${TARGET}"
done
for TARGET in linux_amd64 linux_arm64; do
    [[ "$(grep -c "_${TARGET}\.deb$" "${STAGING}/names")" -eq 1 ]] || die "missing or duplicate Debian package: ${TARGET}"
done
LC_ALL=C sort "${STAGING}/names" >"${STAGING}/sorted"
# Relative basenames keep the manifest usable after users download the release.
(
    cd "${ARTIFACTS}"
    while IFS= read -r NAME; do
        shasum -a 256 "${NAME}"
    done <"${STAGING}/sorted"
) >"${STAGING}/checksums.txt"
mv "${STAGING}/checksums.txt" "${ARTIFACTS}/checksums.txt"
