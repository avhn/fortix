#!/usr/bin/env bash
# Render a stable release's formula and cask from the combined SHA-256 manifest.
# Usage: render-homebrew.sh VERSION CHECKSUMS_FILE OUTDIR
# VERSION may start with v; CHECKSUMS_FILE supplies exact asset hashes; OUTDIR must not exist.
set -euo pipefail

# die reports invalid inputs without leaving a partial tap update.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

# checksum returns one validated hash for an exact asset basename from CHECKSUMS.
# Missing, duplicate or malformed entries fail before any output directory is created.
checksum() {
    local name="${1}" hash
    hash="$(awk -v name="${name}" '$2 == name { hash = $1; count++; if (NF != 2) bad = 1 } END { if (count != 1 || bad) exit 1; print hash }' "${CHECKSUMS}")" || die "missing or duplicate checksum: ${name}"
    [[ "${hash}" =~ ^[0-9a-f]{64}$ ]] || die "invalid checksum: ${name}"
    printf '%s\n' "${hash}"
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 3 ]] || die "usage: render-homebrew.sh VERSION CHECKSUMS_FILE OUTDIR"
VERSION="${1#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(\+[0-9A-Za-z.]+)?$ ]] || die "invalid stable release version"
CHECKSUMS="${2}"
[[ -f "${CHECKSUMS}" && ! -L "${CHECKSUMS}" && -s "${CHECKSUMS}" ]] || die "invalid checksum file"
OUTPUT="${3}"
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || die "output already exists: ${OUTPUT}"
DARWIN_ARM64="$(checksum "fortix_${VERSION}_darwin_arm64.tar.gz")"
DARWIN_AMD64="$(checksum "fortix_${VERSION}_darwin_amd64.tar.gz")"
LINUX_ARM64="$(checksum "fortix_${VERSION}_linux_arm64.tar.gz")"
LINUX_AMD64="$(checksum "fortix_${VERSION}_linux_amd64.tar.gz")"
DMG="$(checksum "fortix_${VERSION}_darwin_arm64.dmg")"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-homebrew.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
mkdir -p "${STAGING}/Formula" "${STAGING}/Casks"
# Only validated version and hash characters reach Ruby source substitutions.
for TEMPLATE in formula cask; do
    DIRECTORY=Formula
    [[ "${TEMPLATE}" != cask ]] || DIRECTORY=Casks
    sed -e "s/@VERSION@/${VERSION}/g" \
        -e "s/@DARWIN_ARM64_SHA256@/${DARWIN_ARM64}/g" \
        -e "s/@DARWIN_AMD64_SHA256@/${DARWIN_AMD64}/g" \
        -e "s/@LINUX_ARM64_SHA256@/${LINUX_ARM64}/g" \
        -e "s/@LINUX_AMD64_SHA256@/${LINUX_AMD64}/g" \
        -e "s/@DMG_SHA256@/${DMG}/g" \
        "${REPO_ROOT}/packaging/homebrew/${TEMPLATE}.rb.in" >"${STAGING}/${DIRECTORY}/fortix.rb"
done
mkdir -p "$(dirname "${OUTPUT}")"
mv "${STAGING}" "${OUTPUT}"
