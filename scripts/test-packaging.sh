#!/usr/bin/env bash
# Exercise release validation and packaging failure guards without building or installing code.
# Usage: test-packaging.sh
# Fixtures live in an isolated directory and never invoke privilege or networking commands.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-packaging-test.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT

# expect_failure requires a nonzero exit and a specific diagnostic from a guarded command.
expect_failure() {
    local diagnostic="${1}"
    shift
    if "${@}" >"${STAGING}/stdout" 2>"${STAGING}/stderr"; then
        printf 'expected failure: %s\n' "${*}" >&2
        exit 1
    fi
    grep -Fq "${diagnostic}" "${STAGING}/stderr"
}

# asset_set creates all eight release files, including CLI archives for both architectures.
asset_set() {
    local directory="${1}" name
    mkdir -p "${directory}"
    for name in fortix_0.2.0_darwin_amd64.tar.gz fortix_0.2.0_darwin_arm64.tar.gz \
        fortix_0.2.0_linux_amd64.tar.gz fortix_0.2.0_linux_arm64.tar.gz \
        fortix_0.2.0_linux_amd64.deb fortix_0.2.0_linux_arm64.deb \
        fortix_0.2.0_darwin_arm64.app.zip fortix_0.2.0_darwin_arm64.dmg; do
        printf '%s\n' "${name}" >"${directory}/${name}"
    done
}

asset_set "${STAGING}/complete assets"
"${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/complete assets"
[[ "$(wc -l <"${STAGING}/complete assets/checksums.txt" | tr -d ' ')" -eq 8 ]]
LC_ALL=C sort -k 2 "${STAGING}/complete assets/checksums.txt" >"${STAGING}/sorted"
cmp "${STAGING}/sorted" "${STAGING}/complete assets/checksums.txt"
(
    cd "${STAGING}/complete assets"
    shasum -a 256 -c checksums.txt >/dev/null
)
cp "${STAGING}/complete assets/checksums.txt" "${STAGING}/original-checksums"
expect_failure 'checksums.txt already exists' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/complete assets"
cmp "${STAGING}/original-checksums" "${STAGING}/complete assets/checksums.txt"

asset_set "${STAGING}/incomplete"
rm "${STAGING}/incomplete/fortix_0.2.0_linux_arm64.deb"
expect_failure 'incomplete release artifact set' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/incomplete"
[[ ! -e "${STAGING}/incomplete/checksums.txt" ]]

asset_set "${STAGING}/unexpected"
printf '%s\n' untrusted >"${STAGING}/unexpected/metadata.json"
expect_failure 'unexpected asset' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/unexpected"

asset_set "${STAGING}/symlink"
rm "${STAGING}/symlink/fortix_0.2.0_linux_arm64.deb"
ln -s "${STAGING}/complete assets/fortix_0.2.0_linux_arm64.deb" "${STAGING}/symlink/fortix_0.2.0_linux_arm64.deb"
expect_failure 'invalid asset' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/symlink"

asset_set "${STAGING}/unsafe"
mv "${STAGING}/unsafe/fortix_0.2.0_linux_arm64.deb" "${STAGING}/unsafe/unsafe name.deb"
expect_failure 'unsafe asset name' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/unsafe"

asset_set "${STAGING}/empty"
: >"${STAGING}/empty/fortix_0.2.0_linux_arm64.deb"
expect_failure 'invalid asset' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/empty"

asset_set "${STAGING}/duplicate-platform"
mv "${STAGING}/duplicate-platform/fortix_0.2.0_darwin_amd64.tar.gz" "${STAGING}/duplicate-platform/fortix_0.2.1_darwin_arm64.tar.gz"
expect_failure 'missing or duplicate CLI archive' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/duplicate-platform"

asset_set "${STAGING}/duplicate-deb"
mv "${STAGING}/duplicate-deb/fortix_0.2.0_linux_amd64.deb" "${STAGING}/duplicate-deb/fortix_0.2.1_linux_arm64.deb"
expect_failure 'missing or duplicate Debian package' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/duplicate-deb"

expect_failure 'usage:' "${REPO_ROOT}/scripts/build-macos-app.sh"
expect_failure 'invalid release version' "${REPO_ROOT}/scripts/build-macos-app.sh" '<invalid>' "${STAGING}/injected.app"
[[ ! -e "${STAGING}/injected.app" ]]
expect_failure 'usage:' "${REPO_ROOT}/scripts/build-dmg.sh"
if [[ "$(uname -s)" == Darwin ]]; then
    expect_failure 'input must be an app directory' "${REPO_ROOT}/scripts/build-dmg.sh" "${STAGING}/missing.app" "${STAGING}/missing.dmg"
    mkdir "${STAGING}/unsigned.app"
    expect_failure 'output already exists' "${REPO_ROOT}/scripts/build-dmg.sh" "${STAGING}/unsigned.app" "${STAGING}/complete assets/fortix_0.2.0_darwin_arm64.dmg"
    if [[ "$(uname -m)" == arm64 ]]; then
        printf '%s\n' retained >"${STAGING}/existing.app"
        expect_failure 'output already exists' "${REPO_ROOT}/scripts/build-macos-app.sh" v0.2.0 "${STAGING}/existing.app"
        [[ "$(cat "${STAGING}/existing.app")" == retained ]]
    fi
fi
printf '%s\n' 'Packaging guards and combined checksum tests passed.'
