#!/usr/bin/env bash
# Exercise release validation and packaging failure guards without building or installing code.
# Usage: test-packaging.sh
# Fixtures live in an isolated directory and never invoke privilege or networking commands.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-packaging-test.XXXXXX")"
# cleanup stops only the fixture's isolated GPG agent before removing test files.
cleanup() {
    if [[ -d "${STAGING}/gnupg" ]] && command -v gpgconf >/dev/null; then
        GNUPGHOME="${STAGING}/gnupg" gpgconf --kill gpg-agent
    fi
    rm -rf "${STAGING}"
}
trap cleanup EXIT

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
# A published manifest must describe the exact tag, not merely eight valid assets.
"${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"
expect_failure 'missing or invalid release asset' "${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.1 "${STAGING}/complete assets"
printf '%s\n' changed >>"${STAGING}/complete assets/fortix_0.2.0_linux_amd64.deb"
expect_failure 'release checksums do not match' "${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"
asset_set "${STAGING}/complete assets"
"${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"

"${REPO_ROOT}/scripts/render-homebrew.sh" v0.2.0 "${STAGING}/complete assets/checksums.txt" "${STAGING}/rendered tap"
for TARGET in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
    HASH="$(awk -v name="fortix_0.2.0_${TARGET}.tar.gz" '$2 == name { print $1 }' "${STAGING}/complete assets/checksums.txt")"
    grep -Fq "https://github.com/avhn/fortix/releases/download/v0.2.0/fortix_0.2.0_${TARGET}.tar.gz" "${STAGING}/rendered tap/Formula/fortix.rb"
    grep -Fq "sha256 \"${HASH}\"" "${STAGING}/rendered tap/Formula/fortix.rb"
done
HASH="$(awk '$2 == "fortix_0.2.0_darwin_arm64.dmg" { print $1 }' "${STAGING}/complete assets/checksums.txt")"
grep -Fq 'https://github.com/avhn/fortix/releases/download/v0.2.0/fortix_0.2.0_darwin_arm64.dmg' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq "sha256 \"${HASH}\"" "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'bin.install "fortix", "fortix-helper"' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'sudo fortix-helper install' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'brew install openfortivpn' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'system "#{bin}/fortix", "version"' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'depends_on arch: :arm64' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'depends_on macos: ">= :ventura"' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'not notarized' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'xattr -dr com.apple.quarantine /Applications/Fortix.app' "${STAGING}/rendered tap/Casks/fortix.rb"
[[ "$(grep '^[[:space:]]*zap ' "${STAGING}/rendered tap/Casks/fortix.rb")" == '  zap trash: "~/Library/Preferences/com.github.avhn.fortix.plist"' ]]
if grep -Eq '@[A-Z0-9_]+@' "${STAGING}/rendered tap/Formula/fortix.rb" "${STAGING}/rendered tap/Casks/fortix.rb"; then
    printf '%s\n' 'unresolved Homebrew template placeholder' >&2
    exit 1
fi
if command -v ruby >/dev/null; then
    ruby -c "${STAGING}/rendered tap/Formula/fortix.rb"
    ruby -c "${STAGING}/rendered tap/Casks/fortix.rb"
else
    printf '%s\n' 'SKIP: Ruby syntax checks (ruby is unavailable).'
fi
expect_failure 'output already exists' "${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0 "${STAGING}/complete assets/checksums.txt" "${STAGING}/rendered tap"
expect_failure 'invalid stable release version' "${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0-rc.1 "${STAGING}/complete assets/checksums.txt" "${STAGING}/prerelease tap"
expect_failure 'invalid stable release version' "${REPO_ROOT}/scripts/render-homebrew.sh" '0.2.0";system("false")' "${STAGING}/complete assets/checksums.txt" "${STAGING}/unsafe tap"
grep -v 'darwin_arm64.dmg$' "${STAGING}/complete assets/checksums.txt" >"${STAGING}/missing-checksum"
expect_failure 'missing or duplicate checksum' "${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0 "${STAGING}/missing-checksum" "${STAGING}/missing tap"
cat "${STAGING}/complete assets/checksums.txt" "${STAGING}/complete assets/checksums.txt" >"${STAGING}/duplicate-checksum"
expect_failure 'missing or duplicate checksum' "${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0 "${STAGING}/duplicate-checksum" "${STAGING}/duplicate tap"
sed 's/^[0-9a-f]/z/' "${STAGING}/complete assets/checksums.txt" >"${STAGING}/invalid-checksum"
expect_failure 'invalid checksum' "${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0 "${STAGING}/invalid-checksum" "${STAGING}/invalid tap"
[[ ! -e "${STAGING}/missing tap" && ! -e "${STAGING}/duplicate tap" && ! -e "${STAGING}/invalid tap" ]]
sed 's/fortix_0.2.0_/fortix_0.2.0+build.1_/g' "${STAGING}/complete assets/checksums.txt" >"${STAGING}/metadata-checksum"
"${REPO_ROOT}/scripts/render-homebrew.sh" 0.2.0+build.1 "${STAGING}/metadata-checksum" "${STAGING}/metadata tap"
grep -Fq '/v0.2.0+build.1/fortix_0.2.0+build.1_darwin_arm64.dmg' "${STAGING}/metadata tap/Casks/fortix.rb"

expect_failure 'usage:' "${REPO_ROOT}/scripts/build-apt-repo.sh"
expect_failure 'invalid signing key fingerprint' "${REPO_ROOT}/scripts/build-apt-repo.sh" "${STAGING}" "${STAGING}/invalid apt" unsafe
if command -v apt-ftparchive >/dev/null && command -v gpg >/dev/null && command -v dpkg-deb >/dev/null; then
    export GNUPGHOME="${STAGING}/gnupg" APT_SIGNING_PASSPHRASE=packaging-fixture-passphrase
    mkdir -m 0700 "${GNUPGHOME}"
    gpg --batch --pinentry-mode loopback --passphrase-fd 3 \
        --quick-generate-key 'fortix packaging fixture <packaging@example.invalid>' rsa2048 sign 0 \
        3<<<"${APT_SIGNING_PASSPHRASE}"
    FINGERPRINT="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
    # make_debs produces inert package metadata for both architectures at the given version.
    # It writes DEBS_OUTPUT for the repository fixture and never includes maintainer scripts.
    make_debs() {
        local version="${1}" architecture package
        DEBS_OUTPUT="${STAGING}/debs-${version}"
        mkdir -p "${DEBS_OUTPUT}"
        for architecture in amd64 arm64; do
            package="${STAGING}/package-${version}-${architecture}"
            mkdir -p "${package}/DEBIAN" "${package}/usr/share/doc/fortix"
            printf 'Package: fortix\nVersion: %s\nArchitecture: %s\nMaintainer: Packaging Fixture <packaging@example.invalid>\nDescription: Inert packaging fixture\n' \
                "${version}" "${architecture}" >"${package}/DEBIAN/control"
            printf '%s\n' "${version}" >"${package}/usr/share/doc/fortix/fixture"
            dpkg-deb --build "${package}" "${DEBS_OUTPUT}/fortix_${version}_linux_${architecture}.deb" >/dev/null
        done
    }
    make_debs 0.1.0
    "${REPO_ROOT}/scripts/build-apt-repo.sh" "${DEBS_OUTPUT}" "${STAGING}/apt" "${FINGERPRINT}"
    make_debs 0.2.0
    "${REPO_ROOT}/scripts/build-apt-repo.sh" "${DEBS_OUTPUT}" "${STAGING}/apt" "${FINGERPRINT}"
    # An identical rerun is safe, and both older packages stay available in the pool.
    "${REPO_ROOT}/scripts/build-apt-repo.sh" "${DEBS_OUTPUT}" "${STAGING}/apt" "${FINGERPRINT}"
    [[ "$(find "${STAGING}/apt/pool/main" -name '*.deb' | wc -l | tr -d ' ')" -eq 4 ]]
    grep -Fxq 'Suite: stable' "${STAGING}/apt/dists/stable/Release"
    grep -Fxq 'Components: main' "${STAGING}/apt/dists/stable/Release"
    grep -Fxq 'Architectures: amd64 arm64' "${STAGING}/apt/dists/stable/Release"
    for ARCH in amd64 arm64; do
        INDEX="${STAGING}/apt/dists/stable/main/binary-${ARCH}/Packages"
        grep -Fxq 'Version: 0.1.0' "${INDEX}"
        grep -Fxq 'Version: 0.2.0' "${INDEX}"
        [[ "$(grep -c '^Architecture:' "${INDEX}")" -eq 2 ]]
        [[ "$(grep -c "^Architecture: ${ARCH}$" "${INDEX}")" -eq 2 ]]
        grep -Fxq "Filename: pool/main/fortix_0.2.0_linux_${ARCH}.deb" "${INDEX}"
        gzip -dc "${INDEX}.gz" >"${STAGING}/uncompressed"
        cmp "${INDEX}" "${STAGING}/uncompressed"
    done
    # A public-only keyring must verify both signature formats without the private key.
    mkdir -m 0700 "${STAGING}/verify-gnupg"
    gpg --homedir "${STAGING}/verify-gnupg" --batch --no-default-keyring --keyring "${STAGING}/apt/fortix-archive-keyring.gpg" \
        --verify "${STAGING}/apt/dists/stable/InRelease"
    gpg --homedir "${STAGING}/verify-gnupg" --batch --no-default-keyring --keyring "${STAGING}/apt/fortix-archive-keyring.gpg" \
        --verify "${STAGING}/apt/dists/stable/Release.gpg" "${STAGING}/apt/dists/stable/Release"
    gpg --batch --with-colons --show-keys "${STAGING}/apt/fortix-archive-keyring.asc" | grep -Fq ":${FINGERPRINT}:"
    cp "${STAGING}/apt/dists/stable/InRelease" "${STAGING}/untouched-InRelease"
    WRONG_FINGERPRINT=7F1D1CA8B09790EAC0FA70DA1A52C72D8C1F6F06
    expect_failure 'signing key fingerprint mismatch' "${REPO_ROOT}/scripts/build-apt-repo.sh" "${DEBS_OUTPUT}" "${STAGING}/apt" "${WRONG_FINGERPRINT}"
    printf '%s\n' changed >>"${DEBS_OUTPUT}/fortix_0.2.0_linux_amd64.deb"
    expect_failure 'existing Debian package differs' "${REPO_ROOT}/scripts/build-apt-repo.sh" "${DEBS_OUTPUT}" "${STAGING}/apt" "${FINGERPRINT}"
    cmp "${STAGING}/untouched-InRelease" "${STAGING}/apt/dists/stable/InRelease"
    printf '%s\n' 'Signed apt indexes, public keys and previous-version retention tests passed.'
else
    printf '%s\n' 'SKIP: signed apt repository tests (apt-ftparchive, gpg or dpkg-deb is unavailable).'
fi
printf '%s\n' 'Packaging guards, combined checksums and Homebrew renderer tests passed.'
