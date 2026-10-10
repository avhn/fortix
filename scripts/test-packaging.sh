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
    if ! grep -Fq "${diagnostic}" "${STAGING}/stderr"; then
        printf 'expected diagnostic %s from: %s\n' "${diagnostic}" "${*}" >&2
        cat "${STAGING}/stderr" >&2
        exit 1
    fi
}

# asset_set creates all nine payloads, including the canonical Windows preview ZIP.
asset_set() {
    local directory="${1}" name
    mkdir -p "${directory}"
    for name in fortix_0.2.0_darwin_amd64.tar.gz fortix_0.2.0_darwin_arm64.tar.gz \
        fortix_0.2.0_linux_amd64.tar.gz fortix_0.2.0_linux_arm64.tar.gz \
        fortix_0.2.0_linux_amd64.deb fortix_0.2.0_linux_arm64.deb \
        fortix_0.2.0_darwin_arm64.app.zip fortix_0.2.0_darwin_arm64.dmg fortix_0.2.0_windows_amd64.zip; do
        printf '%s\n' "${name}" >"${directory}/${name}"
    done
}

asset_set "${STAGING}/complete assets"
"${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/complete assets"
[[ "$(wc -l <"${STAGING}/complete assets/checksums.txt" | tr -d ' ')" -eq 9 ]]
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
# A published manifest must describe the exact tag, not merely nine valid payloads.
"${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"
expect_failure 'missing or invalid release asset' "${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.1 "${STAGING}/complete assets"
printf '%s\n' changed >>"${STAGING}/complete assets/fortix_0.2.0_linux_amd64.deb"
expect_failure 'release checksums do not match' "${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"
asset_set "${STAGING}/complete assets"
"${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/complete assets"

# The Windows payload adds exactly one manifest line and cannot change Unix channel outputs.
[[ "$(find "${STAGING}/complete assets" -type f | wc -l | tr -d ' ')" -eq 10 ]]
cp -R "${STAGING}/complete assets" "${STAGING}/missing-windows"
rm "${STAGING}/missing-windows/fortix_0.2.0_windows_amd64.zip"
expect_failure 'incomplete release artifact set' "${REPO_ROOT}/scripts/verify-release-assets.sh" v0.2.0 "${STAGING}/missing-windows"
rm "${STAGING}/missing-windows/checksums.txt"
expect_failure 'incomplete release artifact set' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/missing-windows"
asset_set "${STAGING}/unknown-windows"
mv "${STAGING}/unknown-windows/fortix_0.2.0_windows_amd64.zip" "${STAGING}/unknown-windows/fortix_0.2.0_windows_arm64.zip"
expect_failure 'unexpected asset' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/unknown-windows"
asset_set "${STAGING}/wrong-windows-version"
mv "${STAGING}/wrong-windows-version/fortix_0.2.0_windows_amd64.zip" "${STAGING}/wrong-windows-version/fortix_0.2.1_windows_amd64.zip"
expect_failure 'unexpected Windows asset' "${REPO_ROOT}/scripts/release-checksums.sh" "${STAGING}/wrong-windows-version"
grep -v '_windows_amd64.zip$' "${STAGING}/complete assets/checksums.txt" >"${STAGING}/unix-checksums"
"${REPO_ROOT}/scripts/render-homebrew.sh" v0.2.0 "${STAGING}/unix-checksums" "${STAGING}/unix tap"
"${REPO_ROOT}/scripts/render-homebrew.sh" v0.2.0 "${STAGING}/complete assets/checksums.txt" "${STAGING}/rendered tap"
cmp "${STAGING}/unix tap/Formula/fortix.rb" "${STAGING}/rendered tap/Formula/fortix.rb"
cmp "${STAGING}/unix tap/Casks/fortix.rb" "${STAGING}/rendered tap/Casks/fortix.rb"
# Independently hash only Unix payloads to verify their sorted manifest lines are unchanged.
(
    cd "${STAGING}/missing-windows"
    for FILE in *; do shasum -a 256 "${FILE}"; done
) >"${STAGING}/expected-unix-checksums"
cmp "${STAGING}/unix-checksums" "${STAGING}/expected-unix-checksums"
for TARGET in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
    HASH="$(awk -v name="fortix_0.2.0_${TARGET}.tar.gz" '$2 == name { print $1 }' "${STAGING}/complete assets/checksums.txt")"
    grep -Fq "https://github.com/avhn/fortix/releases/download/v0.2.0/fortix_0.2.0_${TARGET}.tar.gz" "${STAGING}/rendered tap/Formula/fortix.rb"
    grep -Fq "sha256 \"${HASH}\"" "${STAGING}/rendered tap/Formula/fortix.rb"
done
HASH="$(awk '$2 == "fortix_0.2.0_darwin_arm64.dmg" { print $1 }' "${STAGING}/complete assets/checksums.txt")"
grep -Fq 'https://github.com/avhn/fortix/releases/download/v0.2.0/fortix_0.2.0_darwin_arm64.dmg' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq "sha256 \"${HASH}\"" "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'bin.install "fortix", "fortix-helper"' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'sudo "#{opt_bin}/fortix-helper" install' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'brew install openfortivpn' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'system "#{bin}/fortix", "version"' "${STAGING}/rendered tap/Formula/fortix.rb"
grep -Fq 'depends_on arch: :arm64' "${STAGING}/rendered tap/Casks/fortix.rb"
grep -Fq 'depends_on macos: :ventura' "${STAGING}/rendered tap/Casks/fortix.rb"
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

# Windows packaging never executes fixture binaries and gates its hash override explicitly.
# package-windows.sh checks every platform's notices and resolves Windows module licenses
# offline, so fill the module cache first; go.sum verifies every download.
# The Windows ZIP cases need the Go release that go.mod names, which the apt publishing
# job does not install; the CI check job always runs them.
if GOTOOLCHAIN=local go -C "${REPO_ROOT}" list -m >/dev/null 2>&1; then
    go -C "${REPO_ROOT}" mod download
    mkdir "${STAGING}/windows inputs"
    for FILE in fortix.exe fortix-helper.exe FortixApp.exe wintun.dll; do
        printf 'inert fixture: %s\n' "${FILE}" >"${STAGING}/windows inputs/${FILE}"
    done
    WINDOWS_INPUTS=("${STAGING}/windows inputs/fortix.exe" "${STAGING}/windows inputs/fortix-helper.exe" "${STAGING}/windows inputs/FortixApp.exe" "${STAGING}/windows inputs/wintun.dll")
    DLL_HASH="$(shasum -a 256 "${WINDOWS_INPUTS[3]}" | awk '{print $1}')"
    expect_failure 'usage:' "${REPO_ROOT}/scripts/package-windows.sh"
    expect_failure 'invalid release version' "${REPO_ROOT}/scripts/package-windows.sh" unsafe "${STAGING}/unsafe zip" "${WINDOWS_INPUTS[@]}"
    expect_failure 'Wintun DLL SHA-256 mismatch' "${REPO_ROOT}/scripts/package-windows.sh" v0.2.0 "${STAGING}/bad dll" "${WINDOWS_INPUTS[@]}"
    expect_failure 'Wintun DLL SHA-256 mismatch' env FORTIX_PACKAGING_TEST=0 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" "${REPO_ROOT}/scripts/package-windows.sh" v0.2.0 "${STAGING}/ignored override" "${WINDOWS_INPUTS[@]}"
    expect_failure 'Wintun DLL SHA-256 mismatch' env -u FORTIX_PACKAGING_TEST FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" "${REPO_ROOT}/scripts/package-windows.sh" v0.2.0 "${STAGING}/unset test mode" "${WINDOWS_INPUTS[@]}"
    ln -s "${WINDOWS_INPUTS[3]}" "${STAGING}/linked-wintun.dll"
    expect_failure 'invalid Windows payload' "${REPO_ROOT}/scripts/package-windows.sh" v0.2.0 "${STAGING}/linked dll" "${WINDOWS_INPUTS[0]}" "${WINDOWS_INPUTS[1]}" "${WINDOWS_INPUTS[2]}" "${STAGING}/linked-wintun.dll"
    [[ ! -e "${STAGING}/bad dll" && ! -e "${STAGING}/ignored override" ]]
    # A missing Windows-only license fails closed without changing cached modules or Unix notices.
    mkdir "${STAGING}/notice tools" "${STAGING}/missing license"
    cat >"${STAGING}/notice tools/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${GOPROXY:-}" == off && "${GOSUMDB:-}" == off && "${GOTOOLCHAIN:-}" == local ]] || {
    printf '%s\n' 'notice generation must stay offline' >&2
    exit 1
}
if [[ "${3:-}" == list && "${4:-}" == -m && "${6:-}" == '{{.Dir}}' && "${7:-}" == github.com/danieljoos/wincred ]]; then
    printf '%s\n' "${FORTIX_NOTICE_FIXTURE_DIR}"
else
    exec "${FORTIX_REAL_GO}" "${@}"
fi
EOF
    chmod 0700 "${STAGING}/notice tools/go"
    expect_failure 'missing version or license for github.com/danieljoos/wincred' env \
        PATH="${STAGING}/notice tools:${PATH}" FORTIX_REAL_GO="$(command -v go)" FORTIX_NOTICE_FIXTURE_DIR="${STAGING}/missing license" \
        FORTIX_PACKAGING_TEST=1 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" SOURCE_DATE_EPOCH=1700000000 \
        "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/missing license output" "${WINDOWS_INPUTS[@]}"
    [[ ! -e "${STAGING}/missing license output" ]]
    env FORTIX_PACKAGING_TEST=1 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" SOURCE_DATE_EPOCH=1700000000 TZ=UTC \
        "${REPO_ROOT}/scripts/package-windows.sh" v0.2.0 "${STAGING}/windows first" "${WINDOWS_INPUTS[@]}"
    # An isolated PATH models Windows hosts with only python or a broken python3 alias.
    mkdir "${STAGING}/common tools" "${STAGING}/python tools" "${STAGING}/python3 stub" "${STAGING}/no python"
    for TOOL in bash dirname sed mktemp cp rm cat sort go diff grep mkdir mv; do
        ln -s "$(command -v "${TOOL}")" "${STAGING}/common tools/${TOOL}"
    done
    ln -s "$(command -v python3)" "${STAGING}/python tools/python"
    cat >"${STAGING}/python3 stub/python3" <<'EOF'
#!/usr/bin/env bash
# Model a discoverable interpreter alias that cannot run Python.
set -euo pipefail
printf '%s\n' probed >>"${FORTIX_PYTHON_PROBE_LOG}"
exit 9
EOF
    chmod 0700 "${STAGING}/python3 stub/python3"
    ln -s "${STAGING}/python3 stub/python3" "${STAGING}/no python/python"
    expect_failure 'Python 3.8 or newer is required' env \
        PATH="${STAGING}/no python:${STAGING}/python3 stub:${STAGING}/common tools" FORTIX_PYTHON_PROBE_LOG="${STAGING}/failed probes" \
        "$(command -v bash)" "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/no python output" "${WINDOWS_INPUTS[@]}"
    [[ "$(wc -l <"${STAGING}/failed probes" | tr -d ' ')" -eq 2 && ! -e "${STAGING}/no python output" ]]
    for PYTHON_PATH in "${STAGING}/python tools" "${STAGING}/python3 stub:${STAGING}/python tools"; do
        env PATH="${PYTHON_PATH}:${STAGING}/common tools" FORTIX_PYTHON_PROBE_LOG="${STAGING}/fallback probe" \
            FORTIX_PACKAGING_TEST=1 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" SOURCE_DATE_EPOCH=1700000000 TZ=UTC \
            "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/python output" "${WINDOWS_INPUTS[@]}"
        cmp "${STAGING}/windows first/fortix_0.2.0_windows_amd64.zip" "${STAGING}/python output/fortix_0.2.0_windows_amd64.zip"
        rm -rf "${STAGING}/python output"
    done
    [[ "$(cat "${STAGING}/fallback probe")" == probed ]]
    # Changed source metadata and timezone cannot affect deterministic ZIP bytes.
    touch -t 200001010000 "${WINDOWS_INPUTS[@]}"
    chmod 0600 "${WINDOWS_INPUTS[@]}"
    env FORTIX_PACKAGING_TEST=1 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" SOURCE_DATE_EPOCH=1700000000 TZ=Pacific/Honolulu \
        FORTIX_WINDOWS_CLI="${WINDOWS_INPUTS[0]}" FORTIX_WINDOWS_HELPER="${WINDOWS_INPUTS[1]}" \
        FORTIX_WINDOWS_APP="${WINDOWS_INPUTS[2]}" WINTUN_DLL="${WINDOWS_INPUTS[3]}" \
        "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/windows second"
    cmp "${STAGING}/windows first/fortix_0.2.0_windows_amd64.zip" "${STAGING}/windows second/fortix_0.2.0_windows_amd64.zip"
    expect_failure 'output already exists' "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/windows first" "${WINDOWS_INPUTS[@]}"
    expect_failure 'invalid SOURCE_DATE_EPOCH' env FORTIX_PACKAGING_TEST=1 FORTIX_TEST_WINTUN_SHA256="${DLL_HASH}" SOURCE_DATE_EPOCH=invalid \
        "${REPO_ROOT}/scripts/package-windows.sh" 0.2.0 "${STAGING}/invalid epoch" "${WINDOWS_INPUTS[@]}"
    python3 -I - "${STAGING}/windows first/fortix_0.2.0_windows_amd64.zip" "${REPO_ROOT}" "${STAGING}/windows inputs" <<'PY'
import os
import pathlib
import subprocess
import sys
import zipfile
repo, inputs = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
prefix = 'fortix_0.2.0_windows_amd64/'
expected = ['FortixApp.exe', 'LICENSE', 'NOTICES.txt', 'README.txt', 'fortix-helper.exe', 'fortix.exe', 'wintun.dll']
with zipfile.ZipFile(sys.argv[1]) as archive:
    assert archive.namelist() == [prefix + name for name in expected]
    assert all(info.date_time == (2023, 11, 14, 22, 13, 20) and not info.extra for info in archive.infolist())
    for name in ['FortixApp.exe', 'fortix-helper.exe', 'fortix.exe', 'wintun.dll']:
        assert archive.read(prefix + name) == (inputs / name).read_bytes()
    assert archive.read(prefix + 'LICENSE') == (repo / 'LICENSE').read_bytes()
    notices = archive.read(prefix + 'NOTICES.txt')
    assert notices.startswith((repo / 'THIRD_PARTY_NOTICES.txt').read_bytes())
    assert b'===== github.com/danieljoos/wincred ' in notices
    # Both Windows architectures must have one versioned header and the full linked license texts.
    for arch in ['amd64', 'arm64']:
        go_env = dict(os.environ, GOOS='windows', GOARCH=arch, CGO_ENABLED='0',
                      GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', GOMAXPROCS='2', GOFLAGS='-p=2')
        modules = subprocess.run(
            ['go', '-C', str(repo), 'list', '-deps', '-f',
             '{{with .Module}}{{if not .Main}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}{{end}}',
             './cmd/fortix', './cmd/fortix-helper'],
            env=go_env, check=True, capture_output=True, text=True, timeout=60)
        for entry in set(modules.stdout.splitlines()) - {''}:
            module, version, directory = entry.split('|')
            assert notices.count(f'===== {module} {version} ====='.encode()) == 1
            assert (pathlib.Path(directory) / 'LICENSE').read_bytes() in notices
            for name in ['NOTICE', 'PATENTS']:
                notice_file = pathlib.Path(directory) / name
                if notice_file.is_file():
                    assert notice_file.read_bytes() in notices
    for name in ['WINTUN-LICENSE.txt', 'DOTNET-LICENSE.txt']:
        assert (repo / 'packaging/windows' / name).read_bytes() in notices
    assert b'Wintun 0.14.1' in notices and b'https://www.wintun.net/builds/wintun-0.14.1.zip' in notices
    assert b'.NET runtime (MIT)' in notices and b'https://github.com/dotnet/runtime/blob/main/LICENSE.TXT' in notices
    readme = archive.read(prefix + 'README.txt')
    for text in [b'preview', b'unsigned', b'SmartScreen', b'fortix-helper.exe install --user <name>', b'fortix-helper.exe uninstall', b'docs/windows.md']:
        assert text in readme
PY
    SIGNING_OUTPUT="$(env -u WINDOWS_SIGNING_CERT "${REPO_ROOT}/scripts/sign-windows.sh")"
    [[ "${SIGNING_OUTPUT}" == 'SKIP: Windows signing (no certificate configured).' ]]
    SIGNING_OUTPUT="$(WINDOWS_SIGNING_CERT=inert-fixture "${REPO_ROOT}/scripts/sign-windows.sh" "${STAGING}/windows inputs")"
    [[ "${SIGNING_OUTPUT}" == 'SKIP: Windows signing (placeholder hook; preview payload remains unsigned).' ]]
else
    printf '%s\n' 'SKIP: Windows ZIP packaging tests (the Go toolchain go.mod requires is unavailable).'
fi

# Compare all three winget files byte-for-byte, including a numeric-looking dummy hash.
WINGET_HASH=0000000000000000000000000000000000000000000000000000000000000000
"${REPO_ROOT}/scripts/render-winget.sh" v0.3.0 "${WINGET_HASH}" "${STAGING}/winget"
mkdir "${STAGING}/expected winget"
cat >"${STAGING}/expected winget/avhn.fortix.yaml" <<'EOF'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.10.0.schema.json
PackageIdentifier: avhn.fortix
PackageVersion: '0.3.0'
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.10.0
EOF
cat >"${STAGING}/expected winget/avhn.fortix.installer.yaml" <<'EOF'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.10.0.schema.json
PackageIdentifier: avhn.fortix
PackageVersion: '0.3.0'
InstallerType: zip
NestedInstallerType: portable
MinimumOSVersion: 10.0.19045.0
NestedInstallerFiles:
  - RelativeFilePath: fortix_0.3.0_windows_amd64/fortix.exe
    PortableCommandAlias: fortix
  - RelativeFilePath: fortix_0.3.0_windows_amd64/fortix-helper.exe
    PortableCommandAlias: fortix-helper
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/avhn/fortix/releases/download/v0.3.0/fortix_0.3.0_windows_amd64.zip
    InstallerSha256: '0000000000000000000000000000000000000000000000000000000000000000'
ManifestType: installer
ManifestVersion: 1.10.0
EOF
cat >"${STAGING}/expected winget/avhn.fortix.locale.en-US.yaml" <<'EOF'
# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.10.0.schema.json
PackageIdentifier: avhn.fortix
PackageVersion: '0.3.0'
PackageLocale: en-US
Publisher: avhn
PackageName: fortix
PackageUrl: https://github.com/avhn/fortix
License: GPL-3.0-or-later
LicenseUrl: https://github.com/avhn/fortix/blob/v0.3.0/LICENSE
ShortDescription: FortiGate SSL VPN client
ReleaseNotesUrl: https://github.com/avhn/fortix/releases/tag/v0.3.0
ManifestType: defaultLocale
ManifestVersion: 1.10.0
EOF
diff -ru "${STAGING}/expected winget" "${STAGING}/winget"
expect_failure 'usage:' "${REPO_ROOT}/scripts/render-winget.sh"
expect_failure 'invalid release version' "${REPO_ROOT}/scripts/render-winget.sh" '0.3.0;unsafe' "${WINGET_HASH}" "${STAGING}/unsafe winget"
expect_failure 'invalid ZIP SHA-256' "${REPO_ROOT}/scripts/render-winget.sh" 0.3.0 unsafe "${STAGING}/bad winget hash"
expect_failure 'output already exists' "${REPO_ROOT}/scripts/render-winget.sh" 0.3.0 "${WINGET_HASH}" "${STAGING}/winget"

# The site pages render for a valid fingerprint, carry it, and leave apt files alone.
expect_failure 'usage:' "${REPO_ROOT}/scripts/build-pages-index.sh"
expect_failure 'invalid signing key fingerprint' "${REPO_ROOT}/scripts/build-pages-index.sh" "${STAGING}" unsafe
mkdir -p "${STAGING}/site/apt"
printf 'retained\n' >"${STAGING}/site/apt/Release"
"${REPO_ROOT}/scripts/build-pages-index.sh" "${STAGING}/site" 7F1D1CA8B09790EAC0FA70DA1A52C72D8C1F6F06
# Match the shell variable literally in the generated installation instructions.
# shellcheck disable=SC2016
grep -Fq 'test "$FINGERPRINT" = 7F1D1CA8B09790EAC0FA70DA1A52C72D8C1F6F06' "${STAGING}/site/index.html"
grep -Fq '<code>7F1D1CA8B09790EAC0FA70DA1A52C72D8C1F6F06</code>' "${STAGING}/site/apt/index.html"
# shellcheck disable=SC2016
grep -Fq 'fortix-helper.exe install --user $env:USERNAME' "${STAGING}/site/index.html"
[[ "$(cat "${STAGING}/site/apt/Release")" == retained ]]

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
printf '%s\n' 'Packaging guards, combined checksums, Homebrew, Windows ZIP and winget renderer tests passed.'
