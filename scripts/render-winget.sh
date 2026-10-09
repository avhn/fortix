#!/usr/bin/env bash
# Render winget's multi-file manifests for the Windows preview archive.
# Usage: render-winget.sh VERSION ZIP_SHA256 OUTDIR
# VERSION may start with v; only validated version/hash characters reach YAML.
# OUTDIR must not exist. Rendering does not submit manifests or install the service.
set -euo pipefail

# die leaves invalid or existing output directories untouched.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

[[ $# -eq 3 ]] || die "usage: render-winget.sh VERSION ZIP_SHA256 OUTDIR"
VERSION="${1#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "invalid release version"
HASH="${2}"
[[ "${HASH}" =~ ^[a-fA-F0-9]{64}$ ]] || die "invalid ZIP SHA-256"
OUTPUT="${3}"
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || die "output already exists"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-winget.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
cat >"${STAGING}/avhn.fortix.yaml" <<EOF
PackageIdentifier: avhn.fortix
PackageVersion: '${VERSION}'
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.10.0
EOF
cat >"${STAGING}/avhn.fortix.installer.yaml" <<EOF
PackageIdentifier: avhn.fortix
PackageVersion: '${VERSION}'
InstallerType: zip
NestedInstallerType: portable
MinimumOSVersion: 10.0.19045.0
NestedInstallerFiles:
  - RelativeFilePath: fortix_${VERSION}_windows_amd64/fortix.exe
    PortableCommandAlias: fortix
  - RelativeFilePath: fortix_${VERSION}_windows_amd64/fortix-helper.exe
    PortableCommandAlias: fortix-helper
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/avhn/fortix/releases/download/v${VERSION}/fortix_${VERSION}_windows_amd64.zip
    InstallerSha256: '${HASH}'
ManifestType: installer
ManifestVersion: 1.10.0
EOF
cat >"${STAGING}/avhn.fortix.locale.en-US.yaml" <<EOF
PackageIdentifier: avhn.fortix
PackageVersion: '${VERSION}'
PackageLocale: en-US
Publisher: avhn
PackageName: fortix
PackageUrl: https://github.com/avhn/fortix
License: GPL-3.0-or-later
LicenseUrl: https://github.com/avhn/fortix/blob/v${VERSION}/LICENSE
ShortDescription: FortiGate SSL VPN client
ReleaseNotesUrl: https://github.com/avhn/fortix/releases/tag/v${VERSION}
ManifestType: defaultLocale
ManifestVersion: 1.10.0
EOF
mkdir -p "$(dirname "${OUTPUT}")"
mv "${STAGING}" "${OUTPUT}"
