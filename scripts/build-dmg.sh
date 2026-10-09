#!/usr/bin/env bash
# Package a verified app in a compressed read-only disk image with an Applications link.
# Usage: build-dmg.sh INPUT_APP OUTPUT_DMG
# INPUT_APP must be a signed bundle; OUTPUT_DMG must not already exist.
set -euo pipefail

# die reports invalid packaging input before creating or publishing an image.
die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "usage: build-dmg.sh INPUT_APP OUTPUT_DMG"
[[ "$(uname -s)" == Darwin ]] || die "building a disk image requires macOS"
APP="${1}"
OUTPUT="${2}"
[[ -d "${APP}" && ! -L "${APP}" && "${APP}" == *.app ]] || die "input must be an app directory, not a symlink"
[[ "${OUTPUT}" == *.dmg ]] || die "output must have a .dmg suffix"
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || die "output already exists: ${OUTPUT}"
codesign --verify --deep --strict "${APP}"
mkdir -p "$(dirname "${OUTPUT}")"
OUTPUT="$(cd "$(dirname "${OUTPUT}")" && pwd)/$(basename "${OUTPUT}")"
STAGING="$(mktemp -d "$(dirname "${OUTPUT}")/.fortix-dmg.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
mkdir "${STAGING}/volume"
ditto "${APP}" "${STAGING}/volume/Fortix.app"
ln -s /Applications "${STAGING}/volume/Applications"
# UDZO is a zlib-compressed, read-only image; HFS+ supports the deployment floor.
hdiutil create -volname Fortix -srcfolder "${STAGING}/volume" -format UDZO -fs HFS+ \
    -imagekey zlib-level=9 "${STAGING}/Fortix.dmg"
hdiutil verify "${STAGING}/Fortix.dmg"
mv "${STAGING}/Fortix.dmg" "${OUTPUT}"
printf '%s\n' "${OUTPUT}"
