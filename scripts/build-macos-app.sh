#!/usr/bin/env bash
# Build an arm64 menu-bar app with three bundled Go executables and ad-hoc signatures.
# Usage: build-macos-app.sh VERSION [OUTPUT_APP]
# VERSION is a semantic release version, optionally prefixed by v. OUTPUT_APP must not exist.
set -euo pipefail

# die reports a packaging failure without continuing to publish a partial bundle.
die() {
    printf '%s\n' "$*" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -ge 1 && $# -le 2 ]] || die "usage: build-macos-app.sh VERSION [OUTPUT_APP]"
VERSION="${1#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "invalid release version"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die "building the app requires an arm64 macOS host"
OUTPUT="${2:-${REPO_ROOT}/dist/Fortix.app}"
[[ "${OUTPUT}" == *.app ]] || die "output must have an .app suffix"
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || die "output already exists: ${OUTPUT}"
mkdir -p "$(dirname "${OUTPUT}")"
OUTPUT="$(cd "$(dirname "${OUTPUT}")" && pwd)/$(basename "${OUTPUT}")"
STAGING="$(mktemp -d "$(dirname "${OUTPUT}")/.fortix-app.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
APP="${STAGING}/Fortix.app"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources/libexec"
export GOMAXPROCS=2 GOFLAGS=-p=2

# Swift's executable is built against the supported deployment floor, not the host OS.
swift build --package-path "${REPO_ROOT}/macos" -c release --jobs 2 --triple arm64-apple-macosx13.0
SWIFT_BIN="$(swift build --package-path "${REPO_ROOT}/macos" -c release --jobs 2 --triple arm64-apple-macosx13.0 --show-bin-path)"
install -m 0755 "${SWIFT_BIN}/FortixApp" "${APP}/Contents/MacOS/Fortix"
for BINARY in fortix fortix-helper fortix-pinentry; do
    COMMAND="${BINARY}"
    # Pinentry is the helper dispatcher under its dedicated executable basename.
    [[ "${BINARY}" != fortix-pinentry ]] || COMMAND=fortix-helper
    GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go -C "${REPO_ROOT}" build -trimpath \
        -ldflags "-s -w -X github.com/avhn/fortix/internal/buildinfo.Version=${VERSION}" \
        -o "${APP}/Contents/Resources/libexec/${BINARY}" "./cmd/${COMMAND}"
done
cp "${REPO_ROOT}/packaging/macos/Info.plist" "${APP}/Contents/Info.plist"
# Bundle version fields require numeric components; CLI metadata retains prerelease labels.
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${VERSION%%[-+]*}" "${APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${VERSION%%[-+]*}" "${APP}/Contents/Info.plist"
cp "${REPO_ROOT}/LICENSE" "${REPO_ROOT}/THIRD_PARTY_NOTICES.txt" "${APP}/Contents/Resources/"
plutil -lint "${APP}/Contents/Info.plist"

# Sign nested executables before sealing the outer bundle; never rely on --deep signing.
for BINARY in fortix fortix-helper fortix-pinentry; do
    codesign --force --sign - --timestamp=none "${APP}/Contents/Resources/libexec/${BINARY}"
    codesign --verify --strict "${APP}/Contents/Resources/libexec/${BINARY}"
done
codesign --force --sign - --timestamp=none "${APP}/Contents/MacOS/Fortix"
codesign --force --sign - --timestamp=none "${APP}"
codesign --verify --deep --strict "${APP}"
mv "${APP}" "${OUTPUT}"
printf '%s\n' "${OUTPUT}"
