#!/usr/bin/env bash
# Verify bundle layout, arm64 signatures, license resources and read-only DMG contents.
# Usage: verify-macos-package.sh INPUT_APP INPUT_DMG
# The image is mounted read-only at a private temporary mountpoint and always detached.
set -euo pipefail

# die stops verification without running the app or its privileged helper.
die() {
    printf '%s\n' "$*" >&2
    exit 1
}

# verify_app checks the same executable layout used by the installer and runtime.
verify_app() {
    local app="${1}" binary release build
    codesign --verify --deep --strict "${app}"
    release="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${app}/Contents/Info.plist")"
    build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "${app}/Contents/Info.plist")"
    [[ "${release}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "${build}" == "${release}" ]] || die "bundle versions must be numeric release components"
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${app}/Contents/Info.plist")" == com.github.avhn.fortix ]] || die "unexpected bundle identifier"
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :LSUIElement' "${app}/Contents/Info.plist")" == true ]] || die "app is not a menu-bar agent"
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "${app}/Contents/Info.plist")" == 13.0 ]] || die "unexpected deployment floor"
    for binary in Contents/MacOS/Fortix Contents/Resources/libexec/fortix Contents/Resources/libexec/fortix-helper Contents/Resources/libexec/fortix-pinentry; do
        [[ -f "${app}/${binary}" && -x "${app}/${binary}" && ! -L "${app}/${binary}" ]] || die "missing executable: ${binary}"
        [[ "$(lipo -archs "${app}/${binary}")" == arm64 ]] || die "unexpected executable architecture: ${binary}"
        codesign --verify --strict "${app}/${binary}"
    done
    [[ -s "${app}/Contents/Resources/LICENSE" && -s "${app}/Contents/Resources/THIRD_PARTY_NOTICES.txt" ]] || die "license resources are missing"
    [[ ! -e "${app}/Contents/Resources/libexec/openfortivpn" ]] || die "optional backend must not be bundled"
}

[[ $# -eq 2 ]] || die "usage: verify-macos-package.sh INPUT_APP INPUT_DMG"
APP="${1}"
DMG="${2}"
verify_app "${APP}"
hdiutil verify "${DMG}"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-verify.XXXXXX")"
MOUNTED=0

# cleanup detaches before removing temporary files, leaving the mountpoint intact on failure.
cleanup() {
    if [[ "${MOUNTED}" -eq 1 ]]; then
        hdiutil detach "${STAGING}/mount" >/dev/null || return 1
    fi
    rm -rf "${STAGING}"
}
trap cleanup EXIT
hdiutil imageinfo "${DMG}" >"${STAGING}/imageinfo"
grep -q '^Format: UDZO' "${STAGING}/imageinfo" || die "disk image is not compressed read-only UDZO"
mkdir "${STAGING}/mount"
hdiutil attach -readonly -nobrowse -mountpoint "${STAGING}/mount" "${DMG}" >/dev/null
MOUNTED=1
[[ -L "${STAGING}/mount/Applications" && "$(readlink "${STAGING}/mount/Applications")" == /Applications ]] || die "Applications link is missing"
verify_app "${STAGING}/mount/Fortix.app"
diff -qr "${APP}" "${STAGING}/mount/Fortix.app"
printf '%s\n' 'Verified arm64 app and compressed read-only disk image.'
