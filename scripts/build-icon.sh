#!/usr/bin/env bash
# Regenerate the macOS app icon and README header images from assets/icon/art.py.
# Usage: build-icon.sh
# Requires macOS with Xcode 26 or later (actool compiles the layered .icon format),
# python3, rsvg-convert and ImageMagick. Outputs are committed, so release builds on
# older Xcode copy them instead of compiling: packaging/macos/Assets.car carries the
# light, dark and tinted appearances for macOS 26, packaging/macos/AppIcon.icns is
# the full-size light fallback for earlier releases.
set -euo pipefail

# die reports a missing prerequisite or failed step and stops before replacing outputs.
die() {
    printf '%s\n' "$*" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for TOOL in python3 rsvg-convert magick xcrun iconutil; do
    command -v "${TOOL}" >/dev/null || die "missing required tool: ${TOOL}"
done
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
ART=(python3 -I "${REPO_ROOT}/assets/icon/art.py")

# Vector masters: full-bleed layers for the .icon and masked icons for the fallback.
"${ART[@]}" foreground light >"${WORK}/foreground-light.svg"
"${ART[@]}" foreground dark >"${WORK}/foreground-dark.svg"
for THEME in light dark; do
    "${ART[@]}" background "${THEME}" >"${WORK}/background-${THEME}.svg"
    "${ART[@]}" icon "${THEME}" >"${WORK}/icon-${THEME}.svg"
    "${ART[@]}" icon "${THEME}" small >"${WORK}/icon-${THEME}-small.svg"
done

# Layered icon document: one foreground and one background group, each with a dark
# specialization. System glass effects are disabled so the artwork renders as drawn.
ICON="${WORK}/AppIcon.icon"
mkdir -p "${ICON}/Assets"
for LAYER in foreground-light foreground-dark background-light background-dark; do
    rsvg-convert -w 1024 -h 1024 "${WORK}/${LAYER}.svg" -o "${ICON}/Assets/${LAYER}.png"
done
cat >"${ICON}/icon.json" <<'JSON'
{
  "fill" : "none",
  "groups" : [
    {
      "layers" : [
        {
          "image-name" : "foreground-light.png",
          "image-name-specializations" : [ { "appearance" : "dark", "value" : "foreground-dark.png" } ],
          "name" : "foreground"
        }
      ],
      "shadow" : { "kind" : "none", "opacity" : 0 },
      "specular" : false,
      "translucency" : { "enabled" : false, "value" : 0 }
    },
    {
      "layers" : [
        {
          "image-name" : "background-light.png",
          "image-name-specializations" : [ { "appearance" : "dark", "value" : "background-dark.png" } ],
          "name" : "background"
        }
      ],
      "shadow" : { "kind" : "none", "opacity" : 0 },
      "specular" : false,
      "translucency" : { "enabled" : false, "value" : 0 }
    }
  ],
  "supported-platforms" : { "squares" : [ "macOS" ] }
}
JSON
mkdir -p "${WORK}/compiled"
xcrun actool "${ICON}" --compile "${WORK}/compiled" --platform macosx \
    --minimum-deployment-target 13.0 --app-icon AppIcon \
    --output-partial-info-plist "${WORK}/partial.plist" >/dev/null

# Fallback icns: masked light icon at every standard size; 32 and below use the
# simplified master so the arch stays legible.
ICONSET="${WORK}/AppIcon.iconset"
mkdir -p "${ICONSET}"
render() {  # render PIXELS NAME
    local master="${WORK}/icon-light.svg"
    [[ "$1" -gt 32 ]] || master="${WORK}/icon-light-small.svg"
    rsvg-convert -w "$1" -h "$1" "${master}" -o "${ICONSET}/$2"
}
for POINTS in 16 32 128 256 512; do
    render "${POINTS}" "icon_${POINTS}x${POINTS}.png"
    render "$((POINTS * 2))" "icon_${POINTS}x${POINTS}@2x.png"
done
iconutil -c icns "${ICONSET}" -o "${WORK}/AppIcon.icns"

# README headers: 1280x640 with the icon centred, one per color scheme.
for THEME in light dark; do
    rsvg-convert -w 320 -h 320 "${WORK}/icon-${THEME}.svg" -o "${WORK}/header-icon-${THEME}.png"
done
magick -size 1280x640 radial-gradient:'#FBFAF8'-'#E9E6E1' \
    "${WORK}/header-icon-light.png" -gravity center -composite -strip "${WORK}/readme-header.png"
magick -size 1280x640 radial-gradient:'#24262D'-'#0E0F12' \
    "${WORK}/header-icon-dark.png" -gravity center -composite -strip "${WORK}/readme-header-dark.png"

install -m 0644 "${WORK}/compiled/Assets.car" "${REPO_ROOT}/packaging/macos/Assets.car"
install -m 0644 "${WORK}/AppIcon.icns" "${REPO_ROOT}/packaging/macos/AppIcon.icns"
install -m 0644 "${WORK}/readme-header.png" "${WORK}/readme-header-dark.png" "${REPO_ROOT}/docs/assets/"
printf 'icon outputs written to packaging/macos and docs/assets\n'
