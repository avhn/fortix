#!/usr/bin/env bash
# Package prebuilt Windows binaries without downloading or executing the payload.
# Usage: package-windows.sh VERSION OUTDIR [FORTIX_EXE HELPER_EXE APP_EXE WINTUN_DLL]
# With two arguments, use FORTIX_WINDOWS_CLI, FORTIX_WINDOWS_HELPER,
# FORTIX_WINDOWS_APP and WINTUN_DLL. OUTDIR may exist; the ZIP must not exist.
# FORTIX_PACKAGING_TEST=1 alone enables FORTIX_TEST_WINTUN_SHA256 for inert fixtures.
# Python zipfile writes sorted files, fixed UTC mtimes and no extra fields or directory
# entries (the equivalent of zip -X -D). SOURCE_DATE_EPOCH defaults to the commit time.
set -euo pipefail

# die rejects untrusted or incomplete inputs before creating a release archive.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 2 || $# -eq 6 ]] || die "usage: package-windows.sh VERSION OUTDIR [FORTIX_EXE HELPER_EXE APP_EXE WINTUN_DLL]"
VERSION="${1#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "invalid release version"
OUTPUT="${2}"
BASENAME="fortix_${VERSION}_windows_amd64"
[[ ! -e "${OUTPUT}/${BASENAME}.zip" && ! -L "${OUTPUT}/${BASENAME}.zip" ]] || die "output already exists"
CLI="${3:-${FORTIX_WINDOWS_CLI:-}}"
HELPER="${4:-${FORTIX_WINDOWS_HELPER:-}}"
APP="${5:-${FORTIX_WINDOWS_APP:-}}"
DLL="${6:-${WINTUN_DLL:-}}"
for INPUT in "${CLI}" "${HELPER}" "${APP}" "${DLL}"; do
    [[ -f "${INPUT}" && ! -L "${INPUT}" && -s "${INPUT}" ]] || die "invalid Windows payload: ${INPUT}"
done
# Windows may expose Python as python or a python3 alias that cannot execute.
PYTHON=""
for CANDIDATE in python3 python; do
    if command -v "${CANDIDATE}" >/dev/null && "${CANDIDATE}" -I -c 'import sys, zipfile; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
        PYTHON="${CANDIDATE}"
        break
    fi
done
[[ -n "${PYTHON}" ]] || die "Python 3.8 or newer is required"
EXPECTED="$(sed -n 's/^[[:space:]]*wintunAMD64SHA256[[:space:]]*=[[:space:]]*"\([a-f0-9]*\)"$/\1/p' "${REPO_ROOT}/internal/tun/wintun_windows.go")"
if [[ "${FORTIX_PACKAGING_TEST:-}" == 1 && -n "${FORTIX_TEST_WINTUN_SHA256:-}" ]]; then
    EXPECTED="${FORTIX_TEST_WINTUN_SHA256}"
fi
[[ "${EXPECTED}" =~ ^[a-f0-9]{64}$ ]] || die "missing or invalid pinned Wintun DLL hash"
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${REPO_ROOT}" log -1 --format=%ct)}"
[[ "${EPOCH}" =~ ^[0-9]+$ ]] || die "invalid SOURCE_DATE_EPOCH"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-windows-package.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT

# Copy first, then hash the exact bytes that will be archived, not a mutable input.
cp "${CLI}" "${STAGING}/fortix.exe"
cp "${HELPER}" "${STAGING}/fortix-helper.exe"
cp "${APP}" "${STAGING}/FortixApp.exe"
cp "${DLL}" "${STAGING}/wintun.dll"
ACTUAL="$(
    "${PYTHON}" -I - "${STAGING}/wintun.dll" <<'PY'
import hashlib
import pathlib
import sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
[[ "${ACTUAL}" == "${EXPECTED}" ]] || die "Wintun DLL SHA-256 mismatch"
cp "${REPO_ROOT}/LICENSE" "${STAGING}/LICENSE"
# Reuse the Unix notice verbatim, then append linked Windows modules it does not cover.
(
    export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
    bash "${REPO_ROOT}/scripts/generate-notices.sh" --check
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go -C "${REPO_ROOT}" list -deps \
        -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' ./cmd/fortix ./cmd/fortix-helper |
        LC_ALL=C sort -u | sed '/^$/d' >"${STAGING}/windows-modules"
    cat "${REPO_ROOT}/THIRD_PARTY_NOTICES.txt"
    while IFS= read -r MODULE; do
        if grep -Fq "===== ${MODULE} " "${REPO_ROOT}/THIRD_PARTY_NOTICES.txt"; then
            continue
        fi
        MODULE_VERSION="$(go -C "${REPO_ROOT}" list -m -f '{{.Version}}' "${MODULE}")"
        MODULE_DIR="$(go -C "${REPO_ROOT}" list -m -f '{{.Dir}}' "${MODULE}")"
        [[ -n "${MODULE_VERSION}" && -f "${MODULE_DIR}/LICENSE" ]] || die "missing version or license for ${MODULE}"
        printf '===== %s %s =====\n\n' "${MODULE}" "${MODULE_VERSION}"
        cat "${MODULE_DIR}/LICENSE"
        printf '\n'
        for NOTICE in NOTICE PATENTS; do
            if [[ -f "${MODULE_DIR}/${NOTICE}" ]]; then
                cat "${MODULE_DIR}/${NOTICE}"
                printf '\n'
            fi
        done
    done <"${STAGING}/windows-modules"
    printf '\n===== Wintun 0.14.1 prebuilt binaries =====\nSource: https://www.wintun.net/builds/wintun-0.14.1.zip (wintun/LICENSE.txt)\n\n'
    cat "${REPO_ROOT}/packaging/windows/WINTUN-LICENSE.txt"
    printf '\n===== .NET runtime (MIT) =====\nSource: https://github.com/dotnet/runtime/blob/main/LICENSE.TXT\n\n'
    cat "${REPO_ROOT}/packaging/windows/DOTNET-LICENSE.txt"
) >"${STAGING}/NOTICES.txt"
rm "${STAGING}/windows-modules"
cat >"${STAGING}/README.txt" <<'EOF'
Fortix for Windows (x64) - preview
Windows 10 22H2 or Windows 11. This preview is unsigned; SmartScreen may warn.
Only run files obtained from the official release and verify checksums first.

Extract the entire folder. In an administrator terminal, from this folder:
  fortix-helper.exe install --user <name>
Use your Windows account name. Then launch FortixApp.exe as that user.

Uninstall in this order: disconnect all tunnels, quit FortixApp.exe, then run
  fortix-helper.exe uninstall
from this extracted folder in an administrator terminal. Add --purge only to
remove retained machine state and the helper group. Finally delete this folder.

Instructions: https://github.com/avhn/fortix/blob/main/docs/windows.md
EOF

# Explicit ZIP metadata makes output independent of host timezone, permissions and mtimes.
"${PYTHON}" -I - "${STAGING}" "${BASENAME}" "${EPOCH}" <<'PY'
import datetime
import pathlib
import stat
import sys
import zipfile
stage, basename, epoch = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
if not 1980 <= date.year <= 2107:
    sys.exit('SOURCE_DATE_EPOCH is outside the ZIP timestamp range')
with zipfile.ZipFile(stage / 'payload.zip', 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for file in sorted(stage.iterdir()):
        if file.name == 'payload.zip':
            continue
        info = zipfile.ZipInfo(basename + '/' + file.name, date.timetuple()[:6])
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
PY
mkdir -p "${OUTPUT}"
mv "${STAGING}/payload.zip" "${OUTPUT}/${BASENAME}.zip"
