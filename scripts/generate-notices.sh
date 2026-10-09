#!/usr/bin/env bash
# Emit exact dependency license texts for the Linux tray and Linux/macOS CLI releases.
# Usage: generate-notices.sh [--check]
# With --check, compare generated output with the checked-in notice without modifying it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 0 || ($# -eq 1 && "${1}" == --check) ]] || {
    printf '%s\n' 'usage: generate-notices.sh [--check]' >&2
    exit 1
}
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-notices.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
export GOMAXPROCS=2 GOFLAGS=-p=2

# Discover linked modules only; test tools and Windows-only dependencies are not shipped.
for PLATFORM in linux darwin; do
    PACKAGES=(./cmd/fortix ./cmd/fortix-helper)
    [[ "${PLATFORM}" != linux ]] || PACKAGES+=(./cmd/fortix-tray)
    GOOS="${PLATFORM}" GOARCH=arm64 CGO_ENABLED=0 go -C "${REPO_ROOT}" list -deps \
        -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' "${PACKAGES[@]}"
done | LC_ALL=C sort -u | sed '/^$/d' >"${STAGING}/modules"

{
    printf '%s\n\n' 'Third-party notices for Fortix' \
        'License texts below are copied from the exact linked module versions.' \
        'openfortivpn and ppp are optional external programs, not bundled in the app.'
    # The runtime and standard library are linked into every Go executable.
    printf '%s\n\n' '===== Go runtime and standard library (BSD-3-Clause) ====='
    GOROOT="$(go env GOROOT)"
    RUNTIME_LICENSE="${GOROOT}/LICENSE"
    # Some toolchain distributions place the license beside the runtime directory.
    [[ -f "${RUNTIME_LICENSE}" ]] || RUNTIME_LICENSE="${GOROOT}/../LICENSE"
    cat "${RUNTIME_LICENSE}"
    printf '\n'
    if [[ -f "${GOROOT}/PATENTS" ]]; then
        cat "${GOROOT}/PATENTS"
        printf '\n'
    fi
    while IFS= read -r MODULE; do
        VERSION="$(go -C "${REPO_ROOT}" list -m -f '{{.Version}}' "${MODULE}")"
        MODULE_DIR="$(go -C "${REPO_ROOT}" list -m -f '{{.Dir}}' "${MODULE}")"
        [[ -n "${VERSION}" && -f "${MODULE_DIR}/LICENSE" ]] || {
            printf 'missing version or license for %s\n' "${MODULE}" >&2
            exit 1
        }
        printf '===== %s %s =====\n\n' "${MODULE}" "${VERSION}"
        cat "${MODULE_DIR}/LICENSE"
        printf '\n'
        for NOTICE in NOTICE PATENTS; do
            if [[ -f "${MODULE_DIR}/${NOTICE}" ]]; then
                cat "${MODULE_DIR}/${NOTICE}"
                printf '\n'
            fi
        done
    done <"${STAGING}/modules"
} >"${STAGING}/THIRD_PARTY_NOTICES.txt"
if [[ "${1:-}" == --check ]]; then
    diff -u "${REPO_ROOT}/THIRD_PARTY_NOTICES.txt" "${STAGING}/THIRD_PARTY_NOTICES.txt"
else
    cat "${STAGING}/THIRD_PARTY_NOTICES.txt"
fi
