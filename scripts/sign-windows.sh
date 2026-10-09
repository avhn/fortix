#!/usr/bin/env bash
# Reserve a signing hook for prebuilt Windows payloads without handling certificates yet.
# Usage: sign-windows.sh [PAYLOAD_DIRECTORY]
# WINDOWS_SIGNING_CERT is checked only for presence; never print or decode its value.
# This preview remains unsigned even when a certificate has been configured.
set -euo pipefail

[[ $# -le 1 ]] || {
    printf '%s\n' 'usage: sign-windows.sh [PAYLOAD_DIRECTORY]' >&2
    exit 1
}
if [[ -z "${WINDOWS_SIGNING_CERT:-}" ]]; then
    printf '%s\n' 'SKIP: Windows signing (no certificate configured).'
else
    printf '%s\n' 'SKIP: Windows signing (placeholder hook; preview payload remains unsigned).'
fi
