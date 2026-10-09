#!/usr/bin/env bash
# Prove Unix sources and release inputs match a detached baseline checkout.
# Usage: check-unix-unchanged.sh
# FORTIX_UNIX_BASE overrides d7e3791; staged, unstaged and untracked files are checked as-is.
set -euo pipefail

# die reports an invalid baseline or a failed prerequisite without changing the worktree.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 0 ]] || die "usage: check-unix-unchanged.sh"
command -v git >/dev/null || die "git is required"
command -v go >/dev/null || die "go is required"
BASE_REF="${FORTIX_UNIX_BASE:-d7e3791}"
BASE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify "${BASE_REF}^{commit}")" || die "invalid Unix baseline: ${BASE_REF}"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-unixproof.XXXXXX")"

# cleanup removes only the temporary baseline, retaining the proof's original exit status.
cleanup() {
    local result=$?
    if [[ -d "${STAGING}/base" ]]; then
        git -C "${REPO_ROOT}" worktree remove --force "${STAGING}/base" || {
            printf '%s\n' "failed to remove temporary baseline: ${STAGING}/base" >&2
            return 1
        }
    fi
    rmdir "${STAGING}" || return 1
    return "${result}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

git -C "${REPO_ROOT}" worktree add --detach "${STAGING}/base" "${BASE_COMMIT}" >/dev/null
# The underscore directory keeps this verifier out of the application package graph.
(
    cd "${REPO_ROOT}"
    GOMAXPROCS=2 GOFLAGS=-p=2 GOWORK=off go run ./scripts/_unixproof -base "${STAGING}/base" -head "${REPO_ROOT}"
)
