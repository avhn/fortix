#!/usr/bin/env bash
# Compare Unix release payloads and packaging inputs against a detached baseline.
# Usage: check-release-unchanged.sh
# FORTIX_UNIX_BASE overrides d7e3791; the current working tree is checked as-is.
set -euo pipefail

# die reports an invalid prerequisite before any release build is attempted.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 0 ]] || die "usage: check-release-unchanged.sh"
for TOOL in git go tar shasum cmp python3; do
    command -v "${TOOL}" >/dev/null || die "${TOOL} is required"
done
BASE_REF="${FORTIX_UNIX_BASE:-d7e3791}"
BASE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify "${BASE_REF}^{commit}")" || die "invalid Unix baseline: ${BASE_REF}"
TIMEOUT="$(command -v timeout || command -v gtimeout)" || die "timeout or gtimeout is required to bound Go builds"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-releaseproof.XXXXXX")"
FAILED=0
VERSION=0.3.0
export SOURCE_DATE_EPOCH=1767225600 GOMAXPROCS=2 GOFLAGS=-p=2 GOWORK=off
export GOCACHE="${STAGING}/cache"

# cleanup removes only this proof's temporary checkout and build products.
cleanup() {
    local result=$?
    if [[ -d "${STAGING}/base" ]]; then
        git -C "${REPO_ROOT}" worktree remove --force "${STAGING}/base" || return 1
    fi
    rm -rf "${STAGING}"
    return "${result}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# compare reports both hashes on mismatch and continues to inspect the other artifacts.
compare() {
    local name="${1}" old="${2}" new="${3}" old_hash new_hash
    if [[ ! -f "${old}" || ! -f "${new}" ]]; then
        printf 'FAIL %s: missing file\n' "${name}"
        FAILED=1
        return
    fi
    old_hash="$(shasum -a 256 "${old}" | awk '{print $1}')"
    new_hash="$(shasum -a 256 "${new}" | awk '{print $1}')"
    if [[ "${old_hash}" == "${new_hash}" ]] && cmp -s "${old}" "${new}"; then
        printf 'PASS %s %s\n' "${name}" "${new_hash}"
    else
        printf 'FAIL %s: base=%s head=%s\n' "${name}" "${old_hash}" "${new_hash}"
        FAILED=1
    fi
}

# compare_tree checks the union of tracked baseline and current files, including additions.
compare_tree() {
    local prefix="${1}" file
    {
        git -C "${STAGING}/base" ls-files -- "${prefix}"
        git -C "${REPO_ROOT}" ls-files --cached --others --exclude-standard -- "${prefix}"
    } | LC_ALL=C sort -u >"${STAGING}/files"
    while IFS= read -r file; do
        compare "${file}" "${STAGING}/base/${file}" "${REPO_ROOT}/${file}"
    done <"${STAGING}/files"
}

# build_tree uses one absolute source path because the release does not set -trimpath.
# Git metadata is excluded and -buildvcs=false normalizes commit and dirty-tree stamping.
build_tree() {
    local tree="${1}" label="${2}" os arch binary
    rm -rf "${STAGING}/source"
    mkdir -p "${STAGING}/source" "${STAGING}/${label}-bins"
    git -C "${tree}" ls-files --cached --others --exclude-standard -z >"${STAGING}/sources"
    tar -C "${tree}" --null -T "${STAGING}/sources" -cf "${STAGING}/source.tar"
    tar -C "${STAGING}/source" -xf "${STAGING}/source.tar"
    for os in darwin linux; do
        for arch in amd64 arm64; do
            for binary in fortix fortix-helper fortix-tray; do
                [[ "${os}" != darwin || "${binary}" != fortix-tray ]] || continue
                (
                    cd "${STAGING}/source"
                    GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 "${TIMEOUT}" --kill-after=10s 180s go build -buildvcs=false \
                        -ldflags "-s -w -X github.com/avhn/fortix/internal/buildinfo.Version=${VERSION}" \
                        -o "${STAGING}/${label}-bins/${binary}_${os}_${arch}" "./cmd/${binary}"
                    # Keep diagnostic symbols and omit the source-dependent Go build ID.
                    GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 "${TIMEOUT}" --kill-after=10s 180s go build -buildvcs=false \
                        -ldflags "-w -buildid= -X github.com/avhn/fortix/internal/buildinfo.Version=${VERSION}" \
                        -o "${STAGING}/${label}-bins/${binary}_${os}_${arch}.symbols" "./cmd/${binary}"
                ) || die "build failed: ${label} ${binary}/${os}/${arch}"
            done
        done
    done
}

git -C "${REPO_ROOT}" worktree add --detach "${STAGING}/base" "${BASE_COMMIT}" >/dev/null
printf 'NOTICE version=%s SOURCE_DATE_EPOCH=%s; shared toolchain: %s\n' "${VERSION}" "${SOURCE_DATE_EPOCH}" "$(go version)"
printf '%s\n' 'NOTICE GoReleaser v2.18.2 and .goreleaser.yaml do not enable -trimpath.' \
    'NOTICE Both builds use one source path and -buildvcs=false; this excludes VCS metadata, not code differences.' \
    'NOTICE Ten Go binaries feed eight Unix download assets; container/archive bytes are not rebuilt.'

for FILE in .goreleaser.yaml LICENSE THIRD_PARTY_NOTICES.txt README.md \
    packaging/fortix-helper.service packaging/postinst packaging/prerm packaging/postrm \
    scripts/build-macos-app.sh scripts/build-dmg.sh scripts/build-apt-repo.sh; do
    compare "${FILE}" "${STAGING}/base/${FILE}" "${REPO_ROOT}/${FILE}"
done
compare_tree macos/
compare_tree packaging/debian/
# Only the two predeclared icon resources may differ, and neither may disappear.
for FILE in packaging/macos/AppIcon.icns packaging/macos/Assets.car; do
    [[ -f "${STAGING}/base/${FILE}" && -f "${REPO_ROOT}/${FILE}" ]] || die "missing icon: ${FILE}"
    printf 'NOTICE intended icon exception %s base=%s head=%s\n' "${FILE}" \
        "$(shasum -a 256 "${STAGING}/base/${FILE}" | awk '{print $1}')" \
        "$(shasum -a 256 "${REPO_ROOT}/${FILE}" | awk '{print $1}')"
done
# Check every remaining macOS packaging file without widening the icon exception.
{
    git -C "${STAGING}/base" ls-files -- packaging/macos/
    git -C "${REPO_ROOT}" ls-files --cached --others --exclude-standard -- packaging/macos/
} | LC_ALL=C sort -u >"${STAGING}/files"
while IFS= read -r FILE; do
    case "${FILE}" in packaging/macos/AppIcon.icns | packaging/macos/Assets.car) continue ;; esac
    compare "${FILE}" "${STAGING}/base/${FILE}" "${REPO_ROOT}/${FILE}"
done <"${STAGING}/files"

# Fixed synthetic hashes test the Unix channel templates without downloading release assets.
HASH="$(printf 'fortix-release-proof' | shasum -a 256 | awk '{print $1}')"
for SUFFIX in darwin_amd64.tar.gz darwin_arm64.tar.gz linux_amd64.tar.gz linux_arm64.tar.gz \
    linux_amd64.deb linux_arm64.deb darwin_arm64.dmg darwin_arm64.app.zip; do
    printf '%s  fortix_%s_%s\n' "${HASH}" "${VERSION}" "${SUFFIX}"
done >"${STAGING}/checksums.txt"
for TREE in base head; do
    ROOT="${REPO_ROOT}"
    [[ "${TREE}" != base ]] || ROOT="${STAGING}/base"
    bash "${ROOT}/scripts/render-homebrew.sh" "${VERSION}" "${STAGING}/checksums.txt" "${STAGING}/${TREE}-tap"
done
for FILE in Formula/fortix.rb Casks/fortix.rb; do
    compare "Homebrew ${FILE}" "${STAGING}/base-tap/${FILE}" "${STAGING}/head-tap/${FILE}"
done
compare_tree packaging/homebrew/
printf '%s\n' 'NOTICE apt inputs: package configuration, payload sources and repository script checked above' \
    'SKIP apt Packages/signatures: needs built Debian packages, apt-ftparchive, dpkg-deb and an isolated signing key' \
    'SKIP Swift app/DMG build: source and packaging bytes checked; only AppIcon.icns/Assets.car are allowed differences'

build_tree "${STAGING}/base" base
build_tree "${REPO_ROOT}" head
for FILE in "${STAGING}/base-bins/"*; do
    NAME="${FILE##*/}"
    [[ "${NAME}" != *.symbols ]] || continue
    printf 'NOTICE raw binary SHA-256 %s base=%s head=%s (not a byte-equivalence gate)\n' "${NAME}" \
        "$(shasum -a 256 "${FILE}" | awk '{print $1}')" \
        "$(shasum -a 256 "${STAGING}/head-bins/${NAME}" | awk '{print $1}')"
    if ! python3 -I "${REPO_ROOT}/scripts/_unixproof/release_symbols.py" "${NAME}" \
        "${FILE}.symbols" "${STAGING}/head-bins/${NAME}.symbols"; then
        FAILED=1
    fi
done
if [[ "${FAILED}" != 0 ]]; then
    printf '%s\n' 'FAIL release payload equivalence'
    exit 1
fi
printf '%s\n' 'PASS release payload equivalence'
