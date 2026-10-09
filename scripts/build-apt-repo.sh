#!/usr/bin/env bash
# Add Debian packages to a retained pool and generate signed stable/main indexes.
# Usage: build-apt-repo.sh DEBS_DIR REPO_DIR KEY_FINGERPRINT
# DEBS_DIR contains new fortix debs; REPO_DIR retains old versions; GNUPGHOME holds the signing key.
# APT_SIGNING_PASSPHRASE is read through a private descriptor, never a command-line argument.
set -euo pipefail
set +x

# die fails closed before unsigned repository data can be published.
die() {
    printf '%s\n' "${*}" >&2
    exit 1
}

# validate_deb rejects symlinks, unsafe filenames and unsupported package metadata.
# Its sole argument is a package path; no package scripts or contained executables run.
validate_deb() {
    local file="${1}" name architecture
    [[ -f "${file}" && ! -L "${file}" && -s "${file}" ]] || die "invalid Debian package"
    name="$(basename "${file}")"
    [[ "${name}" =~ ^fortix_[0-9][A-Za-z0-9_.+~-]*_linux_(amd64|arm64)\.deb$ ]] || die "unsafe Debian package name"
    [[ "$(dpkg-deb -f "${file}" Package)" == fortix ]] || die "unexpected Debian package name"
    architecture="$(dpkg-deb -f "${file}" Architecture)"
    [[ "${architecture}" == amd64 || "${architecture}" == arm64 ]] || die "unsupported Debian architecture"
    [[ "${name}" == *_linux_"${architecture}".deb ]] || die "Debian filename architecture mismatch"
}

[[ $# -eq 3 ]] || die "usage: build-apt-repo.sh DEBS_DIR REPO_DIR KEY_FINGERPRINT"
FINGERPRINT="${3}"
[[ "${FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]] || die "invalid signing key fingerprint"
[[ -d "${1}" && ! -L "${1}" ]] || die "invalid Debian input directory"
DEBS="$(cd "${1}" && pwd)"
[[ ! -L "${2}" && (! -e "${2}" || -d "${2}") ]] || die "invalid repository directory"
[[ -n "${GNUPGHOME:-}" && -d "${GNUPGHOME}" && ! -L "${GNUPGHOME}" ]] || die "GNUPGHOME must be an isolated key directory"
for TOOL in apt-ftparchive dpkg-deb gpg gzip; do
    command -v "${TOOL}" >/dev/null || die "required tool not found: ${TOOL}"
done
ACTUAL_FINGERPRINT="$(gpg --batch --with-colons --list-secret-keys "${FINGERPRINT}" | awk -F: '$1 == "fpr" { print $10; exit }')" || die "signing key fingerprint mismatch"
[[ "${ACTUAL_FINGERPRINT}" == "${FINGERPRINT}" ]] || die "signing key fingerprint mismatch"
shopt -s nullglob dotglob
INPUTS=("${DEBS}"/*)
[[ ${#INPUTS[@]} -gt 0 ]] || die "no Debian packages supplied"
for FILE in "${INPUTS[@]}"; do
    validate_deb "${FILE}"
done
mkdir -p "${2}"
REPOSITORY="$(cd "${2}" && pwd)"
[[ -z "$(find "${REPOSITORY}" -type l -print -quit)" ]] || die "repository contains a symlink"
mkdir -p "${REPOSITORY}/pool/main"
# A rerun can reuse identical packages but must never replace an existing release's bytes.
for FILE in "${INPUTS[@]}"; do
    TARGET="${REPOSITORY}/pool/main/$(basename "${FILE}")"
    if [[ -e "${TARGET}" ]]; then
        cmp -s "${FILE}" "${TARGET}" || die "existing Debian package differs"
    fi
done
for FILE in "${INPUTS[@]}"; do
    TARGET="${REPOSITORY}/pool/main/$(basename "${FILE}")"
    [[ -e "${TARGET}" ]] || cp "${FILE}" "${TARGET}"
done
POOL=("${REPOSITORY}/pool/main"/*)
for FILE in "${POOL[@]}"; do
    validate_deb "${FILE}"
done
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/fortix-apt.XXXXXX")"
trap 'rm -rf "${STAGING}"' EXIT
for ARCH in amd64 arm64; do
    INDEX="${STAGING}/dists/stable/main/binary-${ARCH}"
    mkdir -p "${INDEX}"
    # Relative pool filenames remain valid when Pages serves the repository at /apt.
    (cd "${REPOSITORY}" && apt-ftparchive --arch "${ARCH}" packages pool/main) >"${INDEX}/Packages"
    [[ -s "${INDEX}/Packages" ]] || die "missing Debian architecture: ${ARCH}"
    gzip -n -9 -c "${INDEX}/Packages" >"${INDEX}/Packages.gz"
done
(
    cd "${STAGING}"
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=fortix \
        -o APT::FTPArchive::Release::Label=fortix \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        release dists/stable >dists/stable/Release
)
# Loopback signing works noninteractively with an encrypted key and keeps secrets off argv.
gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --local-user "${FINGERPRINT}" \
    --output "${STAGING}/dists/stable/InRelease" --clearsign "${STAGING}/dists/stable/Release" \
    3<<<"${APT_SIGNING_PASSPHRASE:-}"
gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --local-user "${FINGERPRINT}" \
    --output "${STAGING}/dists/stable/Release.gpg" --detach-sign "${STAGING}/dists/stable/Release" \
    3<<<"${APT_SIGNING_PASSPHRASE:-}"
gpg --batch --verify "${STAGING}/dists/stable/InRelease"
gpg --batch --verify "${STAGING}/dists/stable/Release.gpg" "${STAGING}/dists/stable/Release"
# Binary export is already dearmored and suitable for apt's signed-by keyring.
gpg --batch --export "${FINGERPRINT}" >"${STAGING}/fortix-archive-keyring.gpg"
gpg --batch --armor --export "${FINGERPRINT}" >"${STAGING}/fortix-archive-keyring.asc"
[[ -s "${STAGING}/fortix-archive-keyring.gpg" && -s "${STAGING}/fortix-archive-keyring.asc" ]] || die "public key export failed"
mkdir -p "${REPOSITORY}/dists"
cp -R "${STAGING}/dists/stable" "${REPOSITORY}/dists/"
cp "${STAGING}/fortix-archive-keyring.gpg" "${STAGING}/fortix-archive-keyring.asc" "${REPOSITORY}/"
printf '%s\n' 'Signed stable/main apt repository built and verified.'
