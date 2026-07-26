#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ---------------------------------------------------------------------------
# Single implementation of "obtain the prebuilt vendor archive, and refuse it
# unless it is exactly the archive this checkout expects".
#
# This used to exist three times (ezbuild.sh, fullau.sh, and an unverified
# `tar -xJf` in three CI workflows). Three copies of a trust decision is three
# chances to weaken one of them, so they all route through here now.
#
# Two independent checks, BOTH required:
#
#   1. SHA-256 against third_party/prebuilt/yume-vendor-prebuilt.sha256.
#      Catches corruption and a swapped file on the mirror.
#   2. Detached OpenPGP signature, pinned to YUME_RELEASE_KEY_FPR below.
#      Catches an attacker who can rewrite both the archive AND the checksum
#      on the mirror, which a checksum alone cannot.
#
# Check 2 is only worth anything because of the fingerprint pin. A bare
# `gpg --verify` succeeds for a valid signature from *any* key in the caller's
# keyring, so without the pin it would accept an attacker's key just as
# happily as the release key.
#
# Usage as a library:   source scripts/vendor_prebuilt.sh
#                       yume_vendor_verify <archive>
#                       yume_vendor_obtain <archive-or-url-or-dir> <outvar>
#                       yume_vendor_directory_root <dir> <outvar>
#
# Usage as a command:   scripts/vendor_prebuilt.sh ensure [<target-key>]
#                       Downloads (if needed), verifies, and extracts into the
#                       repository root. This is the CI entry point.
# ---------------------------------------------------------------------------

# Guard only an actual repeated source in the same shell. Do not trust an
# inherited environment marker here: when this file is executed as CI's
# verifier, `YUME_VENDOR_PREBUILT_SH=1 scripts/vendor_prebuilt.sh ensure`
# must not turn verification into a successful no-op.
if [[ "${BASH_SOURCE[0]}" != "${0}" &&
      "${YUME_VENDOR_PREBUILT_SH:-0}" == "1" ]] &&
   declare -F yume_vendor_verify >/dev/null 2>&1; then
    return 0 2>/dev/null || exit 0
fi
YUME_VENDOR_PREBUILT_SH=1

YUME_VENDOR_REPO_ROOT="${YUME_VENDOR_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# The YUME release signing key. This is the primary-key fingerprint; a
# signature made by any subkey of it also verifies, so rotating to a signing
# subkey does not require touching this value.
#
# Public counterpart is committed at the path below and is also published at
# https://github.com/F1xGOD.gpg — it is a public key, nothing here is secret.
readonly YUME_RELEASE_KEY_FPR="967278FF6FA436F504CBB0058A1588B5E2598DB1"

YUME_VENDOR_PREBUILT_DIR="${YUME_VENDOR_REPO_ROOT}/third_party/prebuilt"
YUME_VENDOR_SHA256_FILE="${YUME_VENDOR_PREBUILT_DIR}/yume-vendor-prebuilt.sha256"
YUME_VENDOR_SIG_FILE="${YUME_VENDOR_PREBUILT_DIR}/yume-vendor-prebuilt.tar.xz.asc"
YUME_VENDOR_KEY_FILE="${YUME_VENDOR_PREBUILT_DIR}/yume-release-key.asc"
YUME_VENDOR_ARCHIVE_DEFAULT="${YUME_VENDOR_PREBUILT_DIR}/yume-vendor-prebuilt.tar.xz"
YUME_VENDOR_URL_DEFAULT="${YUME_VENDOR_URL:-https://deb.fixcraft.jp/yume/yume-vendor-prebuilt.tar.xz}"

_yume_vendor_err()  { printf '[vendor][error] %s\n' "$*" >&2; }
_yume_vendor_info() { printf '[vendor] %s\n' "$*" >&2; }

_yume_vendor_have() { command -v "$1" >/dev/null 2>&1; }

# Normalize an already-unpacked source to the directory that directly contains
# target keys such as linux-x86_64 and armv8. Accept either the archive root
# (<root>/vendor/<target>) or vendor/ itself (<dir>/<target>).
yume_vendor_directory_root() {
    local _yvdr_source="${1:-}"
    local _yvdr_outvar="$2"
    local _yvdr_root=""

    if [[ ! -d "${_yvdr_source}" ]]; then
        _yume_vendor_err "unpacked vendor directory not found: ${_yvdr_source}"
        return 1
    fi
    if [[ -d "${_yvdr_source}/vendor" ]]; then
        _yvdr_root="${_yvdr_source}/vendor"
    else
        _yvdr_root="${_yvdr_source}"
    fi
    printf -v "${_yvdr_outvar}" '%s' "${_yvdr_root}"
}

# Import the committed release key into an ephemeral keyring, so verification
# does not depend on what the caller happens to have imported and cannot be
# satisfied by an unrelated key that is already trusted locally.
#
# Prints the keyring directory on stdout; caller removes it.
_yume_vendor_keyring() {
    local dir
    dir="$(mktemp -d)" || return 1
    chmod 700 "${dir}"
    if [[ ! -f "${YUME_VENDOR_KEY_FILE}" ]]; then
        _yume_vendor_err "release key missing at ${YUME_VENDOR_KEY_FILE}."
        rm -rf "${dir}"
        return 1
    fi
    if ! gpg --homedir "${dir}" --batch --quiet \
            --import "${YUME_VENDOR_KEY_FILE}" 2>/dev/null; then
        rm -rf "${dir}"
        return 1
    fi
    printf '%s' "${dir}"
}

# Verify <archive> against the pinned checksum and the pinned signing key.
# Returns 0 only if BOTH pass. Never prints the archive contents.
yume_vendor_verify() {
    local archive="$1"

    if [[ ! -f "${archive}" ]]; then
        _yume_vendor_err "archive not found: ${archive}"
        return 1
    fi

    # --- 1. pinned SHA-256 -------------------------------------------------
    if [[ ! -f "${YUME_VENDOR_SHA256_FILE}" ]]; then
        _yume_vendor_err "no pinned checksum at ${YUME_VENDOR_SHA256_FILE}; refusing ${archive}"
        return 1
    fi
    if ! _yume_vendor_have sha256sum; then
        _yume_vendor_err "sha256sum unavailable; refusing to use ${archive} unverified"
        return 1
    fi
    local want got
    want="$(awk '{print $1; exit}' "${YUME_VENDOR_SHA256_FILE}")"
    got="$(sha256sum "${archive}" | awk '{print $1}')"
    if [[ -z "${want}" || "${want}" != "${got}" ]]; then
        _yume_vendor_err "checksum mismatch - refusing to use this archive."
        _yume_vendor_err "  expected ${want:-<empty>}"
        _yume_vendor_err "  actual   ${got}"
        return 1
    fi
    _yume_vendor_info "SHA-256 matches the pinned checksum."

    # --- 2. pinned signature ----------------------------------------------
    # Absence of the signature is treated as tampering, not as "skip". The
    # .asc is committed, so a checkout without it is not a checkout we trust.
    if [[ ! -f "${YUME_VENDOR_SIG_FILE}" ]]; then
        _yume_vendor_err "detached signature missing at ${YUME_VENDOR_SIG_FILE}."
        _yume_vendor_err "  It is committed to this repository; its absence means a damaged"
        _yume_vendor_err "  or tampered checkout. Refusing."
        return 1
    fi
    if ! _yume_vendor_have gpg; then
        _yume_vendor_err "gpg unavailable; cannot verify the release signature. Refusing."
        _yume_vendor_err "  Install gnupg, or build from source without --use-vendor."
        return 1
    fi

    local keyring status validsig primary
    keyring="$(_yume_vendor_keyring)" || {
        _yume_vendor_err "could not import ${YUME_VENDOR_KEY_FILE}"
        return 1
    }
    status="$(gpg --homedir "${keyring}" --batch --status-fd 1 \
                  --verify "${YUME_VENDOR_SIG_FILE}" "${archive}" 2>/dev/null || true)"
    rm -rf "${keyring}"

    # VALIDSIG field 3 is the fingerprint of the key that actually signed;
    # the final field is its primary key. Accept either matching the pin, so
    # a signature from a subkey of the pinned primary still verifies.
    validsig="$(printf '%s\n' "${status}" | awk '$2=="VALIDSIG"{print $3; exit}')"
    primary="$(printf '%s\n' "${status}" | awk '$2=="VALIDSIG"{print $NF; exit}')"

    if [[ -z "${validsig}" ]]; then
        _yume_vendor_err "signature did NOT verify - refusing to use this archive."
        _yume_vendor_err "  Expected a signature from ${YUME_RELEASE_KEY_FPR}."
        return 1
    fi
    if [[ "${validsig}" != "${YUME_RELEASE_KEY_FPR}" && "${primary}" != "${YUME_RELEASE_KEY_FPR}" ]]; then
        _yume_vendor_err "signature is valid but was made by an UNPINNED key - refusing."
        _yume_vendor_err "  signer   ${validsig} (primary ${primary:-unknown})"
        _yume_vendor_err "  expected ${YUME_RELEASE_KEY_FPR}"
        return 1
    fi
    _yume_vendor_info "signature verified against the pinned release key."
    return 0
}

# Resolve <source> to a verified local archive path, downloading if needed.
# Writes the resulting path into the variable named by <outvar>.
#
# <source> may be empty (use the committed path, else the published URL), a
# .tar.xz path, or an https URL. A directory is rejected here; callers that
# accept an already-unpacked tree handle that before calling.
yume_vendor_obtain() {
    # Locals are _yvo_-prefixed on purpose. `printf -v "${outvar}"` assigns by
    # name, so a local sharing the caller's chosen output name would shadow it
    # and the caller would silently receive nothing. Callers naturally pick
    # `archive`, which is exactly the name this function wants for itself.
    local _yvo_source="${1:-}"
    local _yvo_outvar="$2"
    local _yvo_archive="${_yvo_source}"
    local _yvo_download=""

    if [[ -z "${_yvo_archive}" ]]; then
        if [[ -f "${YUME_VENDOR_ARCHIVE_DEFAULT}" ]]; then
            _yvo_archive="${YUME_VENDOR_ARCHIVE_DEFAULT}"
        else
            _yvo_archive="${YUME_VENDOR_URL_DEFAULT}"
        fi
    fi

    if [[ "${_yvo_archive}" == http://* || "${_yvo_archive}" == https://* ]]; then
        if [[ "${_yvo_archive}" == http://* ]]; then
            _yume_vendor_err "refusing a plaintext http:// source: ${_yvo_archive}"
            return 1
        fi
        if ! _yume_vendor_have curl; then
            _yume_vendor_err "curl is required to fetch ${_yvo_archive}"
            return 1
        fi
        mkdir -p "${YUME_VENDOR_PREBUILT_DIR}"
        _yvo_download="$(
            mktemp "${YUME_VENDOR_PREBUILT_DIR}/.vendor-download.tar.xz.XXXXXX"
        )" || {
            _yume_vendor_err "could not create a private download file."
            return 1
        }
        _yume_vendor_info "downloading ${_yvo_archive}"
        if ! curl -fsSL --proto '=https' --tlsv1.2 \
                -o "${_yvo_download}" "${_yvo_archive}"; then
            _yume_vendor_err "download failed."
            yume_vendor_cleanup "${_yvo_download}"
            return 1
        fi
        if ! yume_vendor_verify "${_yvo_download}"; then
            yume_vendor_cleanup "${_yvo_download}"
            return 1
        fi
        printf -v "${_yvo_outvar}" '%s' "${_yvo_download}"
        return 0
    fi

    if ! yume_vendor_verify "${_yvo_archive}"; then
        return 1
    fi
    printf -v "${_yvo_outvar}" '%s' "${_yvo_archive}"
    return 0
}

# Remove a temporary download, if that is what the given path is. Safe to call
# with any path; it only ever deletes our own temp file.
yume_vendor_cleanup() {
    local archive="${1:-}"
    local archive_dir=""
    local archive_name=""
    archive_dir="$(dirname -- "${archive}")"
    archive_name="$(basename -- "${archive}")"
    if [[ "${archive_dir}" == "${YUME_VENDOR_PREBUILT_DIR}" &&
          "${archive_name}" == .vendor-download.tar.xz.* ]]; then
        rm -f -- "${archive}"
    fi
}

# Reject a validly signed but incorrectly packaged archive before extraction.
# Consumers require a single top-level vendor/ tree; accepting other members
# would let a producer mistake overwrite unrelated checkout files in CI.
yume_vendor_validate_archive_layout() {
    local archive="$1"
    if ! _yume_vendor_have tar; then
        _yume_vendor_err "tar unavailable; cannot inspect ${archive}"
        return 1
    fi

    local listing=""
    if ! listing="$(tar -tJf "${archive}")"; then
        _yume_vendor_err "could not list vendor archive."
        return 1
    fi

    local member=""
    local saw_content=0
    while IFS= read -r member; do
        member="${member#./}"
        if [[ -z "${member}" ]]; then
            continue
        fi
        if [[ "${member}" == /* ||
              "${member}" == *\\* ||
              "${member}" == *"//"* ||
              "/${member}/" == *"/../"* ||
              "/${member}/" == *"/./"* ]]; then
            _yume_vendor_err "unsafe archive member: ${member}"
            return 1
        fi
        case "${member}" in
            vendor|vendor/)
                ;;
            vendor/*)
                saw_content=1
                ;;
            *)
                _yume_vendor_err \
                    "archive member is outside the required vendor/ root: ${member}"
                return 1
                ;;
        esac
    done <<< "${listing}"

    if [[ "${saw_content}" != "1" ]]; then
        _yume_vendor_err "archive contains no vendor target content."
        return 1
    fi
    return 0
}

# Obtain + verify + extract into <dest-root> (default: repository root).
# The archive contains vendor/<target>/... so extraction is relative to root.
yume_vendor_ensure_extracted() {
    local _yve_dest_root="${1:-${YUME_VENDOR_REPO_ROOT}}"
    local _yve_source="${2:-${YUME_VENDOR_SOURCE:-}}"
    local _yve_archive=""

    if ! yume_vendor_obtain "${_yve_source}" _yve_archive; then
        return 1
    fi
    if [[ -z "${_yve_archive}" || ! -f "${_yve_archive}" ]]; then
        _yume_vendor_err "internal: no archive resolved."
        return 1
    fi
    if ! yume_vendor_validate_archive_layout "${_yve_archive}"; then
        yume_vendor_cleanup "${_yve_archive}"
        return 1
    fi
    if ! mkdir -p "${_yve_dest_root}"; then
        _yume_vendor_err "could not create extraction root: ${_yve_dest_root}"
        yume_vendor_cleanup "${_yve_archive}"
        return 1
    fi
    if [[ -e "${_yve_dest_root}/vendor" ||
          -L "${_yve_dest_root}/vendor" ]]; then
        _yume_vendor_err \
            "refusing to overwrite existing vendor path: ${_yve_dest_root}/vendor"
        yume_vendor_cleanup "${_yve_archive}"
        return 1
    fi
    if ! tar -xJf "${_yve_archive}" -C "${_yve_dest_root}"; then
        _yume_vendor_err "extraction failed."
        rm -rf -- "${_yve_dest_root}/vendor"
        yume_vendor_cleanup "${_yve_archive}"
        return 1
    fi
    yume_vendor_cleanup "${_yve_archive}"
    _yume_vendor_info "extracted verified vendor libraries into ${_yve_dest_root}/vendor"
    return 0
}

# ---------------------------------------------------------------------------
# Command-line entry point (CI). Not reached when sourced.
# ---------------------------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -euo pipefail
    case "${1:-}" in
        ensure)
            shift
            yume_vendor_ensure_extracted "${YUME_VENDOR_REPO_ROOT}" "${YUME_VENDOR_SOURCE:-}"
            # A caller may name the target directory it actually needs, so a
            # partial or wrong-arch archive fails here rather than at configure
            # time with a confusing BaseFWX error.
            for key in "$@"; do
                if [[ ! -d "${YUME_VENDOR_REPO_ROOT}/vendor/${key}" ]]; then
                    _yume_vendor_err "vendor/${key} missing after extraction."
                    exit 1
                fi
                _yume_vendor_info "vendor/${key} present."
            done
            ;;
        verify)
            shift
            yume_vendor_verify "${1:?usage: vendor_prebuilt.sh verify <archive>}"
            ;;
        *)
            cat >&2 <<'USAGE'
Usage: scripts/vendor_prebuilt.sh ensure [<target-key>...]
       scripts/vendor_prebuilt.sh verify <archive>

  ensure   Download (if needed), verify against the pinned SHA-256 and the
           pinned release key, and extract into the repository root. Any
           <target-key> given must exist as vendor/<target-key> afterwards.
  verify   Verify an existing archive without extracting it.

Environment:
  YUME_VENDOR_SOURCE   .tar.xz path or https URL to use instead of the default
  YUME_VENDOR_URL      override the published archive URL
USAGE
            exit 2
            ;;
    esac
fi
