#!/bin/sh
# Tracks which authentication block succeeded so the PAM account phase can
# run the account module of exactly that block (stateful branching).
#
# The key is RDPGW_SESSION_ID, which rdpgw-auth injects into the PAM
# environment for every authentication attempt: a fresh GUID, so concurrent
# logins for the same user cannot overwrite each other's state. There is no
# username fallback: a missing id is a hard failure and the PAM stack fails
# closed.
#
# Called from the generated /etc/pam.d/rdpgw stack:
#   pam_exec.so ... create <backend>   after a successful auth module
#   pam_exec.so ... check  <backend>   in the account phase
#   pam_exec.so ... cleanup            once the account phase matched
set -u

BASE_DIR="${RDPGW_PAM_SESSION_DIR:-/tmp/pam/sessions}"
umask 077

SESSION_ID="${RDPGW_SESSION_ID:-}"
# Never let the id escape the directory.
SAFE_SESSION=$(printf '%s' "${SESSION_ID}" | tr -c 'A-Za-z0-9._-' '_')
TARGET_FILE="${BASE_DIR}/${SAFE_SESSION}"

case "${1:-}" in
create)
    [ -n "${SAFE_SESSION}" ] || exit 1
    [ -n "${2:-}" ] || exit 1
    mkdir -p "${BASE_DIR}" || exit 1
    chmod 0700 "${BASE_DIR}" 2>/dev/null || true
    # A GUID is never reused: drop state whose cleanup never ran (for example
    # when the account phase failed) instead of accumulating files.
    find "${BASE_DIR}" -type f -mmin +60 -delete 2>/dev/null || true
    printf '%s\n' "$2" >"${TARGET_FILE}"
    ;;
check)
    [ -n "${SAFE_SESSION}" ] || exit 1
    [ -f "${TARGET_FILE}" ] || exit 1
    [ "$(cat "${TARGET_FILE}" 2>/dev/null)" = "${2:-}" ]
    ;;
cleanup)
    [ -n "${SAFE_SESSION}" ] || exit 1
    rm -f "${TARGET_FILE}"
    ;;
*)
    exit 1
    ;;
esac
