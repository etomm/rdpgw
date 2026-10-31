#!/bin/sh
# Entrypoint for Dockerfile.auth-winbind.
#
# This script prepares the container filesystem and the keytab/SPN side of
# the domain membership. Domain join, winbindd startup/health-checking and
# supervision all happen in rdpgw-auth, which therefore runs as root in this
# image (and re-executes its gRPC server as the unprivileged rdpgw user).
#
# Set RDPGW_AUTH_EXTERNAL_WINBIND=1 to skip the local winbindd and use the
# winbind of a domain-joined host instead (mount its /run/samba and
# /var/lib/samba/winbindd_privileged into the container). rdpgw-auth then
# only waits for that external winbindd.
set -e

PRIV_DIR=/var/lib/samba/winbindd_privileged

if [ "${RDPGW_AUTH_EXTERNAL_WINBIND}" != "1" ]; then
  if [ ! -f /etc/samba/smb.conf ]; then
    echo "missing /etc/samba/smb.conf; mount the domain member configuration" >&2
    exit 1
  fi
  mkdir -p /run/samba "${PRIV_DIR}" /var/lib/samba/private /var/lib/samba/lock /var/lib/samba/cores /var/cache/samba /var/log/samba
  chown root:root /var/lib/samba/private
  chmod 0700 /var/lib/samba/private
  chown root:winbindd_priv "${PRIV_DIR}"
  chmod 0750 "${PRIV_DIR}"

  # Create an empty secrets.ldb if missing to satisfy Samba LDB module checks on startup
  if [ ! -f /var/lib/samba/private/secrets.ldb ]; then
    if command -v ldbadd >/dev/null 2>&1; then
      printf "dn: @ATTRIBUTES\n\n" | ldbadd -H /var/lib/samba/private/secrets.ldb >/dev/null 2>&1 || true
    else
      touch /var/lib/samba/private/secrets.ldb 2>/dev/null || true
    fi
  fi

  # Domain join, keytab creation and SPN registration are performed by
  # rdpgw-auth before winbindd starts; see cmd/auth/join.go and
  # cmd/auth/spn.go.
fi

# winbindd itself is started, health-checked (wbinfo -p) and supervised by
# rdpgw-auth: it owns the child process, mirrors its output and stops it on
# SIGTERM/SIGINT. With RDPGW_AUTH_EXTERNAL_WINBIND=1 it only waits for the
# host-provided winbindd and never starts a second one.
echo "Starting rdpgw-auth"
exec /opt/rdpgw/rdpgw-auth --serve-user rdpgw "$@"
