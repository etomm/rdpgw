#!/bin/sh
# Entrypoint for Dockerfile.auth-winbind.
#
# By default winbindd is started inside the container. This requires
# /etc/samba/smb.conf and the domain join state (/var/lib/samba) to be
# provided, e.g. as volumes from a previous "net ads join".
#
# Set RDPGW_AUTH_EXTERNAL_WINBIND=1 to skip starting winbindd and use the
# winbind of a domain-joined host instead (mount its /run/samba and
# /var/lib/samba/winbindd_privileged into the container).
set -e

PRIV_DIR=/var/lib/samba/winbindd_privileged

if [ "${RDPGW_AUTH_EXTERNAL_WINBIND}" != "1" ]; then
  if [ ! -f /etc/samba/smb.conf ]; then
    echo "missing /etc/samba/smb.conf; mount the domain member configuration" >&2
    exit 1
  fi
  echo "Starting winbindd"
  mkdir -p /run/samba "${PRIV_DIR}"
  winbindd -D
fi

# Wait until winbindd answers before accepting authentication requests.
i=0
until wbinfo -p >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "${i}" -ge 30 ]; then
    echo "winbindd is not responding (wbinfo -p failed)" >&2
    exit 1
  fi
  sleep 1
done

# ntlm_auth needs access to winbind's privileged pipe. Samba requires the
# directory to be owned by root with mode 0750; hand the group to
# winbindd_priv so the rdpgw user can reach it.
if [ -d "${PRIV_DIR}" ] && [ "${RDPGW_AUTH_EXTERNAL_WINBIND}" != "1" ]; then
  chgrp winbindd_priv "${PRIV_DIR}"
  chmod 0750 "${PRIV_DIR}"
fi

echo "Starting rdpgw-auth"
exec su-exec rdpgw /opt/rdpgw/rdpgw-auth "$@"
