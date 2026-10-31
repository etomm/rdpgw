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

  # Domain join (testjoin pre-check, auto-join with backoff, manual wait)
  # is performed by rdpgw-auth before winbindd starts; see cmd/auth/join.go.
  # Determine keytab path dynamically from smb.conf (defaulting to /etc/samba/samba.keytab if unset)
  KEYTAB_PATH=$(testparm -s --parameter-name="dedicated keytab file" /etc/samba/smb.conf 2>/dev/null | tr -d '[:space:]')
  if [ -z "${KEYTAB_PATH}" ] || [ "${KEYTAB_PATH}" = "0" ]; then
    KEYTAB_PATH="/etc/samba/samba.keytab"
  fi
  echo "Using dedicated keytab path from smb.conf: ${KEYTAB_PATH}"
  mkdir -p "$(dirname "${KEYTAB_PATH}")"

  # Ensure keytab is created/refreshed initially
  net ads keytab create -P 2>/dev/null || true

  # Determine primary SPN from GatewayAddress if rdpgw.yaml is mounted/present
  ALL_SPNS=""
  RDPGW_CONF="${RDPGW_CONF:-/opt/rdpgw/rdpgw.yaml}"
  if [ -f "${RDPGW_CONF}" ]; then
    GW_RAW=$(yq eval '.Server.GatewayAddress // .server.gatewayaddress // ""' "${RDPGW_CONF}" 2>/dev/null | tr -d '\r\n')
    GW_ADDR=$(echo "${GW_RAW}" | sed -e 's|^https\?://||' -e 's|:[0-9]\+.*$||' -e 's|/.*$||')
    if [ -n "${GW_ADDR}" ] && [ "${GW_ADDR}" != "localhost" ] && [ "${GW_ADDR}" != "127.0.0.1" ]; then
      ALL_SPNS="HTTP/${GW_ADDR}"
    fi
  fi

  # Extract additional SPNs from rdpgw-auth.yaml under ntlm.winbind.spns if present
  AUTH_CONF="${RDPGW_AUTH_CONF:-/etc/rdpgw-auth.yaml}"
  if [ -f "${AUTH_CONF}" ]; then
    YAML_SPNS=$(yq eval '.ntlm.winbind.spns[]?' "${AUTH_CONF}" 2>/dev/null | tr '\n' ' ' || true)
    if [ -n "${YAML_SPNS}" ]; then
      ALL_SPNS="${ALL_SPNS} ${YAML_SPNS}"
    fi
  fi

  # Append any legacy KERBEROS_SPNS env var if set
  if [ -n "${KERBEROS_SPNS}" ]; then
    ALL_SPNS="${ALL_SPNS} ${KERBEROS_SPNS}"
  fi
  # Normalize whitespace
  ALL_SPNS=$(echo "${ALL_SPNS}" | xargs)

  # Verify and add missing SPNs
  if [ -n "${ALL_SPNS}" ]; then
    NETBIOS_NAME=$(testparm -s --parameter-name="netbios name" /etc/samba/smb.conf 2>/dev/null | tr -d '[:space:]')
    [ -z "${NETBIOS_NAME}" ] && NETBIOS_NAME="COMPUTER"
    WORKGROUP=$(testparm -s --parameter-name="workgroup" /etc/samba/smb.conf 2>/dev/null | tr -d '[:space:]')
    [ -z "${WORKGROUP}" ] && WORKGROUP="DOMAIN"
    
    for spn in ${ALL_SPNS}; do
      if ! klist -k "${KEYTAB_PATH}" 2>/dev/null | grep -q "${spn}"; then
        echo "SPN ${spn} missing from keytab."
        if [ -n "${AD_JOIN_USER}" ] && [ -n "${AD_JOIN_PASSWORD}" ]; then
          echo "Attempting automatic registration for ${spn} using provided credentials..."
          net ads setspn add "${spn}" -U "${AD_JOIN_USER}%${AD_JOIN_PASSWORD}" 2>/dev/null || true
          net ads keytab create -P 2>/dev/null || true
        fi
        
        # Loop waiting until the SPN appears in the keytab (allowing manual addition from DC/Windows or container shell)
        until klist -k "${KEYTAB_PATH}" 2>/dev/null | grep -q "${spn}"; do
          echo "--------------------------------------------------------------------------------" >&2
          echo "WARNING: Required SPN '${spn}' is missing from the keytab." >&2
          echo "Please manually register the SPN in Active Directory from a Windows DC or machine:" >&2
          echo "    setspn -A ${spn} ${WORKGROUP}\\${NETBIOS_NAME}\$" >&2
          echo "OR from a shell INSIDE this container using domain admin credentials:" >&2
          echo "    net ads setspn add ${spn} -U Administrator" >&2
          echo "" >&2
          echo "Examples to access the container:" >&2
          echo "  - Kubernetes: kubectl exec -it <pod-name> -n <namespace> -c rdpgw-auth -- sh" >&2
          echo "  - Docker:     docker exec -it <container-name> sh" >&2
          echo "--------------------------------------------------------------------------------" >&2
          echo "Waiting for SPN ${spn} to appear in keytab..." >&2
          net ads keytab create -P >/dev/null 2>&1 || true
          sleep 5
        done
        echo "SPN ${spn} successfully detected and validated in keytab!"
      else
        echo "Verified SPN present in keytab: ${spn}"
      fi
    done
  fi

  if [ -f "${KEYTAB_PATH}" ]; then
    chmod 0644 "${KEYTAB_PATH}"
    echo "Keytab successfully validated at ${KEYTAB_PATH}"
  else
    echo "WARNING: Keytab not found at ${KEYTAB_PATH}" >&2
  fi
fi

# winbindd itself is started, health-checked (wbinfo -p) and supervised by
# rdpgw-auth: it owns the child process, mirrors its output and stops it on
# SIGTERM/SIGINT. With RDPGW_AUTH_EXTERNAL_WINBIND=1 it only waits for the
# host-provided winbindd and never starts a second one.
echo "Starting rdpgw-auth"
exec /opt/rdpgw/rdpgw-auth --serve-user rdpgw "$@"
