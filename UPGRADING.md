# Upgrading

## Unreleased

### The auth container entrypoint is `rdpgw-auth` itself (no shell startup script)

`dev/docker/run-auth-winbind.sh`, `yq-go` and `su-exec` are gone. The
`Dockerfile.auth-winbind` entrypoint is now
`["/opt/rdpgw/rdpgw-auth", "--serve-user", "rdpgw"]`; everything the script
did is inside the daemon:

* provisioning/reconciliation of `smb.conf` and `krb5.conf`,
* domain join (`net ads testjoin` pre-check, auto-join with exponential
  backoff or a bounded wait for a manual join),
* shared keytab refresh, SPN registration and keytab permissions (`0644`),
* generation of the PAM stack when `AuthProtocols.Basic` is enabled,
* `winbindd` supervision (readiness via `wbinfo -p`, graceful stop on
  SIGTERM/SIGINT), with `RDPGW_WINBIND_PATH` and `RDPGW_WINBIND_DEBUG` as
  deployment overrides,
* `RDPGW_AUTH_EXTERNAL_WINBIND=1` still selects the host-provided winbindd
  compatibility mode (wait-only, 30s ready timeout).

Container arguments are forwarded to the same flags as before, so
`-c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock --allow-uid 1001`
manifests keep working. The daemon's default configuration path is
`rdpgw-auth.yaml` relative to its working directory
(`/opt/rdpgw/rdpgw-auth.yaml` in the image) — manifests that mount the config
to `/etc/rdpgw-auth.yaml` without a `-c` flag must now pass
`-c /etc/rdpgw-auth.yaml` explicitly.

### rdpgw-auth images are published as `rdpgw-auth` (legacy alias kept)

CI publishes `ghcr.io/<owner>/rdpgw-auth:<tag>` and keeps publishing the same
build as the legacy alias `rdpgw-auth-winbind:<tag>` (plus `latest` tags for
version pushes), so existing references keep resolving. Prefer `rdpgw-auth`
going forward.

### Unified `AuthProtocols` configuration for the auth daemon

`rdpgw-auth` now has one schema for all identity protocols:

```yaml
AuthProtocols:
  Kerberos:  # shared keytab for the gateway + SPN management
    share: true
    keytabPath: /var/lib/samba/rdpgw.keytab
    spns: [HTTP/rdpgw.example.com]
  Ntlm:      # ordered NTLM verifiers: winbind and/or users
    enabled: true
    backends: [winbind, users]
  Basic:     # generated PAM stack: winbind, ldap, unix, users (+ OATH 2FA)
    enabled: true
    stack: [{backend: unix}]
```

Legacy configurations keep working unchanged: without an `AuthProtocols`
block the legacy `Ntlm:` schema is mapped automatically (`Ntlm.Backend:
winbind` also enables the Kerberos keytab share; `Ntlm.Winbind.Spns` move to
`AuthProtocols.Kerberos.Spns`; `Ntlm.Winbind.Domain` maps to the modern
`Winbind.workgroup`, so a FQDN now belongs in `Winbind.domain`). Multiple
NTLM backends are tried in configured order per handshake; a backend chain
that cannot be built is an explicit denial instead of a silent fallback.
See [docs/advanced-auth-configuration.md](docs/advanced-auth-configuration.md).

### rdpgw-auth provisions `smb.conf` and `krb5.conf` (strict drift policy)

When the configuration has winbind capability, the daemon stages generated
`smb.conf`/`krb5.conf` under `/tmp/rdpgw/` and reconciles the targets before
joining:

* a missing target is installed;
* a writable target gets the generated settings it lacks **appended**
  (inside `[global]` for smb.conf; for krb5.conf single relations go inside
  their section and a missing realm block is appended as one collected
  `{ … }` unit): existing operator values are **never overwritten** — and
  krb5.conf in particular is no longer regenerated wholesale when it is
  writable; its merge treats each `[realms]` block as one value (realm
  names must be upper case; a case-only difference is drift, never a
  duplicate block), per
  [docs/configuration-provisioning.md](docs/configuration-provisioning.md);
* a setting the operator defined differently is drift: with the default
  strict policy (for `smb.conf` and `krb5.conf` alike) this stops the
  daemon — the error names every conflicting setting;
* settings that cannot be appended (a read-only target, or a `[global]`
  section ending in a continuation backslash) also stop the daemon in
  strict mode; a read-only file that already carries everything is accepted
  without writing;
* with **`--relaxed`** all of the above drift becomes a warning instead of an
  exit — the daemon keeps running and logs exactly what differs. Operator
  values stay untouched in every mode.

If you mount a hand-written `smb.conf` into the winbind container, make sure
it carries the same values the configuration produces (realm, workgroup,
`netbios name` via `Winbind.hostname`, separator, and with a keytab share
`kerberos method` / `dedicated keytab file` / `sync machine password to
keytab`), or leave it out and let the daemon generate it. Advanced settings
such as `Winbind.hostname`, `Winbind.domaincontrollers`, `autojoin`,
`jointimeout` and `requiremembershipof` feed the generated files. Only a
strict-mode (there: container) deployment stops on drift; `--relaxed`
deployments degrade loudly instead of crash-looping over a mount they
cannot rewrite.

### PAM stack generation and overwrite when `AuthProtocols.Basic` is enabled

Enabling `AuthProtocols.Basic` makes `rdpgw-auth` generate
`/etc/pam.d/rdpgw` on every start together with `/tmp/rdpgw/users.pwd`
(SHA-512 crypt of the YAML `Users`), per-profile LDAP client files and
`/opt/rdpgw/session_manager.sh` (a `pam_exec` helper that keeps the PAM
account phase on the backend that won the auth phase). Local edits to the
generated file are overwritten.

**Not enabling `AuthProtocols.Basic` is the legacy behavior**: the daemon
never touches `/etc/pam.d/rdpgw`, so hand-written PAM configurations,
traditional `pam_ldap.conf`-based LDAP stacks and custom module setups keep
working untouched.

### Domain join timing is now governed by the configuration

Previously the container joined (or waited indefinitely) based on whether
`AD_JOIN_USER`/`AD_JOIN_PASSWORD` were set in the environment. The policy now
comes from `Winbind.autojoin` / `Winbind.jointimeout` (default: manual join
with a 10-minute wait budget, after which the daemon exits with a remediation
playbook):

* `autojoin: true` + both env vars: automatic join retries with exponential
  backoff (2s → 30s) within the join budget;
* `autojoin: false` (default): the daemon logs the manual instructions and
  waits for an operator `net ads join`, then exits if the budget expires.

Existing Kubernetes secrets with those names keep working; just set
`Winbind.autojoin: true` to restore the automatic-join behavior.

### SPN configuration moved to `AuthProtocols.Kerberos.Spns`

SPNs are a Kerberos concern and now live under `AuthProtocols.Kerberos`.
The daemon registers missing SPNs from that list, the legacy `KERBEROS_SPNS`
environment variable, and `HTTP/<GatewayAddress>` derived from the gateway
configuration (`RDPGW_CONF`, default `/opt/rdpgw/rdpgw.yaml`) — the same
sources the removed startup script used. The legacy
`Ntlm.Winbind.Spns` field keeps working via the legacy mapping.

### Container image no longer bakes a TLS cert and runs as UID 1001

Two changes to `dev/docker/Dockerfile` and the dev image's entrypoint:

* The build step that ran `openssl genrsa` / `openssl x509` and shipped
  the resulting key/cert in the image is gone. The runtime image now
  contains `openssl` and the entrypoint mints an ephemeral self-signed
  cert at first start when no cert is mounted at the configured path.
  Each container instance gets its own key.
* The entrypoint runs as UID 1001 throughout. The previous `USER 0`
  block, the dead `createusers.txt` loop in `run.sh`, and the
  `chmod u+s` on `rdpgw-auth` (which set the bit on a file owned by
  1001 and was therefore a no-op anyway) have been removed.

If you mount your own cert (recommended for any non-dev deployment),
make sure `RDPGW_SERVER__CERT_FILE` and `RDPGW_SERVER__KEY_FILE` point
to the mounted paths. Otherwise the entrypoint generates a fresh
self-signed pair at the configured locations on first start.

If your deployment relies on `rdpgw-auth` running with elevated
privileges from the same image, run it from a separate container or
use Linux capabilities -- see
[docs/pam-authentication.md](docs/pam-authentication.md) for the
privilege-separation model.

### Refuse to start when known placeholder secrets are configured

These literal values appearing in `Server.SessionKey`,
`Server.SessionEncryptionKey`, `Security.PAATokenSigningKey`,
`Security.PAATokenEncryptionKey`, `Security.UserTokenSigningKey`,
`Security.UserTokenEncryptionKey`, or `Security.QueryTokenSigningKey`
will now cause rdpgw to refuse to start:

```
thisisasessionkeyreplacethisjetzt
thisisasessionkeyreplacethisjetz
thisisasessionkeyreplacethisnunu!
thisisasessionkeyreplacethisnunu
thisisasessionencryptionkey12345
```

These are the published example values from `README.md` and the dev
compose files. Replace them with unique 32-character strings.

### `rdpgw-auth` only accepts connections from the daemon's own UID by default

The auth daemon previously created its socket world-writable
(`Umask(0)`) and accepted any local UID that could `connect(2)` to it.
Two changes:

* The socket is now created with mode `0660` (no access for `other`).
* The daemon reads `SO_PEERCRED` on every accepted connection and
  rejects callers whose UID is not on the allow-list. The default
  allow-list is the daemon's own UID.

If `rdpgw` and `rdpgw-auth` run as the same user, no action is
required. Otherwise, list the gateway's UID (or a shared GID):

```
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-uid 1001
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-gid 1100
```

`--allow-uid` and `--allow-gid` are repeatable.

### `X-Forwarded-For` is no longer trusted by default

Previously rdpgw read the first `X-Forwarded-For` entry into the
request identity unconditionally. The resulting client IP attribute is
later compared against the value embedded in the gateway access
cookie, so any caller reaching rdpgw directly could set
`X-Forwarded-For` to any value and steer that binding.

After upgrading, `X-Forwarded-For` is honored only when the request
arrives from a `Server.TrustedProxies` CIDR. Otherwise the client IP
comes from `r.RemoteAddr`. The default `Server.TrustedProxies` is
empty, so by default `X-Forwarded-For` is ignored entirely.

If your deployment fronts rdpgw with a reverse proxy or load balancer
on a known subnet, list it:

```yaml
Server:
  TrustedProxies:
    - 10.0.0.0/8        # the proxy's egress subnet
```

If no proxy fronts rdpgw, leave `TrustedProxies` empty -- the
request's `RemoteAddr` is the right source for client identity in
that case.

### `hostselection: any` now refuses non-routable destinations and non-RDP ports by default

Previously, when `server.hostselection: any` was set, rdpgw forwarded
to whatever `?host=` value the request carried with no check on the
target. The gateway would happily relay TCP traffic to loopback,
RFC1918, link-local, or arbitrary high-numbered ports on public hosts.

After upgrading, `any` mode rejects any destination that resolves to a
loopback / RFC1918 / link-local / IPv6 ULA / unspecified / multicast
address, and any port that is not in `AllowedDestinationPorts`. The
default port allow-list is `[3389]`.

If your deployment legitimately reaches private destinations or extra
ports through `any` mode, opt back in:

```yaml
Server:
  HostSelection: any
  AllowedDestinationPorts:
    - 3389
    - 5985        # add what you actually need
  AllowPrivateDestinations: true
```

The other host-selection modes (`roundrobin`, `signed`, `unsigned`)
already use the operator-curated `Server.Hosts` allow-list and are
unaffected by this change.

# Upgrading from 1.X to 2.0

In 2.0 the options for configuring client side RDP settings have been removed in favor of template file.
The template file is a RDP file that is used as a template for the connection. The template file is parsed 
and a few settings are replaced to ensure the client can connect to the server and the correct domain is used.

The format of the template file is as follows:

```
# <setting>:<type i or s>:<value>
domain:s:testdomain
connection type:i:2
```

The filename is set under `client > defaults`.
