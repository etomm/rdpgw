# RDPGW-Auth Configuration Reference

`rdpgw-auth` supports multi-backend authentication pipelines for the NTLM
challenge/response and Basic (PAM) authentication protocols, including stacked
fallbacks and OATH 2FA integration. The same daemon also provisions the files
it needs at startup: `smb.conf`, `krb5.conf` and the `/etc/pam.d/<service>`
PAM stack (default `/etc/pam.d/rdpgw`). Legacy configurations keep working; see
[Legacy configuration](#legacy-configuration) at the bottom.

## Configuration example (`rdpgw-auth.yaml`)

```yaml
# ==========================================
# RDPGW-AUTH CONFIGURATION
# ==========================================

# 1. Active Directory integration via winbind
Winbind:
  Domain: "corp.example.com"          # FQDN of the domain (the Kerberos realm)
  Workgroup: "CORP"                   # NetBIOS domain name; derived from the
                                      # first Domain label (upper-cased) when omitted
  Hostname: "rdpgw-auth"              # name of the AD computer object ("netbios name" in smb.conf)
  RequireMembershipOf: "CORP\\RDP Users"  # optional: limit NTLM logons to a group or SID
  NtlmAuthPath: "/usr/bin/ntlm_auth"  # default path of Samba's ntlm_auth helper
  Timeout: 10                         # seconds to wait for each reply from ntlm_auth
  AutoJoin: true                      # join the AD domain automatically when unjoined
  JoinTimeout: 10                     # minutes budget for the (auto)join/wait, default 10
  StripDomain: false                  # report "alice" instead of "CORP\alice" to the gateway
  # Separator defaults to "\" and is omitted from the generated smb.conf
  # (smb.conf has no escape syntax); set it only for non-default separators.
  # Separator: "\\"
  DomainControllers:                  # feeds the generated krb5.conf; supports
    - "dc1.corp.example.com"          # plain hosts (port defaults 88 / 749) or
    - Host: "dc2.corp.example.com"    # explicit ports
      Port: 88
      AdminPort: 749

# 2. Kerberos protocol: shared keytab with the rdpgw gateway
AuthProtocols:
  Kerberos:
    Share: true                       # keep the machine keytab synchronized for the gateway
    KeytabPath: "/var/lib/samba/rdpgw.keytab"  # default shared keytab location
    Krb5ConfPath: "/var/lib/samba/krb5.conf"  # published for the gateway; default is next to the keytab
    Spns:                             # SPNs registered in AD and kept in the keytab
      - "HTTP/rdpgw.corp.example.com"

  # 3. NTLM protocol: ordered list of NT-hash capable verifiers
  Ntlm:
    Enabled: true
    Backends:
      - "winbind"                     # delegate to the domain controller first,
      - "users"                       # then fall back to the local YAML users

  # 4. Basic (password) protocol: generated PAM stack with OATH 2FA
  Basic:
    Enabled: true
    Stack:
      - Backend: "winbind"            # AD accounts via pam_winbind
        Oath: "default-totp"          # optional 2FA attached to this entry

      - Backend: "ldap"
        Name: "corp-ldap"             # references the Ldap profile below
        Oath: "strict-yubikey"

      - Backend: "unix"               # local system users (/etc/shadow)

      - Backend: "users"              # local YAML static users
        Oath: "default-totp"

# 5. LDAP directories (named profiles, referenced by the Basic stack)
Ldap:
  corp-ldap:
    Host: "ldap.example.com"
    Port: 636
    TLS: true
    Base: "dc=example,dc=com"
    BindDN: "cn=readonly,dc=example,dc=com"
    BindPW: "secret"

# 6. Static users (break-glass or simple deployments)
Users:
  - Username: "alice"
    Password: "secure_password_1"

# 7. Named OATH policies (TOTP/HOTP), referenced by the Basic stack
Oath:
  default-totp:
    UsersFile: "/etc/users.oath"
    Window: 30
  strict-yubikey:
    UsersFile: "/etc/yubikey.oath"
```

Keys are decoded case-insensitively, but the examples and references below use
the canonical field names for readability. When the file has no
`AuthProtocols` block at all, the [legacy mapping](#legacy-configuration)
applies.

## `AuthProtocols`

| Block | Keys | Meaning |
|-------|------|---------|
| `AuthProtocols.Kerberos` | `Share` (default `false`)<br>`KeytabPath` (default `/var/lib/samba/rdpgw.keytab`)<br>`Krb5ConfPath` (default `dir(KeytabPath)/krb5.conf`)<br>`Spns` (`[]string`) | When `Share: true`, `rdpgw-auth` keeps the Samba machine keytab synchronized in `KeytabPath`, publishes the reconciled `krb5.conf` to `Krb5ConfPath`, and makes sure every listed SPN is registered in Active Directory and present in the keytab. Required by the gateway's Kerberos `/KdcProxy` + keytab authentication. See [Keytab sharing and SPNs](#keytab-sharing-and-spns). |
| `AuthProtocols.Ntlm` | `Enabled` (default `true`)<br>`Backends` (ordered; `winbind` and/or `users`) | Ordered NTLM verifiers. Each handshake is committed to the first backend that produced a challenge; failed/unavailable backends are tried in order afterwards. See [docs/ntlm-authentication.md](ntlm-authentication.md). |
| `AuthProtocols.Basic` | `Enabled` (default `false`)<br>`Stack` | Ordered Basic (password) backends rendered into a generated PAM stack. See [docs/pam-authentication.md](pam-authentication.md). |

At least one protocol must be enabled; otherwise the configuration is invalid.

## `Winbind`

The `Winbind` block is required whenever any protocol uses the `winbind`
backend (Kerberos keytab share, NTLM `winbind`, Basic `winbind` entry).
`Domain` is mandatory because it is the Kerberos realm; `Workgroup` is derived
from it when omitted. `NtlmAuthPath` is checked at startup and must point to an
existing `ntlm_auth` binary; `Timeout` must be positive.

| Key | Default | Meaning |
|-----|---------|---------|
| `Domain` | required | FQDN of the domain, the Kerberos realm. Used as `realm` in `smb.conf` and `default_realm` in `krb5.conf`. |
| `Workgroup` | derived | NetBIOS domain name (pre-Windows 2000). When empty, derived by upper-casing the first label of `Domain`. Used as `workgroup` and for the `idmap config <workgroup>` lines in `smb.conf`. |
| `Hostname` | empty | Machine computer name in Active Directory. Sets `netbios name = <hostname>` in `smb.conf`. Set a stable name instead of relying on an ephemeral container hostname: it is the AD computer account registered and joined across restarts. |
| `RequireMembershipOf` | empty | Passed to `ntlm_auth` as `--require-membership-of`. A `DOMAIN\Group` name or SID; only members authenticate. |
| `NtlmAuthPath` | `/usr/bin/ntlm_auth` | Path of the `ntlm_auth` helper binary; its existence is validated at startup. |
| `Timeout` | `10` | Seconds to wait for a single exchange with `ntlm_auth`. |
| `AutoJoin` | `false` | Automatically join the domain with `AD_JOIN_USER`/`AD_JOIN_PASSWORD` when `net ads testjoin` reports the host is not joined. |
| `JoinTimeout` | `10` | Minutes budget: with `AutoJoin: true`, bounded retry loop (exponential backoff, 2s to 30s); with `AutoJoin: false`, how long the daemon waits for a manual `net ads join`. After the budget the daemon exits with the operator playbook. |
| `StripDomain` | `false` | When true, the gateway sees `alice` instead of `CORP\alice` (rdpgw-auth normalizes; winbindd keeps reporting the full name). |
| `Separator` | `\` | The `winbind separator` from `smb.conf`. The default backslash is expressed by **omitting** the directive (smb.conf's parser has no escape syntax and would continue any backslash-terminated line); any other single character is written verbatim. See [docs/configuration-provisioning.md](configuration-provisioning.md). |
| `DomainControllers` | empty | Feeds the `kdc`/`admin_server` lines of the generated `krb5.conf`. Plain entries get ports 88/749; objects may set `Host`, `Port` and `AdminPort`. Without entries the generated `krb5.conf` relies on DNS SRV discovery. |

## `Ldap` and `Oath` profiles

Both `Ldap` and `Oath` accept either the mapping form shown above or a list of
entries with a `Name` field. The two are equivalent, and duplicate names are
rejected in both forms:

```yaml
Ldap:
  - Name: corp-ldap
    Host: ldap.example.com
```

Basic stack entries can be written as bare strings when they need no `Oath`
policy. A bare string that matches an `Ldap` profile resolves to
`{Backend: ldap, Name: <profile>}`; the reserved backend names `winbind`,
`unix` and `users` resolve to that backend. `ldap` cannot be bare because it
needs a profile name.

```yaml
  Basic:
    Enabled: true
    Stack:
      - winbind
      - corp-ldap        # same as {Backend: ldap, Name: corp-ldap}
      - users
```

Use the object form to attach an OATH policy:

```yaml
      - Backend: users
        Oath: default-totp
```

For that reason `Ldap` and `Oath` profile names cannot be `winbind`, `ldap`,
`unix`, `users` or `oath`. Profile names may only contain letters, digits,
`.`, `_` and `-`. They are case-insensitive: `Corp` and `corp` are the same
profile.

Each referenced `Ldap` profile also creates a per-profile LDAP client
configuration (`Host`, `Port`, `TLS`, `Base`, `BindDN`, `BindPW`) that the
generated stack hands to `pam_ldap.so`; it contains the bind password and is
mode `0600`, or `0640` readable by the serving group when `--serve-user` is
used.

## Static users

The static `Users` list is used by:

- the NTLM `users` backend (verifying AUTHENTICATE messages against the list in-process), and
- the Basic `users` stack entry, when present. `rdpgw-auth` then generates a
  `pam_pwdfile` database (`users.pwd`) with a freshly salted SHA-512 crypt
  hash per username at every start; the file is only generated when the stack
  contains a `users` entry, and is regenerated on each startup.

## What rdpgw-auth provisions at startup

With winbind capability, `rdpgw-auth` stages rendered `smb.conf` and
`krb5.conf` under `/tmp/rdpgw/`, installs or merges
`/etc/samba/smb.conf` and `/etc/krb5.conf`, and generates
`/etc/pam.d/<service>` only when `AuthProtocols.Basic` is enabled. Existing
operator values are never overwritten: drift stops the daemon by default and
becomes a warning with `--relaxed`. Samba runtime directories and
`secrets.ldb` are only prepared when the daemon supervises `winbindd`.

The full artifact list, merge model, strict/relaxed table and parser details
are in [Configuration provisioning](configuration-provisioning.md). PAM
generation is covered in [PAM Authentication](pam-authentication.md).

After provisioning, `rdpgw-auth` ensures domain membership, refreshes the
shared keytab/SPNs (see below), starts and supervises `winbindd` (readiness
probe via `wbinfo -p`, graceful stop on SIGTERM/SIGINT), and only then opens
the gRPC socket.

## Keytab sharing and SPNs

With `AuthProtocols.Kerberos.Share: true` the generated `smb.conf` contains:

```ini
    dedicated keytab file = <KeytabPath>
    sync machine password to keytab = "<KeytabPath>:sync_spns:sync_kvno:machine_password"
```

so Samba keeps the keytab in sync with the machine account password. On every
start the daemon refreshes the keytab (`net ads keytab create -P`), then makes
sure each SPN is present, in order:

1. `AuthProtocols.Kerberos.Spns` from the configuration;
2. `KERBEROS_SPNS` (comma or space separated), the legacy environment variable;
3. `HTTP/<GatewayAddress>` derived from the gateway configuration file set
   with `RDPGW_CONF` (default `/opt/rdpgw/rdpgw.yaml`).

SPNs that are missing from the keytab are registered with `net ads setspn
add` when `AD_JOIN_USER`/`AD_JOIN_PASSWORD` are available; otherwise the daemon
logs the manual registration instructions and waits until the SPN appears.
The keytab ends with mode `0644` so the gateway container can read it through
the shared volume.

When the keytab is shared, `rdpgw-auth` also publishes the reconciled
`krb5.conf` to `Krb5ConfPath`. It defaults to `dir(KeytabPath)/krb5.conf`
(`/var/lib/samba/krb5.conf` with the default keytab), so both Kerberos files
travel through the same shared volume. Point the gateway's
`Kerberos.Krb5conf` at that path; the gateway reloads the file when it changes.

## Domain join and winbindd supervision

- `net ads testjoin` pre-check: an already-joined host is left alone.
- `AutoJoin: true`: retries `net ads join` with exponential backoff using
  `AD_JOIN_USER` / `AD_JOIN_PASSWORD` (the same variable names the legacy
  startup script used, so Kubernetes secrets keep working).
- `AutoJoin: false` (default): logs the manual instructions (`net ads join -U
  Administrator` inside the container) and waits until the join budget
  expires.
- The daemon then starts `winbindd` (`-F --no-process-group --debug-stdout
  -d 2` by default), waits for `wbinfo -p` readiness before opening the gRPC
  socket, and stops winbindd gracefully on shutdown.
- `RDPGW_WINBIND_PATH` and `RDPGW_WINBIND_DEBUG` are environment overrides
  (deployment concerns, not configuration schema), e.g. `-d 5`.
- `RDPGW_AUTH_EXTERNAL_WINBIND=1`: deployment uses a host-provided winbindd
  instead. No join is attempted and no child is started; the daemon only
  waits up to 30s for the external winbindd.

## Manual domain join and provisioning

Manual operations are not legacy-specific. They are required whenever
`Winbind.AutoJoin` is `false` (the default), when `AD_JOIN_USER` /
`AD_JOIN_PASSWORD` are not available, or when the host provides its own
`winbindd`. The steps below are the manual equivalent of what the daemon does
automatically:

```bash
# 1. Install Samba/winbind (the image already contains them)
sudo apt install winbind samba-common-bin krb5-user

# 2. Prepare smb.conf/krb5.conf yourself and join the domain
sudo net ads join -U Administrator
net ads testjoin

# 3. Generate the shared keytab and register SPNs
sudo net ads keytab create -P
sudo net ads setspn add HTTP/rdpgw.example.com -U Administrator
klist -k /var/lib/samba/rdpgw.keytab

# 4. Let the gateway read the shared keytab
sudo chown rdpgw:rdpgw /var/lib/samba/rdpgw.keytab
sudo chmod 644 /var/lib/samba/rdpgw.keytab

# 5. Start/verify winbind and the privileged pipe access
sudo systemctl enable --now winbind
wbinfo -t && wbinfo -p
sudo usermod -aG winbindd_priv rdpgw

# 6. Static users for the Basic stack: create users.pwd yourself
#    (or let AuthProtocols.Basic generate it; see pam-authentication.md)
```

Manual paths keep working as before:

- Mounting your own `/etc/samba/smb.conf` is still possible; it must either
  carry the values the configuration produces, or be writable so the missing
  settings can be merged in (existing values are never replaced).
- A classic deployment on a domain-joined Linux host with a system
  `winbindd` service: set `RDPGW_AUTH_EXTERNAL_WINBIND=1` so `rdpgw-auth`
  delegates winbindd and the join state to the host (it only waits for
  readiness) instead of starting its own winbindd. It still reconciles the
  client-side `smb.conf`/`krb5.conf` files; existing values are never
  replaced, and anything it cannot reconcile keeps the daemon from starting
  half-configured.

Long-lived systemd deployments usually also pass `--relaxed` (see the policy
in [Configuration provisioning](configuration-provisioning.md)) so a value
difference in an operator-owned file becomes a loud warning instead of an
outage:

```ini
# /etc/systemd/system/rdpgw-auth.service (excerpt)
[Service]
Environment=RDPGW_AUTH_EXTERNAL_WINBIND=1
ExecStart=/usr/local/bin/rdpgw-auth --conf /etc/rdpgw-auth.yaml --relaxed
```

## Legacy configuration

Legacy configurations without the `AuthProtocols` block keep working: they
are mapped automatically into the modern structure. The legacy schema is the
NTLM-focused block that `rdpgw-auth` used before multi-protocol pipelines:

```yaml
Ntlm:
  Backend: winbind        # or "file" (default) / "users"
  Winbind:
    NtlmAuthPath: /usr/bin/ntlm_auth
    Domain: EXAMPLE       # NetBIOS workgroup in the legacy schema
    RequireMembershipOf: "EXAMPLE\\RDP Users"
    Timeout: 10
    StripDomain: false
    Separator: "\\"
    Spns:                 # carried over to AuthProtocols.Kerberos.Spns
      - HTTP/rdpgw.example.com

Users:
  - Username: "alice"
    Password: "secure_password_1"
```

The mapping runs only when the configuration file contains no
`AuthProtocols` block:

| Legacy key | Modern equivalent |
|------------|-------------------|
| `Ntlm.Backend: winbind` | `AuthProtocols.Ntlm` with `Backends: [winbind]` **and** `AuthProtocols.Kerberos` with `Share: true` and the default keytab path |
| `Ntlm.Winbind.Domain` | `Winbind.Workgroup` (the legacy field held the NetBIOS domain, not the FQDN) |
| `Ntlm.Winbind.NtlmAuthPath`, `Ntlm.Winbind.Timeout`, `Ntlm.Winbind.RequireMembershipOf`, `Ntlm.Winbind.StripDomain`, `Ntlm.Winbind.Separator` | the same-named `Winbind.*` fields |
| `Ntlm.Winbind.Spns` | `AuthProtocols.Kerberos.Spns` |
| `Ntlm.Backend: file` or omitted, with a `Users` list | `AuthProtocols.Ntlm` with `Backends: [users]` |
| a top-level `Winbind:` block | stays as-is (modern `Winbind` schema) |

Notes:

- The legacy schema never enabled the Basic (PAM) protocol, so an operator
  hand-written `/etc/pam.d/<service>` keeps being used unchanged. Switching to
  `AuthProtocols.Basic` starts to generate and overwrite that file.
- The legacy `Domain` was ambiguous. The generated `smb.conf` `realm` and
  `krb5.conf` `default_realm` are the DNS/Kerberos realm, so
  **`Winbind.Domain` (the FQDN) is required whenever `rdpgw-auth` provisions
  these files**. `Ntlm.Winbind.Domain` only maps to the NetBIOS
  `Winbind.Workgroup` and cannot substitute for the realm. A legacy
  NetBIOS-only configuration must add a top-level
  `Winbind: { Domain: corp.example.com }`, or keep mounting a complete
  `smb.conf`/`krb5.conf`.
- `Users` is ignored with a winbind NTLM backend; `rdpgw-auth` logs a
  warning when it is present.

## Troubleshooting

- **`Invalid configuration: unknown AuthProtocols`**: the file has neither a
  usable `AuthProtocols` block nor a legacy `Ntlm`/`Users` setup. Keep at least
  one protocol enabled.
- **`Winbind must be configured ...`**: a winbind backend (Kerberos keytab
  share, NTLM `winbind`, or Basic `winbind`) is enabled but the `Winbind`
  block is missing.
- **`Winbind.NtlmAuthPath ... is not usable`**: `ntlm_auth` is not installed
  at the configured path (default `/usr/bin/ntlm_auth`).
- **`Winbind.Domain ... must be set`**: the generated `smb.conf` `realm` and
  `krb5.conf` `default_realm` need the DNS/Kerberos FQDN, not the NetBIOS
  workgroup. A bare `Winbind:` block is not enough for a winbind-capable
  deployment; `Winbind.Workgroup` is derived by `config.Load` from `Domain`.
- **`AuthProtocols.Basic.Stack[...] references unknown Ldap/Oath`**: the
  profile name does not exist; profile names are case-insensitive but must be
  declared under `Ldap:` / `Oath:`.
- **Generated PAM stack not applied**: `/etc/pam.d/<service>` is read-only and
  differs from the generated stack; the daemon warns and keeps the operator
  file. Compare it with the header comment showing the configured backend
  order, or make the file writable.
- **Drift in `smb.conf`/`krb5.conf` at startup**: strict mode exits naming
  every conflicting setting; reconcile the operator file with the staged
  reference under `/tmp/rdpgw/`, or pass `--relaxed` on systemd hosts.
- **`--serve-user` fails**: it requires root and a resolvable user; drop the
  flag when the daemon already runs as the serving user.
- **Domain join/SPN wait**: see the playbooks in
  [NTLM Authentication](ntlm-authentication.md#troubleshooting) and
  [Kerberos Authentication](kerberos-authentication.md#troubleshooting).

Useful commands:

```bash
# Show the effective configuration defaults and validation errors
rdpgw-auth --conf /etc/rdpgw-auth.yaml --help

# Inspect generated artifacts
ls -l /tmp/rdpgw/ /etc/samba/smb.conf /etc/krb5.conf /etc/pam.d/rdpgw

# Verify the domain side
net ads testjoin
wbinfo -t
klist -k /var/lib/samba/rdpgw.keytab

# PAM smoke test (matches the gateway's account phase)
pamtester rdpgw alice authenticate
```
