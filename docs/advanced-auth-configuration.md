# RDPGW-Auth Configuration Reference

`rdpgw-auth` supports multi-backend authentication pipelines for the NTLM
challenge/response and Basic (PAM) authentication protocols, including stacked
fallbacks and OATH 2FA integration. The same daemon also provisions the files
it needs at startup: `smb.conf`, `krb5.conf` and the `/etc/pam.d/rdpgw` PAM
stack. Legacy configurations keep working; see
[Legacy configuration](#legacy-configuration) at the bottom.

## Configuration example (`rdpgw-auth.yaml`)

```yaml
# ==========================================
# RDPGW-AUTH CONFIGURATION
# ==========================================

# 1. Active Directory integration via winbind
Winbind:
  domain: "corp.example.com"          # FQDN of the domain (the Kerberos realm)
  workgroup: "CORP"                   # NetBIOS domain name; derived from the
                                      # first domain label (upper-cased) when omitted
  hostname: "rdpgw-auth"              # name of the AD computer object ("netbios name" in smb.conf)
  requiremembershipof: "CORP\\RDP Users"  # optional: limit NTLM logons to a group or SID
  ntlmauthpath: "/usr/bin/ntlm_auth"  # default path of Samba's ntlm_auth helper
  timeout: 10                         # seconds to wait for each reply from ntlm_auth
  autojoin: true                      # join the AD domain automatically when unjoined
  jointimeout: 10                     # minutes budget for the (auto)join/wait, default 10
  stripdomain: false                  # report "alice" instead of "CORP\alice" to the gateway
  # separator defaults to "\" and is omitted from the generated smb.conf
  # (smb.conf has no escape syntax); set it only for non-default separators.
  # separator: "\\"
  domaincontrollers:                  # feeds the generated krb5.conf; supports
    - "dc1.corp.example.com"          # plain hosts (ports default 88 / 749) or
    - host: "dc2.corp.example.com"    # explicit ports
      port: 88
      adminport: 749

# 2. Kerberos protocol: shared keytab with the rdpgw gateway
AuthProtocols:
  Kerberos:
    share: true                       # keep the machine keytab synchronized for the gateway
    keytabpath: "/var/lib/samba/rdpgw.keytab"  # default shared keytab location
    spns:                             # SPNs registered in AD and kept in the keytab
      - "HTTP/rdpgw.corp.example.com"

  # 3. NTLM protocol: ordered list of NT-hash capable verifiers
  Ntlm:
    enabled: true
    backends:
      - "winbind"                     # delegate to the domain controller first,
      - "users"                       # then fall back to the local YAML users

  # 4. Basic (password) protocol: generated PAM stack with OATH 2FA
  Basic:
    enabled: true
    stack:
      - backend: "winbind"            # AD accounts via pam_winbind
        oath: "default-totp"          # optional 2FA attached to this entry

      - backend: "ldap"
        name: "corp-ldap"             # references the Ldap profile below
        oath: "strict-yubikey"

      - backend: "unix"               # local system users (/etc/shadow)

      - backend: "users"              # local YAML static users
        oath: "default-totp"

# 5. LDAP directories (named profiles, referenced by the Basic stack)
Ldap:
  corp-ldap:
    host: "ldap.example.com"
    port: 636
    tls: true
    base: "dc=example,dc=com"
    binddn: "cn=readonly,dc=example,dc=com"
    bindpw: "secret"

# 6. Static users (break-glass or simple deployments)
Users:
  - Username: "alice"
    Password: "secure_password_1"

# 7. Named OATH policies (TOTP/HOTP), referenced by the Basic stack
Oath:
  default-totp:
    usersfile: "/etc/users.oath"
    window: 30
  strict-yubikey:
    usersfile: "/etc/yubikey.oath"
```

Configuration keys are case-insensitive. When the file has no
`AuthProtocols` block at all, the [legacy mapping](#legacy-configuration)
applies.

## `AuthProtocols`

| Block | Keys | Meaning |
|-------|------|---------|
| `AuthProtocols.Kerberos` | `share` (`false`, default), `keytabpath` (default `/var/lib/samba/rdpgw.keytab`), `spns` (`[]string`) | When `share: true`, `rdpgw-auth` keeps the Samba machine keytab synchronized in `keytabpath` and makes sure every listed SPN is registered in Active Directory and present in the keytab. Required by the gateway's Kerberos `/KdcProxy` + keytab authentication. See [Keytab sharing and SPNs](#keytab-sharing-and-spns). |
| `AuthProtocols.Ntlm` | `enabled` (default `true`), `backends` (ordered; `winbind` and/or `users`) | Ordered NTLM verifiers. Each handshake is committed to the first backend that produced a challenge; failed/unavailable backends are tried in order afterwards. See [docs/ntlm-authentication.md](ntlm-authentication.md). |
| `AuthProtocols.Basic` | `enabled` (`false`, default), `stack` | Ordered Basic (password) backends rendered into a generated PAM stack. See [docs/pam-authentication.md](pam-authentication.md). |

At least one protocol must be enabled; otherwise the configuration is invalid.

## `Winbind`

The `Winbind` block is required whenever any protocol uses the `winbind`
backend (Kerberos keytab share, NTLM `winbind`, Basic `winbind` entry).
`ntlmauthpath` is checked at startup and must point to an existing
`ntlm_auth` binary; `timeout` must be positive.

| Key | Default | Meaning |
|-----|---------|---------|
| `domain` | empty | FQDN of the domain, the Kerberos realm. Used as `realm` in `smb.conf` and `default_realm` in `krb5.conf`. |
| `workgroup` | derived | NetBIOS domain name (pre-Windows 2000). When empty, derived by upper-casing the first label of `domain`. Used as `workgroup` and for the `idmap config <workgroup>` lines in `smb.conf`. |
| `hostname` | empty | Machine computer name in Active Directory. Sets `netbios name = <hostname>` in `smb.conf`. Set a stable name instead of relying on an ephemeral container hostname: it is the AD computer account registered and joined across restarts. |
| `requiremembershipof` | empty | Passed to `ntlm_auth` as `--require-membership-of`. A `DOMAIN\Group` name or SID; only members authenticate. |
| `ntlmauthpath` | `/usr/bin/ntlm_auth` | Path of the `ntlm_auth` helper binary; its existence is validated at startup. |
| `timeout` | `10` | Seconds to wait for a single exchange with `ntlm_auth`. |
| `autojoin` | `false` | Automatically join the domain with `AD_JOIN_USER`/`AD_JOIN_PASSWORD` when `net ads testjoin` reports the host is not joined. |
| `jointimeout` | `10` | Minutes budget: with `autojoin: true`, bounded retry loop (exponential backoff, 2s→30s); with `autojoin: false`, how long the daemon waits for a manual `net ads join`. After the budget the daemon exits with the operator playbook. |
| `stripdomain` | `false` | When true, the gateway sees `alice` instead of `CORP\alice` (rdpgw-auth normalizes; winbindd keeps reporting the full name). |
| `separator` | `\` | The `winbind separator` from `smb.conf`. The default backslash is expressed by **omitting** the directive (smb.conf's parser has no escape syntax and would continue any backslash-terminated line); any other single character is written verbatim. See [docs/configuration-provisioning.md](configuration-provisioning.md). |
| `domaincontrollers` | empty | Feeds the `kdc`/`admin_server` lines of the generated `krb5.conf`. Plain entries get ports 88/749; objects may set both. Without entries the generated `krb5.conf` relies on DNS SRV discovery. |

## `Ldap` and `Oath` profiles

Both `Ldap` and `Oath` accept either the mapping form shown above or a list of
entries with a `name:` field. The two are equivalent, and duplicate names are
rejected in both forms:

```yaml
Ldap:
  - name: corp-ldap
    host: ldap.example.com
```

Basic stack entries can be written as bare strings when they need no `oath`
policy. A bare string that matches an `Ldap` profile resolves to
`{backend: ldap, name: <profile>}`; the reserved backend names `winbind`,
`unix` and `users` resolve to that backend. `ldap` cannot be bare because it
needs a profile name.

```yaml
  Basic:
    enabled: true
    stack:
      - winbind
      - corp-ldap        # same as {backend: ldap, name: corp-ldap}
      - users
```

Use the object form to attach an OATH policy:

```yaml
      - backend: users
        oath: default-totp
```

For that reason `Ldap` and `Oath` profile names cannot be `winbind`, `ldap`,
`unix`, `users` or `oath`. Profile names may only contain letters, digits,
`.`, `_` and `-`. They are case-insensitive: `Corp` and `corp` are the same
profile.

Each referenced `Ldap` profile also creates a per-profile LDAP client
configuration (`host`, `port`, `tls`, `base`, `binddn`, `bindpw`) that the
generated stack hands to `pam_ldap.so`; it contains the bind password and is
mode `0600`.

## Static users

The static `Users` list is used by:

- the NTLM `users` backend (verifying AUTHENTICATE messages against the list in-process), and
- the Basic `users` stack entry, for which `rdpgw-auth` generates a
  `pam_pwdfile` database (`users.pwd`) with a freshly salted SHA-512 crypt
  hash per username at every start; the file is regenerated on each startup.

## What rdpgw-auth provisions at startup

When the configuration has *winbind capability* (Kerberos keytab share, or a
winbind NTLM/Basic backend), the daemon prepares its own system files so the
container no longer needs startup scripts for them:

1. **Staging**: templates are rendered into `/tmp/rdpgw/` (transient, image
   owned).
2. **`/etc/samba/smb.conf`**: generated or merged:
   - missing: installed;
   - present: the generated `[global]` settings the file lacks
     are appended; existing operator values are **never overwritten**;
   - a value that differs from the generated one is drift: in strict mode
     (the default) the daemon exits listing every conflict, with `--relaxed`
     it logs the same list and keeps running;
   - required settings that cannot be added (read-only volume, or a
     `[global]` section ending in a continuation backslash) terminate
     the daemon in strict mode and only warn in relaxed mode. The
     authoritative directives are `kerberos method`,
     `dedicated keytab file` and `sync machine password to keytab`
     (the last two only with a keytab share).
3. **PAM stack** (`/etc/pam.d/rdpgw`): generated only when
   `AuthProtocols.Basic` is enabled; otherwise an operator-provided PAM file
   is left alone. See [docs/pam-authentication.md](pam-authentication.md).
4. **`/etc/krb5.conf`**: merged from `Winbind.domain` and
   `domaincontrollers` with exactly the same rules as `smb.conf` (never
   overwritten): missing single-line relations are appended inside their
   section, a missing realm block is appended whole (the collected `{ … }`
   text verbatim), and differing
   values follow the strict/relaxed policy. A read-only `krb5.conf` behaves
   like a read-only `smb.conf`: accepted when it already carries everything,
   otherwise strict mode stops and `--relaxed` warns.
5. **Samba runtime state** (only when the daemon itself supervises
   `winbindd`): the runtime directories and an initial `secrets.ldb` are
   created before the join. With an external winbindd the host owns that
   state and it is left alone.

The two policies side by side (the full merge model — normalization,
comparison, insertion anchors — is documented in
[Configuration provisioning](configuration-provisioning.md)):

| Situation | strict (default) | `--relaxed` |
|---|---|---|
| File missing | installed | installed |
| Missing generated settings, writable file | appended | appended |
| Operator value differs | daemon exits, error names every conflict | warning, keeps running; the value stays |
| Settings cannot be added (read-only target, continuation hazard) | daemon exits | warning, keeps running |
| Unbalanced `krb5.conf` braces | daemon exits | warning, keeps running |

`--relaxed` exists for long-lived systemd deployments, where the operator
fully owns the files and an outage over a value difference is worse than a
loud warning. Container deployments keep strict by default so drift is
caught at deploy time. The generated files always live in the staging
directory (`/tmp/rdpgw/`) as the reconciliation reference, and the same
warnings name the `--relaxed` escape hatch inline.

After provisioning, `rdpgw-auth` ensures domain membership, refreshes the
shared keytab/SPNs (see below), starts and supervises `winbindd` (readiness
probe via `wbinfo -p`, graceful stop on SIGTERM/SIGINT), and only then opens
the gRPC socket.

## Keytab sharing and SPNs

With `AuthProtocols.Kerberos.share: true` the generated `smb.conf` contains:

```ini
    dedicated keytab file = <keytabpath>
    sync machine password to keytab = "<keytabpath>:sync_spns:sync_kvno:machine_password"
```

so Samba keeps the keytab in sync with the machine account password. On every
start the daemon refreshes the keytab (`net ads keytab create -P`), then makes
sure each SPN is present, in order:

1. `AuthProtocols.Kerberos.spns` from the configuration;
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
- `autojoin: true`: retries `net ads join` with exponential backoff using
  `AD_JOIN_USER` / `AD_JOIN_PASSWORD` (the same variable names the legacy
  startup script used, so Kubernetes secrets keep working).
- `autojoin: false` (default): logs the manual instructions (`net ads join -U
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
| `Ntlm.Backend: winbind` | `AuthProtocols.Ntlm` with `backends: [winbind]` **and** `AuthProtocols.Kerberos` with `share: true` and the default keytab path |
| `Ntlm.Winbind.Domain` | `Winbind.workgroup` (the legacy field held the NetBIOS domain, not the FQDN) |
| `Ntlm.Winbind.NtlmAuthPath`, `Ntlm.Winbind.Timeout`, `Ntlm.Winbind.RequireMembershipOf`, `Ntlm.Winbind.StripDomain`, `Ntlm.Winbind.Separator` | the same-named `Winbind.*` fields |
| `Ntlm.Winbind.Spns` | `AuthProtocols.Kerberos.Spns` |
| `Ntlm.Backend: file` or omitted, with a `Users` list | `AuthProtocols.Ntlm` with `backends: [users]` |
| a top-level `Winbind:` block | stays as-is (modern `Winbind` schema) |

Notes:

- The legacy schema never enabled the Basic (PAM) protocol, so an operator
  hand-written `/etc/pam.d/rdpgw` keeps being used unchanged. Switching to
  `AuthProtocols.Basic` starts to generate and overwrite that file.
- The legacy `Domain` was ambiguous. If you switch to the modern schema,
  put the NetBIOS name in `Winbind.workgroup` and the FQDN in
  `Winbind.domain`; the generated `smb.conf`/`krb5.conf` need the FQDN.
- `Users` is ignored with a winbind NTLM backend; `rdpgw-auth` logs a
  warning when it is present.

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

Long-lived systemd deployments usually also pass `--relaxed` (see the
policy table above) so a value difference in an operator-owned file becomes
a loud warning instead of an outage:

```ini
# /etc/systemd/system/rdpgw-auth.service (excerpt)
[Service]
Environment=RDPGW_AUTH_EXTERNAL_WINBIND=1
ExecStart=/usr/local/bin/rdpgw-auth --conf /etc/rdpgw-auth.yaml --relaxed
```
