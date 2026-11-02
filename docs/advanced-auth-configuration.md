# RDPGW-Auth Advanced Configuration Reference

`rdpgw-auth` supports flexible, multi-backend authentication pipelines for both NTLM challenge-response and Basic (PAM) authentication protocols, including stacked fallbacks and OATH 2FA integration.

## Complete Configuration Example (`rdpgw-auth.yaml`)

```yaml
# ==========================================
# RDPGW-AUTH ADVANCED CONFIGURATION
# ==========================================

# 1. Active Directory Integration via Winbind
Winbind:
  domain: "corp.example.com"
  netbios: "CORP"
  ntlmAuthPath: "/usr/bin/ntlm_auth"
  timeout: 10
  spns:
    - "HTTP/rdpgw.corp.example.com"

# 2. LDAP Directories (keyed by profile name)
Ldap:
  corp-ldap:
    host: "ldap.example.com"
    port: 636
    tls: true
    base: "dc=example,dc=com"
    binddn: "cn=readonly,dc=example,dc=com"
    bindpw: "secret"

# 3. Local In-YAML Static Users
Users:
  - Username: "alice"
    Password: "secure_password_1"

# 4. Named OATH Policies (TOTP/HOTP, keyed by profile name)
Oath:
  default-totp:
    usersfile: "/etc/users.oath"
    window: 30
  strict-yubikey:
    usersfile: "/etc/yubikey.oath"

# 5. Protocol Frontends & Authentication Pipelines
AuthProtocols:
  # NTLM Protocol: Ordered list of NT-hash capable backends
  Ntlm:
    enabled: true
    backends:
      - "winbind"
      - "users"                         # Fallback to local YAML users if Winbind misses

  # Basic / Password Protocol: Full rich PAM stack with multiple backends and OATH 2FA linking
  Basic:
    enabled: true
    stack:
      - backend: "winbind"
        oath: "default-totp"            # Optional: attach 2FA to Winbind auth

      - backend: "ldap"
        name: "corp-ldap"               # References Ldap block named "corp-ldap"
        oath: "strict-yubikey"

      - backend: "unix"                 # Local system users /etc/shadow

      - backend: "users"                # Local YAML static users
        oath: "default-totp"
```

Both `Ldap` and `Oath` accept either the mapping form shown above or a list of
entries with a `name:` field. The two are equivalent, and duplicate names are
rejected in both forms:

```yaml
Ldap:
  - name: corp-ldap
    host: ldap.example.com
```

Stack entries can be written as bare strings when they need no `oath` policy.
A bare string that matches an `Ldap` profile resolves to
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

## Kerberos keytab sharing

With `AuthProtocols.Kerberos.Share: true`, `rdpgw-auth` keeps the Samba
machine keytab in `KeytabPath` and publishes the generated `krb5.conf` for
the gateway in `Krb5ConfPath`. When `Krb5ConfPath` is omitted it defaults to
`<KeytabPath directory>/krb5.conf`; with the default keytab that is
`/var/lib/samba/krb5.conf`. Point the gateway's `Kerberos.Krb5conf` at the same
shared path; the gateway reloads it when the file changes.

```yaml
AuthProtocols:
  Kerberos:
    Share: true
    KeytabPath: /var/lib/samba/rdpgw.keytab
    Krb5ConfPath: /var/lib/samba/krb5.conf # optional; default is next to the keytab
    Spns:
      - HTTP/rdpgw.example.com
```

## Backward Compatibility

For backward compatibility with existing deployments, legacy configurations such as:

```yaml
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: /usr/bin/ntlm_auth
    Domain: EXAMPLE
    Timeout: 10

Users:
  - Username: "admin"
    Password: "password"
```

Are automatically mapped into the new pipeline structure if the `AuthProtocols` block is omitted.

## Provisioning drift and `--relaxed`

`rdpgw-auth` provisions `smb.conf` and `krb5.conf` from its own configuration
and never overwrites operator values: missing settings are appended, a
differing value is drift. Strict mode (the default) refuses to start;
`--relaxed` logs the drift and keeps running. The full merge model -
normalization, comparison and insertion for both files - is documented in
[Configuration provisioning](configuration-provisioning.md).

Long-lived systemd deployments usually pass `--relaxed` so a value difference
in an operator-owned file becomes a loud warning instead of an outage:

```ini
# /etc/systemd/system/rdpgw-auth.service (excerpt)
[Service]
Environment=RDPGW_AUTH_EXTERNAL_WINBIND=1
ExecStart=/usr/local/bin/rdpgw-auth --conf /etc/rdpgw-auth.yaml --relaxed
```
