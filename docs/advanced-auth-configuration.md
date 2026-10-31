# RDPGW-Auth Advanced Configuration Reference

`rdpgw-auth` supports flexible, multi-backend authentication pipelines for both NTLM challenge-response and Basic (PAM) authentication protocols, including stacked fallbacks and OATH 2FA integration.

## Complete Configuration Example (`rdpgw-auth.yaml`)

```yaml
# ==========================================
# RDPGW-AUTH ADVANCED CONFIGURATION
# ==========================================

# 1. Active Directory Integration via Winbind
Winbind:
  domain: "valinor.ercole.li"
  netbios: "VALINOR"
  ntlmAuthPath: "/usr/bin/ntlm_auth"
  timeout: 10
  spns:
    - "HTTP/calacirya.doomring.valinor.ercole.li"

# 2. LDAP Directories (Multiple allowed)
Ldap:
  - name: "corp-ldap"
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

# 4. Multiple Named OATH Policies (TOTP/HOTP)
Oath:
  - name: "default-totp"
    usersfile: "/etc/users.oath"
    window: 30
  - name: "strict-yubikey"
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
