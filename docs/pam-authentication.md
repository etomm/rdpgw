# PAM/Local Authentication

![PAM](images/flow-pam.svg)

RDPGW supports PAM (Pluggable Authentication Modules) for authentication against local accounts, LDAP, Active Directory, and other PAM-supported systems.

## Important Notes

**⚠️ Client Limitation**: The default Windows client `mstsc` does not support basic authentication. Use alternative clients or switch to OpenID Connect, Kerberos, or NTLM authentication.

**⚠️ Container Considerations**: Using PAM for passwd authentication within containers is not recommended. Use OpenID Connect or Kerberos instead. For LDAP/AD authentication, PAM works well in containers.

## Architecture

PAM authentication uses a privilege separation model with the `rdpgw-auth` helper program:

- `rdpgw` - Main gateway (runs as unprivileged user)
- `rdpgw-auth` - Authentication helper (runs as root or setuid)
- Communication via Unix socket

## PAM stack: hand-written or generated

You have two options, and both remain supported:

1. **Hand-driven PAM configuration (classic, and still fully supported).** You
   write `/etc/pam.d/rdpgw` yourself exactly as described below and leave
   `AuthProtocols.Basic` disabled in `rdpgw-auth.yaml`. Without an enabled
   Basic protocol `rdpgw-auth` never touches `/etc/pam.d/rdpgw`, and PAM
   modules are configured the standard way (pam_ldap.conf, smb.conf,
   /etc/shadow...). This is the right choice for non-container hosts and for
   setups with unusual PAM requirements.

2. **Generated PAM stack (modern).** Enable `AuthProtocols.Basic` in
   `rdpgw-auth.yaml` and `rdpgw-auth` generates `/etc/pam.d/rdpgw` at every
   startup from an ordered `stack` of backends — `winbind`, `ldap`,
   `unix`, `users` — each optionally chained with an OATH (TOTP/HOTP)
   policy. Companion files are generated too:
   - `/tmp/rdpgw/users.pwd`: `pam_pwdfile` database of the YAML `Users` list
     (SHA-512 crypt, random salt per start, mode `0600`);
   - per-profile LDAP client files for every referenced `Ldap` entry
     (contain the bind password, mode `0600`);
   - `/opt/rdpgw/session_manager.sh`: a `pam_exec` helper that records which
     backend won the `auth` phase and steers the `account` phase to the same
     backend. The daemon injects a fresh per-attempt `RDPGW_SESSION_ID` into
     the PAM environment, so concurrent logins for the same user do not
     interfere and a missing id fails closed.

   The generated file's header is explicit — local hand edits are overwritten
   on the next start. With the generated stack you do not manage
   `/etc/pam_ldap.conf`, winbind's smb.conf account phase, or the users file
   yourself. See the
   [configuration reference](advanced-auth-configuration.md#authprotocols)
   for the exact schema.

Why the generated stack takes this route: on musl-based (Alpine) images
there is no NSS, so a `getpwnam`-style local lookup fails for domain users
and the PAM `account` phase cannot be resolved reliably. The account phase
must deterministically match whichever backend succeeded during the `auth`
phase; `session_manager.sh` + `pam_exec` control-flag jumps provide that
without arithmetic skip-count changes when you reorder the stack. Details in
`docs/plans/auth-migration-plan.md`.

The generated winbind block is:

```text
auth    [success=ok default=1]       pam_winbind.so
auth    [success=done default=die]   pam_exec.so /opt/rdpgw/session_manager.sh create winbind

account [success=ok default=2]       pam_exec.so quiet /opt/rdpgw/session_manager.sh check winbind
account [success=ok default=die]     pam_permit.so
account [success=done default=done]  pam_exec.so quiet /opt/rdpgw/session_manager.sh cleanup
```

With an OATH policy attached to the entry, a `pam_oath.so` line is prepended
to the auth block (with `default=2`); the account block is unchanged.

`krb5_auth` is deliberately not used: when set, `pam_winbind` calls
`getpwnam()` to obtain the user's UID *before* it contacts `winbindd`. The
musl-based Alpine image has no NSS, so domain users cannot be resolved and
authentication fails with `PAM_USER_UNKNOWN` before the password is checked.
Password authentication itself does not need NSS: `winbindd` validates the
credentials directly.

`pam_winbind`'s account phase is unusable there for the same reason: it starts
with `getpwnam()` (through `valid_user()`) and would only re-check that the
user exists. The AD logon in the auth phase already returns the account-state
results (disabled, expired, locked out, password expired, logon-hours and
workstation restrictions). The account block therefore first verifies that the
`winbind` block authenticated (`session_manager.sh check winbind`) and then
accepts it with `pam_permit`; if the check does not match, the control flags
skip `pam_permit` and the final `pam_deny` rejects the login.

## Configuration

### 1. PAM Service Configuration

Create `/etc/pam.d/rdpgw` for the authentication service:

**Local passwd authentication:**
```plaintext
auth required pam_unix.so
account required pam_unix.so
```

**LDAP authentication:**
```plaintext
auth required pam_ldap.so
account required pam_ldap.so
```

**Active Directory (via Winbind):**
```plaintext
auth sufficient pam_winbind.so
account sufficient pam_winbind.so
```

### 2. Gateway Configuration

```yaml
Server:
  Authentication:
    - local
  AuthSocket: /tmp/rdpgw-auth.sock
  BasicAuthTimeout: 5  # seconds
Caps:
  TokenAuth: false
```

### 3. Start Authentication Helper

Run the `rdpgw-auth` helper program:

```bash
# Basic usage
./rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock

# With custom PAM service name
./rdpgw-auth -n custom-service -s /tmp/rdpgw-auth.sock

# Run as systemd service
systemctl start rdpgw-auth
```

### 4. Allow the gateway process to call the socket

`rdpgw-auth` only accepts connections from its own UID by default. If
the rdpgw process runs as a different user, list its UID (or a shared
GID) explicitly:

```bash
# rdpgw runs as UID 1001
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-uid 1001

# rdpgw and rdpgw-auth share group 'rdpgw' (GID 1100)
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-gid 1100
```

The socket itself is created with mode `0660`, so listing a shared GID
on the daemon is the typical privilege-separated deployment.

## Authentication Flow

1. Client connects to gateway with username/password
2. Gateway forwards credentials to `rdpgw-auth` via socket
3. `rdpgw-auth` validates credentials using PAM
4. Gateway generates session tokens on successful authentication
5. Client connects directly using authenticated session

## PAM Module Examples

### LDAP Integration

Install and configure LDAP PAM module:

```bash
# Install LDAP PAM module
sudo apt-get install libpam-ldap

# Configure /etc/pam_ldap.conf
host ldap.example.com
base dc=example,dc=com
binddn cn=readonly,dc=example,dc=com
bindpw secret
```

### Active Directory Integration

Configure Winbind PAM module:

```bash
# Install Winbind
sudo apt-get install winbind libpam-winbind

# Configure /etc/samba/smb.conf
[global]
security = ads
realm = EXAMPLE.COM
workgroup = EXAMPLE
```

### Two-Factor Authentication

Integrate with TOTP/HOTP using pam_oath:

```plaintext
auth required pam_oath.so usersfile=/etc/users.oath
auth required pam_unix.so
account required pam_unix.so
```

## Container Deployment

### Option 1: External Helper

Run `rdpgw-auth` on the host and mount socket:

```yaml
# docker-compose.yml
services:
  rdpgw:
    image: rdpgw
    volumes:
      - /tmp/rdpgw-auth.sock:/tmp/rdpgw-auth.sock
```

### Option 2: Privileged Container

Mount PAM configuration and user databases:

```yaml
services:
  rdpgw:
    image: rdpgw
    privileged: true
    volumes:
      - /etc/passwd:/etc/passwd:ro
      - /etc/shadow:/etc/shadow:ro
      - /etc/pam.d:/etc/pam.d:ro
```

## Systemd Service

Create `/etc/systemd/system/rdpgw-auth.service`:

```ini
[Unit]
Description=RDPGW Authentication Helper
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable rdpgw-auth
sudo systemctl start rdpgw-auth
```

## Compatible Clients

Since `mstsc` doesn't support basic authentication, use these alternatives:

### Windows
- **Remote Desktop Connection Manager** (RDCMan)
- **mRemoteNG**
- **Royal TS/TSX**

### Linux
- **Remmina**
- **FreeRDP** (with basic auth support)
- **KRDC**

### macOS
- **Microsoft Remote Desktop** (from App Store)
- **Royal TSX**

## Security Considerations

- Run `rdpgw-auth` with minimal privileges
- Secure the Unix socket with appropriate permissions
- Use strong PAM configurations (account lockout, password complexity)
- Enable logging for authentication events
- Consider rate limiting for brute force protection
- Use encrypted connections (TLS) for the gateway

## Troubleshooting

### Common Issues

1. **Socket Permission Denied**: Check socket permissions and ownership
2. **PAM Authentication Failed**: Verify PAM configuration and user credentials
3. **Helper Not Running**: Ensure `rdpgw-auth` is running and accessible

### Debug Commands

```bash
# Test PAM configuration
pamtester rdpgw username authenticate

# Check socket
ls -la /tmp/rdpgw-auth.sock

# Verify helper process
ps aux | grep rdpgw-auth

# Test authentication manually
echo "username:password" | nc -U /tmp/rdpgw-auth.sock
```

### Log Analysis

Enable PAM logging in `/etc/rsyslog.conf`:

```plaintext
auth,authpriv.*                 /var/log/auth.log
```

Monitor authentication attempts:

```bash
tail -f /var/log/auth.log | grep rdpgw
```
