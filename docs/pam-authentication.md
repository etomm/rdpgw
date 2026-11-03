# PAM/Local Authentication

![PAM](images/flow-pam.svg)

RDPGW supports PAM (Pluggable Authentication Modules) for authentication against local accounts, LDAP, Active Directory, and other PAM-supported systems.

## Important Notes

**⚠️ Client limitation:** the Windows `mstsc` client does not send Basic credentials to an RD Gateway. The official Microsoft Android/iOS clients do support Basic and, in practice, need it enabled for the gateway to show a credential prompt. Use those clients, or OpenID Connect, Kerberos, or NTLM.

**⚠️ Container considerations:** checking `/etc/passwd` / `/etc/shadow` inside an ephemeral container is usually pointless unless the image owns those accounts. LDAP, AD via winbind, or the YAML `users` backend are the sensible container choices. The `unix` backend is mainly for non-container hosts or images with deliberately managed local users.

## Architecture

PAM authentication uses a privilege separation model with the `rdpgw-auth` helper program:

- `rdpgw` - the main gateway, running unprivileged.
- `rdpgw-auth` - the supervisor/entrypoint. It starts as root when it must manage `winbindd`, system files, and the socket, then re-executes the gRPC server as an unprivileged user (`--serve-user`). PAM transactions therefore run as that serving user, not as root.
- Communication via Unix socket, gated by peer UID/GID.

## Modern generated PAM stack

Enable `AuthProtocols.Basic` in `rdpgw-auth.yaml` and `rdpgw-auth` generates
`/etc/pam.d/<service>` at every startup from an ordered `stack` of backends -
`winbind`, `ldap`, `unix`, `users` - each optionally chained with an OATH
(TOTP/HOTP) policy:

```yaml
AuthProtocols:
  Basic:
    enabled: true
    stack:
      - backend: winbind          # AD accounts via pam_winbind
        oath: default-totp        # optional 2FA for this entry
      - backend: ldap
        name: corp-ldap           # references the Ldap profile below
      - unix                      # local system users (/etc/shadow)
      - users                     # local YAML static users
```

Companion files are generated only for backends that are actually used:

- `/tmp/rdpgw/users.pwd`: `pam_pwdfile` database of the YAML `Users` list
  (SHA-512 crypt, random salt per start, mode `0600`) - **only when the stack
  contains a `users` entry**;
- per-profile LDAP client files for the `Ldap` profiles referenced by the
  stack (they contain the bind password, mode `0600`);
- `/opt/rdpgw/session_manager.sh`: a `pam_exec` helper (mode `0755`) that
  records which backend won the `auth` phase and steers the `account` phase
  to the same backend. The daemon injects a fresh per-attempt
  `RDPGW_SESSION_ID` into the PAM environment, so concurrent logins for the
  same user do not interfere and a missing id fails closed.

When the daemon starts as root with `--serve-user`, `users.pwd` and the LDAP
client files become `0640`, owned by `root:<serving group>`, and their
directory becomes `0750`; the serving user can read them but other users
cannot. `session_manager.sh` is installed as `0755` so the serving user can
execute it.

The generated file carries an explicit "generated" header. A writable
`/etc/pam.d/<service>` is overwritten on the next start; a read-only file that
differs is kept with a warning (and Basic authentication may fail until it is
reconciled). With the generated stack you do not manage `/etc/pam_ldap.conf`,
winbind's smb.conf account phase, or the users file yourself. See the
[configuration reference](advanced-auth-configuration.md#authprotocols) for
the exact schema.

### Why the account phase is branched explicitly

PAM has no built-in notion of “the backend that verified the password”. With
stacked modules and `sufficient`/`required` control flags, the `account`
phase is a separate evaluation and does not automatically follow the `auth`
winner. Orchestrating that deterministically with pure PAM skip counts is
fragile: reordering the stack changes every count, and overlapping accounts
(the same user in winbind and in the YAML list, for example) can otherwise
have one backend's account checks applied to a credential verified by
another.

The generated stack makes the branch explicit:

1. the successful `auth` module records the backend under the per-attempt
   `RDPGW_SESSION_ID`;
2. the `account` phase runs only the recorded backend's account module;
3. no recorded match fails closed.

Order still decides which backend wins when accounts overlap - that is an
operational choice - but the account phase cannot inherit checks from an
unrelated backend.

On musl-based (Alpine) images there is no NSS, so a `getpwnam`-style local
lookup fails for domain users and the PAM `account` phase cannot be resolved
reliably. That is the second reason for the explicit `session_manager.sh`
branch. Details in `docs/plans/auth-migration-plan.md`.

### The winbind block

The winbind entry needs special handling because both `krb5_auth` and
`pam_winbind`'s account phase call `getpwnam()`, while password authentication
itself does not need NSS:

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
`getpwnam()` to obtain the user's UID *before* it contacts `winbindd`. Without
NSS - or, on glibc, without a `winbind` entry in `/etc/nsswitch.conf` - domain
users cannot be resolved, so authentication fails with `PAM_USER_UNKNOWN`
before the password is checked. Password authentication itself does not need
NSS: `winbindd` validates the credentials directly.

`pam_winbind`'s account phase has the same problem: it starts with `getpwnam()`
(through `valid_user()`) before it can verify the winbind account. The AD logon
in the auth phase already returns the account-state results (disabled, expired,
locked out, password expired, logon-hours and workstation restrictions). The
account block therefore first verifies that the `winbind` block authenticated
(`session_manager.sh check winbind`) and then accepts it with `pam_permit`; if
the check does not match, the control flags skip `pam_permit` and the final
`pam_deny` rejects the login.

The `users` backend follows the same pattern: `pam_pwdfile` verifies the
password and its account module is `pam_permit`, because the YAML list has no
account state to check.

## Configuration

### 1. Gateway configuration

```yaml
Server:
  Authentication:
    - local
  AuthSocket: /tmp/rdpgw-auth.sock
  BasicAuthTimeout: 5  # seconds
Caps:
  TokenAuth: false
```

### 2. Start the authentication helper

```bash
# Default PAM service: /etc/pam.d/rdpgw
./rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock

# Custom PAM service: generates /etc/pam.d/custom-service and uses the same
# name for the PAM transaction.
./rdpgw-auth -n custom-service -s /tmp/rdpgw-auth.sock

# Run as systemd service
systemctl start rdpgw-auth
```

`-n` is not just a runtime label: the generated PAM file is
`/etc/pam.d/<name>`, matching the service name passed to PAM.

### 3. Generated companion files

No manual action is needed: enabling `AuthProtocols.Basic` is enough. The
daemon writes `session_manager.sh`, the PAM stack, and only the companion
files for backends in the stack (`users.pwd` for `users`, LDAP profiles for
referenced `Ldap` entries) before it opens the gRPC socket.

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

## Authentication flow

1. Client connects to gateway with username/password
2. Gateway forwards credentials to `rdpgw-auth` via socket
3. `rdpgw-auth` validates credentials using PAM
4. Gateway generates session tokens on successful authentication
5. Client connects directly using authenticated session

## Container deployment

### External helper

Run `rdpgw-auth` on the host and mount socket:

```yaml
# docker-compose.yml
services:
  rdpgw:
    image: rdpgw
    volumes:
      - /tmp/rdpgw-auth.sock:/tmp/rdpgw-auth.sock
```

## Systemd service

Create `/etc/systemd/system/rdpgw-auth.service`:

```ini
[Unit]
Description=RDPGW Authentication Helper
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock --allow-uid 1001
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

`--relaxed` has nothing to do with PAM stack generation. It only changes how
the daemon treats drift in `smb.conf`/`krb5.conf` when the deployment has
**winbind capability** - which includes a generated PAM stack with a `winbind`
entry. If you mount your own `smb.conf`/`krb5.conf` and they differ from the
values the configuration produces, strict mode stops the daemon at startup;
`--relaxed` logs the drift and keeps running. Stacks using only
`unix`/`users`/`ldap` do not provision those files and do not need the flag.

## Compatible clients

Since `mstsc` does not send Basic credentials, use these alternatives:

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

### Mobile
- **Microsoft Remote Desktop** for Android/iOS (Basic authentication is the
  flow these clients use for the gateway)

## Security considerations

- Run `rdpgw-auth` with minimal privileges; the serving process should be
  the unprivileged `--serve-user`, not root.
- Secure the Unix socket with appropriate permissions.
- Use strong PAM configurations (account lockout, password complexity) where
  the backend is responsible for them; the winbind backend delegates those
  checks to AD.
- Enable logging for authentication events.
- Consider rate limiting for brute force protection.
- Use encrypted connections (TLS) for the gateway.

## Troubleshooting

### Common issues

1. **Socket permission denied**: check socket permissions and ownership.
   The socket is mode `0660`; the gateway UID/GID must be listed with
   `--allow-uid`/`--allow-gid`.
2. **PAM authentication failed**: verify the service file and credentials.
   The generated file is `/etc/pam.d/<name>` where `<name>` is the `-n`
   value. Compare it with the expected backend order and check that
   `/opt/rdpgw/session_manager.sh` exists. `/tmp/rdpgw/users.pwd` only exists
   when the stack contains a `users` backend.
3. **Helper not running**: ensure `rdpgw-auth` is running and accessible.
4. **`AuthProtocols.Basic.Stack[...]` validation error**: an unknown backend or
   missing `Ldap`/`Oath` profile; profile names are case-insensitive but must
   be declared.
5. **Generated stack not applied**: the PAM file is read-only and differs;
   the daemon warns and keeps the operator file. Make it writable or
   reconcile it.
6. **Account phase fails for domain users**: the backend that won `auth` did
   not record a session id. `rdpgw-auth` injects `RDPGW_SESSION_ID` into every
   PAM transaction; check that `/opt/rdpgw/session_manager.sh` is executable
   and visible to the serving user. A missing id or a failed `create` line
   fails authentication closed before the account phase.
7. **`users` backend always denies**: `/tmp/rdpgw/users.pwd` must be readable
   by the gRPC user and contain `$6$` hashes; the file is regenerated on every
   start from the `Users` list.

### Debug commands

`pamtester` is a small debugging tool, not part of the `rdpgw-auth` image.
Install it where you run the check:

```bash
# Debian/Ubuntu host or container
sudo apt-get install pamtester

# Alpine container (community repository)
apk add pamtester
```

Then, for the PAM service name configured with `-n`:

```bash
pamtester rdpgw username authenticate
pamtester custom-service username authenticate
```

Other checks:

```bash
# Check socket
ls -la /tmp/rdpgw-auth.sock

# Verify helper process
ps aux | grep rdpgw-auth

# Inspect the generated stack and companion files
cat /etc/pam.d/rdpgw
ls -l /tmp/rdpgw/users.pwd /opt/rdpgw/session_manager.sh
```

The socket speaks gRPC, not a line-based text protocol. Use `grpcurl` or the
gateway itself; `echo user:pass | nc -U ...` does not work.

### Log analysis

The `auth,authpriv.* /var/log/auth.log` rsyslog rule is valid on a classic
systemd host with rsyslog installed. Containers usually log to stdout, so use
`docker logs` / `kubectl logs` instead:

```bash
# systemd + rsyslog host
tail -f /var/log/auth.log | grep rdpgw

# container
docker logs -f <container>
kubectl logs -f deployment/rdpgw-auth
```

## Advanced: custom hand-written PAM stack

The classic setup remains fully supported. Leave `AuthProtocols.Basic`
disabled in `rdpgw-auth.yaml`; without an enabled Basic protocol `rdpgw-auth`
never touches `/etc/pam.d/<service>`, and PAM modules are configured the
standard way (`pam_ldap.conf`, `smb.conf`, `/etc/shadow`, ...). This is the
right choice for non-container hosts and for setups with unusual PAM
requirements that the generated stack cannot express.

### 1. PAM service configuration

Create `/etc/pam.d/rdpgw` (or the name passed with `-n`) for the
authentication service:

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

Modules can be stacked the same standard way (e.g. `pam_winbind` with
`sufficient` followed by a local fallback).

### 2. Manual companion files

The modern daemon generates these; in this custom setup create and maintain
them yourself:

```bash
# Static YAML users for pam_pwdfile: username:SHA-512 crypt hash, mode 0600
sudo install -m 0600 /dev/null /tmp/rdpgw/users.pwd
openssl passwd -6 's3cret'        # produces a $6$... hash
printf 'alice:%s\n' '<hash>' | sudo tee /tmp/rdpgw/users.pwd

# LDAP client configuration (contains the bind password: mode 0600)
sudo install -m 0600 /dev/null /tmp/rdpgw/ldap-corp.conf
sudo tee /tmp/rdpgw/ldap-corp.conf >/dev/null <<'EOF'
host ldap.example.com
port 636
base dc=example,dc=com
binddn cn=readonly,dc=example,dc=com
bindpw secret
ssl on
EOF

# The stateful session helper is only needed for the generated stack;
# a classic stack does not reference /opt/rdpgw/session_manager.sh.
```

### 3. Gateway configuration (custom stack)

```yaml
Server:
  Authentication:
    - local
  AuthSocket: /tmp/rdpgw-auth.sock
  BasicAuthTimeout: 5  # seconds
Caps:
  TokenAuth: false
```

### 4. Start the helper and allow the socket (custom stack)

```bash
./rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-uid 1001
```

### Custom PAM module examples

#### LDAP integration

```bash
# Install LDAP PAM module
sudo apt-get install libpam-ldap

# Configure /etc/pam_ldap.conf
host ldap.example.com
base dc=example,dc=com
binddn cn=readonly,dc=example,dc=com
bindpw secret
```

#### Active Directory integration

```bash
# Install Winbind
sudo apt-get install winbind libpam-winbind

# Configure /etc/samba/smb.conf
[global]
security = ads
realm = EXAMPLE.COM
workgroup = EXAMPLE
```

In the generated stack, a `winbind` entry makes the deployment
winbind-capable: `rdpgw-auth` then also provisions/reconciles
`/etc/samba/smb.conf` and `/etc/krb5.conf`. A hand-written `smb.conf` that
differs from the generated values is drift: strict mode refuses to start,
`--relaxed` logs the drift and keeps running. Use `--relaxed` on host-managed
deployments where the operator owns those files, or make the file match the
configuration.

A purely hand-written stack (`AuthProtocols.Basic` disabled) is not inspected
by `rdpgw-auth`: you own `smb.conf`, `krb5.conf`, and the winbind NSS
integration yourself. The `account sufficient pam_winbind.so` example above
relies on that NSS integration; on musl-based images use the generated stack.

#### Two-factor authentication

```plaintext
auth required pam_oath.so usersfile=/etc/users.oath
auth required pam_unix.so
account required pam_unix.so
```

### Privileged container for local accounts

This belongs to the custom/hand-written setup, not the generated stack. It is
only meaningful when the container is intended to authenticate the host's
local accounts:

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

For LDAP/AD, mount the generated configuration or use the `rdpgw-auth` image
instead of sharing the host's local account databases.
