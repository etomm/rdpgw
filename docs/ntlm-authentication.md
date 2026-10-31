# NTLM Authentication

RDPGW supports NTLM authentication for simple setup with Windows clients. Credentials can be verified in two ways:

- **File backend** (default): users and passwords are listed in the `rdpgw-auth` configuration file. Useful for small deployments with a limited number of users.
- **Winbind backend**: the NTLM handshake is delegated to Samba's `ntlm_auth` helper, and a Microsoft Active Directory domain controller verifies the credentials. No passwords are stored on the gateway. See [Active Directory Authentication via Winbind](#active-directory-authentication-via-winbind).

Both backends work with clients that are not joined to the domain, and both can be
listed together as ordered, alternative verifiers in the modern
`AuthProtocols.Ntlm` schema (see below). The legacy `Ntlm.Backend` schema keeps
working unchanged.

## Advantages

- **Easy Setup**: Simple configuration without external dependencies
- **Windows Client Support**: Works with default Windows client `mstsc`
- **No External Services**: Self-contained authentication mechanism
- **Quick Deployment**: Ideal for small teams or testing environments
- **Active Directory Integration**: With the winbind backend, domain accounts, password policies, lockouts and group membership are enforced by the domain controller

## Security Warning

**⚠️ Plain Text Storage (file backend)**: With the file backend, passwords are stored in plain text to support the NTLM authentication protocol. Keep configuration files secure and avoid reusing passwords for other applications. The winbind backend does not store any passwords.

## Configuration

### 1. Gateway Configuration

Configure RDPGW to use NTLM authentication:

```yaml
Server:
  Authentication:
    - ntlm
Caps:
  TokenAuth: false
```

### 2. Authentication Helper Configuration

Create configuration file for `rdpgw-auth` with user credentials. The modern
schema puts the protocol frontends under `AuthProtocols`:

```yaml
# /etc/rdpgw-auth.yaml
AuthProtocols:
  Ntlm:
    enabled: true
    backends:
      - "users"     # verify against the Users list below

Users:
  - Username: "alice"
    Password: "secure_password_1"
  - Username: "bob"
    Password: "secure_password_2"
```

The file backend also keeps working without an `AuthProtocols` block (legacy
schema): a `Users` list with no `AuthProtocols` maps to the NTLM `users`
backend.

### 3. Start Authentication Helper

Run the `rdpgw-auth` helper with NTLM configuration:

```bash
./rdpgw-auth -c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock
```

## Active Directory Authentication via Winbind

With `Ntlm.Backend: winbind`, `rdpgw-auth` does not verify NTLM messages itself.
For every handshake it starts Samba's `ntlm_auth` helper in
`--helper-protocol=squid-2.5-ntlmssp` mode and relays the NTLM messages to it.
`ntlm_auth` asks `winbindd`, which forwards the authentication to a domain
controller (NTLM pass-through authentication over Netlogon). The gateway never
learns the user's password or NT hash.

NTLM is a challenge/response protocol, so the password never reaches the gateway.
That is why an LDAP bind cannot be used to verify NTLM logons, and why the
gateway host has to be a member of the domain.

### Prerequisites

1. Install Samba's winbind and client tools, e.g. on Debian/Ubuntu:

   ```bash
   sudo apt install winbind samba-common-bin krb5-user
   ```

2. Configure `/etc/samba/smb.conf` as a domain member. This is the manual
   (host) path and keeps working exactly like before. When `rdpgw-auth` runs
   with a winbind-capable configuration it can also generate/merge this file
   for you at startup; see
   [Automatic provisioning](#automatic-provisioning). A minimal example:

   ```ini
   [global]
       security = ads
       realm = EXAMPLE.COM
       workgroup = EXAMPLE
       winbind use default domain = yes
       idmap config * : backend = tdb
       idmap config * : range = 3000-7999
       idmap config EXAMPLE : backend = rid
       idmap config EXAMPLE : range = 10000-999999
   ```

3. Join the domain and start winbind:

   ```bash
   sudo net ads join -U Administrator
   sudo systemctl enable --now winbind
   ```

4. Verify the setup:

   ```bash
   # Trust secret between this host and the domain is valid
   wbinfo -t
   # A domain account can be verified through ntlm_auth
   ntlm_auth --username=alice --password='secret'
   ```

5. Allow the `rdpgw-auth` user to use winbind's privileged pipe. `ntlm_auth` needs
   access to `/var/lib/samba/winbindd_privileged`, which is owned by a dedicated
   group (`winbindd_priv` on Debian/Ubuntu):

   ```bash
   sudo usermod -aG winbindd_priv rdpgw
   ```

### Helper Configuration

The legacy schema is still accepted verbatim (it applies whenever the file
has no `AuthProtocols` block):

```yaml
# /etc/rdpgw-auth.yaml (legacy schema)
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: /usr/bin/ntlm_auth
    Domain: EXAMPLE
    RequireMembershipOf: "EXAMPLE\\RDP Users"
    Timeout: 10
    StripDomain: false
    Separator: "\\"
    Spns:
      - HTTP/rdpgw.example.com
      - HTTP/alt-rdpgw.example.com
```

The equivalent modern configuration is:

```yaml
# /etc/rdpgw-auth.yaml (modern schema)
Winbind:
  domain: "example.com"           # FQDN of the domain; legacy `Domain: EXAMPLE`
                                  # (the NetBIOS workgroup) maps to workgroup
  workgroup: "EXAMPLE"
  requiremembershipof: "EXAMPLE\\RDP Users"

AuthProtocols:
  Ntlm:
    enabled: true
    backends:
      - "winbind"
  Kerberos:
    share: true                   # keep the shared keytab synchronized
    spns:                         # legacy `Ntlm.Winbind.Spns` maps here
      - HTTP/rdpgw.example.com
      - HTTP/alt-rdpgw.example.com
```

With the modern schema, `rdpgw-auth` also understands `Winbind.hostname`
(stable `netbios name` in `smb.conf`), `Winbind.domaincontrollers` (feeds the
generated `krb5.conf`), `Winbind.autojoin` / `Winbind.jointimeout`, and the
generated `smb.conf`; see the
[configuration reference](advanced-auth-configuration.md) for the full list.

Legacy mapping notes (applies only when `AuthProtocols` is missing):
`Ntlm.Backend: winbind` enables both the winbind NTLM backend **and**
`AuthProtocols.Kerberos` (`share: true` with the default shared keytab), and
`Ntlm.Winbind.Spns` carry over to `AuthProtocols.Kerberos.Spns`, so the
keytab/SPN management below runs the same way in both schemas.

| Key | Default | Meaning |
|-----|---------|---------|
| `Ntlm.Backend` | `file` | `file` verifies against the `Users` list, `winbind` delegates to `ntlm_auth`. |
| `Ntlm.Winbind.NtlmAuthPath` | `/usr/bin/ntlm_auth` | Path of the `ntlm_auth` binary. It must exist at startup. |
| `Ntlm.Winbind.Domain` | empty | Passed as `--domain`. Leave empty to use winbind's own domain. |
| `Ntlm.Winbind.RequireMembershipOf` | empty | Passed as `--require-membership-of`. A group name (`DOMAIN\Group`) or SID. Only members of that group can log on. |
| `Ntlm.Winbind.Timeout` | `10` | Seconds to wait for each reply from `ntlm_auth`. Must be positive. |
| `Ntlm.Winbind.Spns` | empty | List of Service Principal Names (SPNs) automatically registered in Active Directory and added to the keytab by `rdpgw-auth`. |
| `Ntlm.Winbind.StripDomain` | `false` | When `true`, the user name passed to the gateway is `alice` instead of `EXAMPLE\alice`. |
| `Ntlm.Winbind.Separator` | `\` | The `winbind separator` from `smb.conf`, used by `StripDomain`. |

The same fields exist in the modern schema as `Winbind.*`
(`requiremembershipof`, `ntlmauthpath`, `timeout`, `stripdomain`, `separator`)
plus `domain`, `workgroup`, `hostname`, `autojoin`, `jointimeout` and
`domaincontrollers`; SPNs live under `AuthProtocols.Kerberos.Spns`.

The `Users` list is ignored with the winbind backend; `rdpgw-auth` logs a warning
when it is present.

### Restricting Access to a Group

Without `RequireMembershipOf`, every enabled domain account can authenticate to the
gateway. To limit access, create a group such as `RDP Users` in Active Directory and
set `RequireMembershipOf: "EXAMPLE\\RDP Users"` (or the group's SID). Users outside
the group are rejected by `ntlm_auth` with `NT_STATUS_ACCESS_DENIED`.

### User Names

`ntlm_auth` reports authenticated users as `DOMAIN<separator>user`, for example
`EXAMPLE\alice`. This is the name rdpgw uses for host selection and in its logs.
Enable `StripDomain` if your `Server.Hosts` templates or downstream systems expect
the bare account name.

Users enter their domain credentials in the client, e.g. `EXAMPLE\alice` or
`alice@example.com`. The client itself does not need to be joined to the domain.

### Limitations

- The gateway host must be joined to the domain and run `winbindd`.
- The distroless container image cannot run this backend because it ships no Samba.
  Use the Alpine based image described in `dev/docker/docker-readme.md`, or run
  `rdpgw-auth` directly on a domain-joined host.
- Only raw NTLMSSP messages are supported. SPNEGO-wrapped `Negotiate` tokens
  (Kerberos) are not handled by this backend; use the
  [Kerberos authentication](kerberos-authentication.md) mode for that.

## Authentication Flow

1. Client initiates NTLM handshake with gateway
2. Gateway forwards NTLM messages to `rdpgw-auth`
3. Helper validates credentials against the configured user list (file backend), or relays the handshake to `ntlm_auth`, which asks a domain controller (winbind backend)
4. Client connects directly on successful authentication

## User Management

This section applies to the file backend. With the winbind backend, users and
passwords are managed in Active Directory.

### Adding Users

Edit the configuration file and restart the helper:

```yaml
Users:
  - Username: "newuser"
    Password: "new_secure_password"
  - Username: "existing_user"
    Password: "existing_password"
```

### Password Rotation

1. Update passwords in configuration file
2. Restart `rdpgw-auth` helper
3. Notify users of password changes

### User Removal

Remove user entries from configuration and restart helper.

## Deployment Options

### Systemd Service

Create `/etc/systemd/system/rdpgw-auth.service`:

```ini
[Unit]
Description=RDPGW NTLM Authentication Helper
After=network.target

[Service]
Type=simple
User=rdpgw
ExecStart=/usr/local/bin/rdpgw-auth -c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

With the winbind backend on a classic domain-joined host, run a system
`winbindd` service (`systemctl enable --now winbind`) and give the helper
access to winbind's privileged pipe. The daemon is also told to delegate
winbindd to the host and to treat file drift as a loud warning (systemd
services should keep running instead of stopping over an operator-owned
file) with `--relaxed`:

```ini
[Unit]
After=network.target winbind.service
Wants=winbind.service

[Service]
Environment=RDPGW_AUTH_EXTERNAL_WINBIND=1
ExecStart=/usr/local/bin/rdpgw-auth -c /etc/rdpgw-auth.yaml --relaxed
SupplementaryGroups=winbindd_priv
```

If the helper runs as root it can also manage winbindd itself (`autojoin`,
keytab/SPN maintenance and supervision, see below); setting
`RDPGW_AUTH_EXTERNAL_WINBIND=1` keeps delegating to the system winbind.

### Docker Deployment

#### Using Winbind Backend with Persistent State & Auto-Join

The `rdpgw-auth` container (published alongside the legacy `rdpgw-auth-winbind`
alias tag) joins Active Directory on startup, provisions its configuration and
supervises `winbindd` itself; the entrypoint is the daemon now, there is no
shell startup script. Domain join credentials are supplied via environment
variables:

```yaml
# docker-compose.yml
services:
  rdpgw-auth:
    image: ghcr.io/example-org/rdpgw-auth:latest
    # No smb.conf to mount: rdpgw-auth generates /etc/samba/smb.conf and
    # /etc/krb5.conf from the configuration below. Mounting your own is still
    # possible; it must then contain the generated [global] settings (missing
    # ones are merged into a writable mount; conflicting values refuse to start).
    command: ["--conf", "/etc/rdpgw-auth.yaml"]
    environment:
      - AD_JOIN_USER=Administrator
      - AD_JOIN_PASSWORD=your_ad_password
    volumes:
      - ./rdpgw-auth.yaml:/etc/rdpgw-auth.yaml:ro
      - samba-state:/var/lib/samba
      - auth-socket:/tmp
    restart: always

  rdpgw:
    image: ghcr.io/example-org/rdpgw:latest
    volumes:
      - auth-socket:/tmp
    depends_on:
      - rdpgw-auth

volumes:
  auth-socket:
  samba-state:
```

The `--conf` flag is needed because the daemon's default configuration path is
`/opt/rdpgw/rdpgw-auth.yaml` (its working directory); alternatively mount the
file there.

### Kubernetes Deployment

In Kubernetes, deploy `rdpgw-auth` as a sidecar alongside `rdpgw`, sharing the unix domain socket via an `emptyDir` volume at `/tmp` and preserving Samba domain membership via a persistent volume (e.g. Longhorn PVC):

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: rdpgw-samba-state-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: longhorn
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rdpgw
spec:
  template:
    spec:
      containers:
      - name: rdpgw
        image: ghcr.io/example-org/rdpgw:latest
        volumeMounts:
        - name: auth-socket
          mountPath: /tmp
      - name: rdpgw-auth
        image: ghcr.io/example-org/rdpgw-auth:latest
        args:
          - -c
          - /etc/rdpgw-auth.yaml
          - -s
          - /tmp/rdpgw-auth.sock
          - --allow-uid
          - "1001"
        env:
          # Optional: provide credentials to automatically join Active Directory on first boot
          - name: AD_JOIN_USER
            valueFrom:
              secretKeyRef:
                name: ad-join-credentials
                key: username
                optional: true
          - name: AD_JOIN_PASSWORD
            valueFrom:
              secretKeyRef:
                name: ad-join-credentials
                key: password
                optional: true
        volumeMounts:
        - name: config-volume
          mountPath: /etc/rdpgw-auth.yaml
          subPath: rdpgw-auth.yaml
        - name: samba-state
          mountPath: /var/lib/samba
        - name: auth-socket
          mountPath: /tmp
      volumes:
      - name: auth-socket
        emptyDir: {}
      - name: samba-state
        persistentVolumeClaim:
          claimName: rdpgw-samba-state-pvc
```

Note the pod hostname is ephemeral; set `Winbind.hostname` in the
configuration so the AD computer account name stays stable across pod
restarts.

#### Automatic vs. Manual Join Behavior

- **Automatic Join**: With `AD_JOIN_USER` and `AD_JOIN_PASSWORD` defined and
  `Winbind.autojoin: true`, the daemon checks `net ads testjoin` first; a
  joined host is left alone. Otherwise it joins via `net ads join` with
  exponential backoff (2s up to 30s) until the join budget
  (`Winbind.jointimeout`, default 10 minutes) elapses. The trust secret is
  persisted in `/var/lib/samba/private/secrets.tdb`, so restarts re-use the
  existing join.
- **Manual Join**: With `autojoin: false` (the default) the daemon logs the
  manual instructions and waits instead of crash-looping:
  ```text
  Domain join: join domain "example.com" by executing inside this container:
      net ads join -U Administrator
  or provide AD_JOIN_USER and AD_JOIN_PASSWORD (with autoJoin: true) so the daemon can do it
  Domain join: waiting up to 10m0s for the join before giving up
  ```
  You can exec into the container and run `net ads join -U Administrator`
  manually. As soon as the join is detected, `rdpgw-auth` continues: keytab
  refresh, SPN registration/verification, `winbindd` supervision and the
  gRPC server follow. If the budget expires without a join, the daemon exits
  with a remediation playbook.
- **Persistent Trust**: Because `/var/lib/samba` is mounted on a persistent volume, domain join is a one-time operation. Pod restarts will automatically detect the existing join state (`net ads testjoin`) and start immediately without re-joining.

#### Automatic provisioning

A winbind-capable `rdpgw-auth` generates or merges its own system files
before the join:

- `/etc/krb5.conf` from `Winbind.domain` and `Winbind.domaincontrollers`;
- `/etc/samba/smb.conf` with the domain member `[global]` settings, including
  the shared-keytab directives when `AuthProtocols.Kerberos.share: true`;
- `/etc/pam.d/rdpgw` when `AuthProtocols.Basic` is enabled.

Operator-provided files keep winning: missing generated settings are
appended (into `[global]` for smb.conf; for krb5.conf single relations go
inside their section and a missing realm block is appended whole, exactly as
generated) and existing values are never overwritten. A value
that differs from the generated one stops the daemon with an error naming
every conflict — containers fail fast at deploy time; on a systemd host pass
`--relaxed` to turn the same drift into a loud warning and keep running.
Mounting your own `smb.conf` is therefore still possible — it just has to
match the configuration unless you run `--relaxed`. See
[docs/advanced-auth-configuration.md](advanced-auth-configuration.md).

## Client Configuration

### Windows (mstsc)

NTLM authentication works seamlessly with the default Windows Remote Desktop client:

1. Configure gateway address in RDP settings
2. Save gateway credentials when prompted
3. Connect using domain credentials or local accounts

### Alternative Clients

NTLM is widely supported across RDP clients:

- **mRemoteNG** (Windows)
- **Royal TS/TSX** (Windows/macOS)
- **Remmina** (Linux)
- **FreeRDP** (Cross-platform)

## Security Best Practices

### File Permissions

Secure the configuration file:

```bash
sudo chown rdpgw:rdpgw /etc/rdpgw-auth.yaml
sudo chmod 600 /etc/rdpgw-auth.yaml
```

### Password Policy

- Use strong, unique passwords for each user
- Implement regular password rotation
- Avoid reusing passwords from other systems
- Consider minimum password length requirements

### Network Security

- Deploy gateway behind TLS termination
- Use private networks when possible
- Implement network-level access controls
- Monitor authentication logs for suspicious activity

### Access Control

- Limit user accounts to necessary personnel only
- Regularly audit user list and remove inactive accounts
- Use principle of least privilege
- Consider time-based access restrictions

## Migration Path

For production environments, consider migrating to more secure authentication methods:

### To OpenID Connect
- Better password security (hashed storage)
- MFA support
- Centralized user management
- SSO integration

### To Kerberos
- No password storage in gateway
- Enterprise authentication integration
- Stronger cryptographic security
- Seamless Windows domain integration

## Troubleshooting

### Common Issues

1. **Authentication Failed**: Verify username/password in configuration
2. **Helper Not Running**: Check if `rdpgw-auth` process is active
3. **Socket Errors**: Verify socket path and permissions

### Winbind Backend

With the winbind backend, rejected logons are logged as
`winbind: authentication rejected: <status>`, and helper failures as
`winbind: ntlm_auth reported a broken helper state: <reason>`. Output that
`ntlm_auth` writes to stderr is logged with the prefix `ntlm_auth: `.

| Log message | Likely cause |
|-------------|--------------|
| `NT_STATUS_WRONG_PASSWORD` | Wrong password. |
| `NT_STATUS_NO_SUCH_USER` | Unknown account, or wrong domain in the user name. |
| `NT_STATUS_ACCOUNT_DISABLED` | The account is disabled in Active Directory. |
| `NT_STATUS_ACCOUNT_LOCKED_OUT` | The account is locked out by the domain's lockout policy. |
| `NT_STATUS_PASSWORD_EXPIRED`, `NT_STATUS_PASSWORD_MUST_CHANGE` | The password must be changed first, e.g. by logging on to a domain workstation. |
| `NT_STATUS_ACCESS_DENIED` | The user is not a member of `RequireMembershipOf`. |
| `broken helper state` (`BH`) | `winbindd` is not running, the trust is broken (`wbinfo -t` fails), or the helper user cannot access `/var/lib/samba/winbindd_privileged`. |
| `ntlm_auth did not answer within` | The domain controller is unreachable or slow. Check `wbinfo -P` and network access, or raise `Timeout`. |
| `NtlmAuthPath ... is not usable` at startup | `ntlm_auth` is not installed at the configured path. |

### Debug Commands

```bash
# Check helper process
ps aux | grep rdpgw-auth

# Verify configuration
cat /etc/rdpgw-auth.yaml

# Test socket connectivity
ls -la /tmp/rdpgw-auth.sock

# Monitor authentication logs
journalctl -u rdpgw-auth -f
```

### Log Analysis

Enable debug logging in `rdpgw-auth` for detailed NTLM protocol analysis:

```bash
./rdpgw-auth -c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock -v
```

## Future Enhancements

Planned improvements for NTLM authentication:

- **Database Backend**: Support for SQLite/PostgreSQL user storage
- **Password Hashing**: Secure password storage options
- **Audit Logging**: Enhanced security monitoring
