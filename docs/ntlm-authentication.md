# NTLM Authentication

RDPGW supports NTLM authentication for RDP clients whether or not they are
joined to the domain. Credentials can be verified in two ways:

- **Users backend** (default in the modern schema): usernames and passwords are
  listed in the `Users` block of the `rdpgw-auth` configuration. Neither the
  RDP client nor the gateway needs Active Directory.
- **Winbind backend**: the NTLM handshake is delegated to Samba's `ntlm_auth`
  helper, and a Microsoft Active Directory domain controller verifies the
  credentials. The gateway/auth host must be joined to the domain. No
  passwords are stored on the gateway. See
  [Active Directory Authentication via Winbind](#active-directory-authentication-via-winbind).

The RDP client (the machine running `mstsc`, FreeRDP, Remmina, and so on) does
not need to be domain-joined for either backend. With the winbind backend, the
host running `rdpgw-auth` is the part that must be joined. Both backends can be
listed together as ordered, alternative verifiers in `AuthProtocols.Ntlm`.
The legacy `Ntlm.Backend` schema keeps working unchanged; see
[Legacy configuration](#legacy-configuration-ntlm-schema).

## Advantages

- **Easy setup**: simple configuration without external dependencies
- **Windows client support**: works with the default Windows client `mstsc`
- **No external services**: self-contained authentication mechanism
- **Quick deployment**: ideal for small teams or testing environments
- **Active Directory integration**: with the winbind backend, domain accounts,
  password policies, lockouts and group membership are enforced by the domain
  controller

## Security Warning

**⚠️ Plain text passwords:** the `users` backend stores each password in plain
text in `/etc/rdpgw-auth.yaml`, because NTLM verification needs the password
itself. Restrict the file permissions and do not reuse those passwords for
other applications. The `winbind` backend stores no passwords on the gateway.

## Modern configuration (`AuthProtocols`)

### 1. Gateway configuration

Configure RDPGW to use NTLM authentication:

```yaml
Server:
  Authentication:
    - ntlm
Caps:
  TokenAuth: false
```

### 2. Authentication helper configuration

Create the configuration file for `rdpgw-auth` with the `users` backend. The
modern schema puts the protocol frontends under `AuthProtocols`:

```yaml
# /etc/rdpgw-auth.yaml
AuthProtocols:
  Ntlm:
    Enabled: true
    Backends:
      - "users"     # verify against the Users list below

Users:
  - Username: "alice"
    Password: "secure_password_1"
  - Username: "bob"
    Password: "secure_password_2"
```

Keys are decoded case-insensitively, but the examples use the canonical field
names.

### 3. Start the authentication helper

```bash
./rdpgw-auth -c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock
```

The socket is created with mode `0660` and only accepts the daemon's own UID
by default; see [PAM/Local Authentication](pam-authentication.md#4-allow-the-gateway-process-to-call-the-socket)
when `rdpgw` runs as a different user.

## Active Directory Authentication via Winbind

With `AuthProtocols.Ntlm.Backends: [winbind]`, `rdpgw-auth` does not verify
NTLM messages itself. For every handshake it starts Samba's `ntlm_auth` helper
in `--helper-protocol=squid-2.5-ntlmssp` mode and relays the NTLM messages to
it. `ntlm_auth` asks `winbindd`, which forwards the authentication to a domain
controller (NTLM pass-through authentication over Netlogon). The gateway never
learns the user's password or NT hash.

NTLM is a challenge/response protocol, so the password never reaches the
gateway. That is why an LDAP bind cannot be used to verify NTLM logons. The
gateway/auth host must be joined to the domain and run `winbindd`.

### Modern helper configuration

```yaml
# /etc/rdpgw-auth.yaml (modern schema)
Winbind:
  Domain: "example.com"           # FQDN of the domain
  Workgroup: "EXAMPLE"            # derived from the first Domain label when omitted
  Hostname: "rdpgw-auth"          # stable AD computer account name
  RequireMembershipOf: "EXAMPLE\\RDP Users"
  AutoJoin: true                  # join with AD_JOIN_USER/AD_JOIN_PASSWORD when unjoined

AuthProtocols:
  Ntlm:
    Enabled: true
    Backends:
      - "winbind"
```

With the modern schema, `rdpgw-auth` also understands `Winbind.Hostname`
(stable `netbios name` in `smb.conf`), `Winbind.DomainControllers` (feeds the
generated `krb5.conf`), `Winbind.AutoJoin` / `Winbind.JoinTimeout`, and the
generated `smb.conf`. See the
[configuration reference](advanced-auth-configuration.md) for the full list.

If this deployment also serves Kerberos, configure `AuthProtocols.Kerberos`
separately. Keytab and SPN handling is a Kerberos concern, documented in
[Kerberos Authentication](kerberos-authentication.md#4-keytab-sharing--spn-management).

### Provisioning and domain join

The provisioning and domain-join behavior is shared by every winbind-capable
deployment, not just NTLM. In short:

- `rdpgw-auth` provisions `smb.conf`, `krb5.conf` and, when enabled, the PAM
  stack from `Winbind.Domain` and the `AuthProtocols` blocks;
- with `Winbind.AutoJoin: true` and `AD_JOIN_USER`/`AD_JOIN_PASSWORD` it joins
  the domain automatically; with `AutoJoin: false` it waits for a manual
  `net ads join` within `Winbind.JoinTimeout`;
- it then starts and supervises `winbindd` before opening the auth socket.

The full policy, merge rules and remediation playbook are documented in:

- [Configuration provisioning](configuration-provisioning.md)
- [What rdpgw-auth provisions at startup](advanced-auth-configuration.md#what-rdpgw-auth-provisions-at-startup)
- [Domain join and winbindd supervision](advanced-auth-configuration.md#domain-join-and-winbindd-supervision)

### Restricting access to a group

Without `RequireMembershipOf`, every enabled domain account can authenticate to
the gateway. To limit access, create a group such as `RDP Users` in Active
Directory and set `RequireMembershipOf: "EXAMPLE\\RDP Users"` (or the group's
SID). Users outside the group are rejected by `ntlm_auth` with
`NT_STATUS_ACCESS_DENIED`.

### User names

`ntlm_auth` reports authenticated users as `DOMAIN<separator>user`, for example
`EXAMPLE\alice`. This is the name rdpgw uses for host selection and in its logs.
Enable `StripDomain` if your `Server.Hosts` templates or downstream systems
expect the bare account name.

Users enter their domain credentials in the client, for example `EXAMPLE\alice`
or `alice@example.com`. The client itself does not need to be joined to the
domain.

### Limitations

- The gateway/auth host must be joined to the domain and run `winbindd`.
- The distroless container image cannot run this backend because it ships no
  Samba. Use the Alpine based image described in `dev/docker/docker-readme.md`,
  or run `rdpgw-auth` directly on a domain-joined host.
- Only raw NTLMSSP messages are supported. SPNEGO-wrapped `Negotiate` tokens
  (Kerberos) are not handled by this backend; use the
  [Kerberos authentication](kerberos-authentication.md) mode for that.

## Authentication flow

1. Client initiates the NTLM handshake with the gateway
2. Gateway forwards NTLM messages to `rdpgw-auth`
3. Helper validates credentials against the configured `Users` list (`users`
   backend), or relays the handshake to `ntlm_auth`, which asks a domain
   controller (`winbind` backend)
4. Client connects directly on successful authentication

## User management

This section applies to the `users` backend. With the `winbind` backend, users
and passwords are managed in Active Directory.

### Adding users

Edit the configuration file and restart the helper:

```yaml
Users:
  - Username: "newuser"
    Password: "new_secure_password"
  - Username: "existing_user"
    Password: "existing_password"
```

### Password rotation

1. Update passwords in the configuration file
2. Restart the `rdpgw-auth` helper
3. Notify users of the password changes

### User removal

Remove user entries from the configuration and restart the helper.

## Deployment options

### Systemd service

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

If the helper runs as root it can also manage winbindd itself (`AutoJoin`,
keytab/SPN maintenance and supervision); setting
`RDPGW_AUTH_EXTERNAL_WINBIND=1` keeps delegating to the system winbind.

### Docker deployment

#### Using winbind with persistent state and auto-join

The `rdpgw-auth` container (published alongside the legacy `rdpgw-auth-winbind`
alias tag) joins Active Directory on startup, provisions its configuration and
supervises `winbindd` itself; the entrypoint is the daemon, there is no shell
startup script. Domain join credentials are supplied via environment variables:

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

#### Kubernetes deployment

In Kubernetes, deploy `rdpgw-auth` as a sidecar alongside `rdpgw`, sharing the
unix domain socket via an `emptyDir` volume at `/tmp` and preserving Samba
domain membership via a persistent volume (for example a Longhorn PVC):

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

Note the pod hostname is ephemeral; set `Winbind.Hostname` in the
configuration so the AD computer account name stays stable across pod
restarts.

## Client configuration

### Windows (`mstsc`)

NTLM authentication works seamlessly with the default Windows Remote Desktop client:

1. Configure the gateway address in RDP settings
2. Save gateway credentials when prompted
3. Connect using domain credentials or local accounts

### Alternative clients

NTLM is widely supported across RDP clients:

- **mRemoteNG** (Windows)
- **Royal TS/TSX** (Windows/macOS)
- **Remmina** (Linux)
- **FreeRDP** (cross-platform)

## Security best practices

### File permissions

Secure the configuration file:

```bash
sudo chown rdpgw:rdpgw /etc/rdpgw-auth.yaml
sudo chmod 600 /etc/rdpgw-auth.yaml
```

### Password policy

- Use strong, unique passwords for each user
- Implement regular password rotation
- Avoid reusing passwords from other systems
- Consider minimum password length requirements

### Network security

- Deploy the gateway behind TLS termination
- Use private networks when possible
- Implement network-level access controls
- Monitor authentication logs for suspicious activity

### Access control

- Limit user accounts to necessary personnel only
- Regularly audit the user list and remove inactive accounts
- Use the principle of least privilege
- Consider time-based access restrictions

## Migration path

For production environments, consider migrating to more secure authentication methods:

### To OpenID Connect
- Better password security (hashed storage)
- MFA support
- Centralized user management
- SSO integration

### To Kerberos
- No password storage in the gateway
- Enterprise authentication integration
- Stronger cryptographic security
- Seamless Windows domain integration

## Troubleshooting

### Common issues

1. **Authentication failed**: verify username/password in the configuration
2. **Helper not running**: check if the `rdpgw-auth` process is active
3. **Socket errors**: verify socket path and permissions
4. **Domain join fails**: check `net ads testjoin`, `wbinfo -t`, DNS and the
   `Winbind.AutoJoin` / `Winbind.JoinTimeout` settings. With the default
   `AutoJoin: false` the daemon waits for a manual
   `net ads join -U Administrator` and exits after the join budget.
5. **File drift at startup**: a value in an operator-mounted `smb.conf` or
   `krb5.conf` differs from the generated configuration. The error names every
   conflict and the staged reference under `/tmp/rdpgw/`; fix the file (or the
   rdpgw-auth configuration), or run with `--relaxed` on a systemd host.

### Winbind backend

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
| `NT_STATUS_PASSWORD_EXPIRED`, `NT_STATUS_PASSWORD_MUST_CHANGE` | The password must be changed first, for example by logging on to a domain workstation. |
| `NT_STATUS_ACCESS_DENIED` | The user is not a member of `RequireMembershipOf`. |
| `broken helper state` (`BH`) | `winbindd` is not running, the trust is broken (`wbinfo -t` fails), or the helper user cannot access `/var/lib/samba/winbindd_privileged`. |
| `ntlm_auth did not answer within` | The domain controller is unreachable or slow. Check `wbinfo -P` and network access, or raise `Timeout`. |
| `NtlmAuthPath ... is not usable` at startup | `ntlm_auth` is not installed at the configured path. |

### Debug commands

```bash
# Check helper process
ps aux | grep rdpgw-auth

# Verify configuration
cat /etc/rdpgw-auth.yaml

# Test socket connectivity
ls -la /tmp/rdpgw-auth.sock

# Monitor authentication logs
journalctl -u rdpgw-auth -f

# Domain membership and trust
net ads testjoin
wbinfo -t
wbinfo -p
```

### Log analysis

Enable debug logging in `rdpgw-auth` for detailed NTLM protocol analysis:

```bash
./rdpgw-auth -c /etc/rdpgw-auth.yaml -s /tmp/rdpgw-auth.sock -v
```

## Legacy configuration (Ntlm schema)

Legacy configurations without an `AuthProtocols` block keep working. They are
mapped automatically into the modern structure. The legacy schema is the
NTLM-focused block that `rdpgw-auth` used before multi-protocol pipelines:

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

A `Users` list with no `AuthProtocols` block maps to the `users` backend. The
legacy `Ntlm.Backend: file` name is still accepted for that same backend.

Legacy mapping notes (applies only when `AuthProtocols` is missing):
`Ntlm.Backend: winbind` enables both the winbind NTLM backend **and**
`AuthProtocols.Kerberos` (`Share: true` with the default shared keytab), and
`Ntlm.Winbind.Spns` carry over to `AuthProtocols.Kerberos.Spns`, so the
keytab/SPN management runs the same way in both schemas.

The legacy `Ntlm.Winbind.Domain` is the NetBIOS workgroup, not the Kerberos
realm. If `rdpgw-auth` provisions `smb.conf`/`krb5.conf` for this
configuration, add the FQDN as well (or mount complete files yourself):

```yaml
Winbind:
  Domain: corp.example.com
Ntlm:
  Backend: winbind
  # ...
```

| Key | Default | Meaning |
|-----|---------|---------|
| `Ntlm.Backend` | `file` | `file` verifies against the `Users` list, `winbind` delegates to `ntlm_auth`. |
| `Ntlm.Winbind.NtlmAuthPath` | `/usr/bin/ntlm_auth` | Path of the `ntlm_auth` binary. It must exist at startup. |
| `Ntlm.Winbind.Domain` | empty | Passed as `--domain`. In the legacy schema this was the NetBIOS workgroup, not the FQDN; it maps to `Winbind.Workgroup`. The generated `smb.conf`/`krb5.conf` need the DNS/Kerberos realm, so a top-level `Winbind.Domain: corp.example.com` is required when `rdpgw-auth` provisions those files. |
| `Ntlm.Winbind.RequireMembershipOf` | empty | Passed as `--require-membership-of`. A group name (`DOMAIN\Group`) or SID. Only members of that group can log on. |
| `Ntlm.Winbind.Timeout` | `10` | Seconds to wait for each reply from `ntlm_auth`. Must be positive. |
| `Ntlm.Winbind.Spns` | empty | List of Service Principal Names (SPNs) automatically registered in Active Directory and added to the keytab by `rdpgw-auth`. |
| `Ntlm.Winbind.StripDomain` | `false` | When `true`, the user name passed to the gateway is `alice` instead of `EXAMPLE\alice`. |
| `Ntlm.Winbind.Separator` | `\` | The `winbind separator` from `smb.conf`, used by `StripDomain`. |

The same fields exist in the modern schema as `Winbind.*`
(`RequireMembershipOf`, `NtlmAuthPath`, `Timeout`, `StripDomain`, `Separator`)
plus `Domain`, `Workgroup`, `Hostname`, `AutoJoin`, `JoinTimeout` and
`DomainControllers`; SPNs live under `AuthProtocols.Kerberos.Spns`.

The `Users` list is ignored with the winbind backend; `rdpgw-auth` logs a
warning when it is present.

## Advanced: manual operations

The manual host and container procedures are shared by every winbind-capable
deployment, so they are documented once in the general guides:

- [Manual domain join and provisioning](advanced-auth-configuration.md#manual-domain-join-and-provisioning)
  covers `smb.conf`, `net ads join`, keytab access and the `winbindd_priv`
  group.
- [Kerberos: manual keytab and classic setup](kerberos-authentication.md#advanced-manual-keytab-and-classic-setup)
  covers manual `krb5.conf`, SPN registration and keytab generation.
- [rdpgw-auth Docker image](../dev/docker/docker-readme.md) covers the
  container image and the manual container join command.
