# Kerberos Authentication

![Kerberos](images/flow-kerberos.svg)

RDPGW supports Kerberos authentication via SPNEGO for seamless integration with Active Directory and other Kerberos environments, including built-in KDC Proxy support (`/KdcProxy`) and stacked NTLM fallback.

## Important Notes

**⚠️ DNS Requirements**: Kerberos is heavily reliant on DNS (forward and reverse). Ensure your DNS is properly configured.

**⚠️ Error Messages**: Kerberos errors are not always descriptive. This documentation provides configuration guidance, but detailed Kerberos troubleshooting is beyond scope.

**⚠️ KDC Proxy Transport**: RDPGW's built-in KDC Proxy (`/KdcProxy`) prioritizes **TCP KDCs** over UDP. This prevents Active Directory `KRB5KRB_ERR_RESPONSE_TOO_BIG` errors that occur when tickets containing large PACs exceed the UDP 1,465-byte limit.

## Prerequisites

- Valid Kerberos environment (KDC/Active Directory)
- Proper DNS configuration (forward and reverse lookups)
- A service principal for the gateway. This is mandatory for Kerberos: the gateway's keytab must contain an SPN matching the DNS name clients use.
- Keytab file with appropriate permissions (ensure binary transfer without UTF-8 string mangling)

## Modern configuration (`rdpgw-auth`)

### 1. Configure `rdpgw-auth`

```yaml
# /etc/rdpgw-auth.yaml
Winbind:
  Domain: "corp.example.com"           # FQDN; becomes the upper-case realm
  DomainControllers:                   # optional; DNS SRV discovery otherwise
    - "dc1.corp.example.com"           # bare host: Port defaults 88 / 749
    - Host: "dc2.corp.example.com"
      Port: 88
      AdminPort: 749

AuthProtocols:
  Kerberos:
    Share: true                        # keep the machine keytab synchronized
    KeytabPath: "/var/lib/samba/rdpgw.keytab"
    Spns:
      - "HTTP/rdpgw.corp.example.com"
```

Keys are decoded case-insensitively, but the examples use the canonical field
names.

### 2. Generated `krb5.conf`

When `rdpgw-auth` has winbind capability it **provisions** `/etc/krb5.conf`
from `Winbind.Domain` and `Winbind.DomainControllers`. Missing relations are
merged in and existing operator values are never overwritten, so the auth
container does not need the file mounted. Mounted custom files keep winning.

With the configuration above, the generated file is:

```ini
[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.corp.example.com:88
        admin_server = dc1.corp.example.com:749
        kdc = dc2.corp.example.com:88
        admin_server = dc2.corp.example.com:749
    }

[domain_realm]
    .corp.example.com = CORP.EXAMPLE.COM
    corp.example.com = CORP.EXAMPLE.COM
```

> 💡 **Multiple KDCs / Domain Controllers**: list them under
> `Winbind.DomainControllers` as plain hosts or `{Host, Port, AdminPort}`
> objects. Repeated `kdc` and `admin_server` entries are generated for
> redundancy. Existing operator values are never replaced; differing values
> are reported as drift (strict by default, `--relaxed` warns).

### 3. Gateway configuration

Configure RDPGW in `rdpgw.yaml`:

```yaml
Server:
  Authentication:
    - kerberos
Kerberos:
  Keytab: /etc/keytabs/rdpgw.keytab
  Krb5conf: /etc/krb5.conf
Caps:
  TokenAuth: false
```

#### Stacked authentication (Kerberos + NTLM fallback)

RDPGW supports stacking Kerberos and NTLM authentication simultaneously.
Non-domain-joined clients seamlessly fall back to NTLM via Samba winbind
(`/tmp/rdpgw-auth.sock`), while domain-joined clients use SPNEGO/Kerberos via
KDC Proxy.

```yaml
Server:
  Authentication:
    - kerberos
    - ntlm
  AuthSocket: /tmp/rdpgw-auth.sock
Kerberos:
  Keytab: /etc/kerberos/rdpgw.keytab
  Krb5conf: /etc/kerberos/krb5.conf
```

### 4. Keytab sharing & SPN management

When the auth side shares the Samba machine keytab
(`AuthProtocols.Kerberos.Share: true` in `rdpgw-auth.yaml`), `rdpgw-auth`
generates the matching `smb.conf` directives, keeps the machine keytab
synchronized (`net ads keytab create -P`), registers missing SPNs in Active
Directory when join credentials are available, ensures each SPN shows up in
the keytab, and makes the keytab mode `0644` so the gateway can read it
through the shared volume. The gateway picks up the refreshed keytab
dynamically via its `Kerberos: Keytab` setting above.

The same share also publishes the reconciled `krb5.conf` to
`AuthProtocols.Kerberos.Krb5ConfPath`. It defaults to
`dir(KeytabPath)/krb5.conf` (`/var/lib/samba/krb5.conf` with the default
keytab), so the gateway can read both files from the same volume. Point
`Kerberos.Krb5conf` at that path; the gateway reloads it when it changes,
including when `rdpgw-auth` rewrites it on restart.

```yaml
AuthProtocols:
  Kerberos:
    Share: true
    KeytabPath: /var/lib/samba/rdpgw.keytab
    Krb5ConfPath: /var/lib/samba/krb5.conf
    Spns:
      - HTTP/rdpgw.example.com
      - HTTP/alt-rdpgw.example.com
```

SPNs are collected from, in order:

1. the `AuthProtocols.Kerberos.Spns` list in `rdpgw-auth.yaml`;
2. the legacy `KERBEROS_SPNS` environment variable (comma or space separated),
   still supported for backward compatibility;
3. the gateway FQDN: `rdpgw-auth` reads `RDPGW_CONF` (default
   `/opt/rdpgw/rdpgw.yaml`), extracts `Server.GatewayAddress` and derives
   `HTTP/<host>` (the legacy container behavior, kept as-is).

The legacy `Ntlm.Winbind.Spns` field in `rdpgw-auth.yaml` still works and maps
into `AuthProtocols.Kerberos.Spns` automatically. Missing SPNs that cannot be
registered automatically are logged with the exact manual steps
(`setspn -A <spn> DOMAIN\COMPUTER$` on a Windows DC, or
`net ads setspn add <spn> -U Administrator` inside the container) and the
daemon waits until the SPN appears. See the
[configuration reference](advanced-auth-configuration.md#keytab-sharing-and-spns)
for the full provisioning rules.

### 5. KDC Proxy support

RDPGW includes KDC proxy functionality for environments where clients cannot directly reach the KDC:

- Endpoint: `https://your-gateway/KdcProxy`
- Supports MS-KKDCP protocol
- Automatically configured when Kerberos authentication is enabled
- UDP and TCP KDCs are both tried, with TCP preferred for large ticket responses (PAC overflow protection)
- KDC host entries without an explicit port default to port 88
- Properly handles framed (4-byte length-prefixed) Kerberos messages over both UDP and TCP

## Authentication flow

1. Client connects to gateway with Kerberos ticket
2. Gateway validates ticket using keytab
3. Client connects directly without RDP file download
4. Gateway proxies TGT requests to KDC as needed

## Client configuration

### Windows clients

Configure Windows clients to use the gateway's FQDN and ensure:
- Client can resolve gateway hostname
- Client time is synchronized with KDC
- Client has valid TGT

### Linux clients

Ensure `krb5.conf` is configured and client has valid ticket:

```bash
kinit username@YOUR.REALM
klist  # Verify ticket
```

## Security considerations

- Protect keytab files with appropriate permissions (600)
- Regularly rotate service account passwords
- Monitor for unusual authentication patterns
- Ensure encrypted communication (aes256-cts-hmac-sha1-96)
- Use specific service accounts, not user accounts

## Troubleshooting

### Common issues

1. **Clock skew**: Ensure all systems have synchronized time
2. **DNS issues**: Verify forward/reverse DNS resolution
3. **Principal names**: Ensure the service principal matches the gateway FQDN
4. **Keytab permissions**: Verify keytab file permissions and ownership
5. **Domain join**: `net ads testjoin` must succeed; a winbind-capable
   `rdpgw-auth` exits with a remediation playbook when the join budget
   (`Winbind.JoinTimeout`) expires without a join.
6. **Missing SPN**: the daemon logs the `setspn`/`net ads setspn add` command
   and waits until the SPN appears in the keytab (`klist -k <keytab>`).
7. **File drift at startup**: a value in an operator-mounted `smb.conf` or
   `krb5.conf` differs from the generated configuration. The error names every
   conflict and the staged reference under `/tmp/rdpgw/`; fix the file (or the
   rdpgw-auth configuration), or run with `--relaxed` on a systemd host.

### Debug commands

```bash
# Test keytab
kinit -k -t /etc/keytabs/rdpgw.keytab HTTP/rdpgw.example.com@YOUR.REALM

# Inspect the keytab
klist -k /etc/keytabs/rdpgw.keytab

# Verify DNS
nslookup rdpgw.example.com
nslookup <gateway-ip>

# Check time sync
ntpdate -q ntp.your.realm

# Domain trust and KDC reachability
net ads testjoin
wbinfo -t
```

### Log analysis

Enable verbose logging in RDPGW and check for:
- Keytab loading errors
- Principal validation failures
- KDC communication issues

## Advanced: manual keytab and classic setup

This is the classic path, and it keeps working exactly like before. The
commands below are the manual equivalents of what a winbind-capable
`rdpgw-auth` automates (provisioned files, domain join, SPN registration,
keytab refresh and permissions). Use it for standalone service accounts,
MIT Kerberos, or hosts where you manage the keytab and `krb5.conf` yourself.

### 1. Manual `krb5.conf`

Ensure `/etc/krb5.conf` is properly configured on the gateway:

```ini
[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.corp.example.com:88
        kdc = dc2.corp.example.com:88
        admin_server = dc1.corp.example.com:749
        admin_server = dc2.corp.example.com:749
    }

[domain_realm]
    .corp.example.com = CORP.EXAMPLE.COM
    corp.example.com = CORP.EXAMPLE.COM
```

### 2. Register the service principal (required)

Every Kerberos deployment needs an SPN matching the gateway's DNS name. The
choice below is where the principal lives, not whether to register it:
an AD-joined Samba host can register it on the machine account, while a
standalone service account or MIT KDC registers it in the realm.

#### Active Directory joined host (Samba `net ads`)

When using `rdpgw-auth` with the winbind backend or a domain-joined Linux
gateway, joining the domain creates the computer object and principal in
Active Directory.

```bash
# Join domain (the modern daemon can do this when Winbind.AutoJoin is true)
net ads join -U Administrator

# Register the gateway SPN on the domain computer object
net ads setspn add HTTP/rdpgw.corp.example.com -U Administrator

# Populate the shared keytab with the registered SPNs
net ads keytab create -P
```

`net ads setspn add` registers the SPN directly on the domain computer object
in Active Directory on the Domain Controller (DC), not just locally in the
keytab.

#### Standalone service account or MIT Kerberos (`setspn` / `kadmin`)

For standalone service accounts or MIT Kerberos KDCs, register the principal
in the realm:

```bash
# Active Directory (registers SPN on service-account in DC)
setspn -A HTTP/rdpgw.corp.example.com@CORP.EXAMPLE.COM service-account

# MIT Kerberos KDC
kadmin.local -q "addprinc -randkey HTTP/rdpgw.corp.example.com@CORP.EXAMPLE.COM"
```

### 3. Generate the keytab

Once the principal is registered in the realm or domain controller, generate a keytab file:

#### Linux / Samba (`net ads keytab`)

```bash
# Automatically create or update the keytab file and extract registered SPNs from AD
net ads keytab create -P
```

#### Standalone MIT Kerberos (`ktutil`)

```bash
ktutil
addent -password -p HTTP/rdpgw.corp.example.com@CORP.EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
wkt rdpgw.keytab
quit
```

#### Windows (`ktpass`)

When working in a Windows management environment, use the built-in `ktpass` tool:

```cmd
ktpass /princ HTTP/rdpgw.corp.example.com@CORP.EXAMPLE.COM /pass YourStrongPassword /mapuser YOUR\ServiceAccount /crypto All /ptype KRB5_NT_PRINCIPAL /out C:\path\to\rdpgw.keytab
```

**⚠️ Important considerations:**

- **AES encryption (`/crypto All`)**: Ensure modern encryption algorithms (AES128 / AES256) are enabled.
- **Binary transfer (PowerShell)**: When transferring keytab files from a Windows management station to a Linux gateway or Kubernetes Secret via PowerShell, always read them as raw byte arrays (`[System.IO.File]::ReadAllBytes()`) rather than text strings to prevent UTF-8/Windows-1252 corruption.

### 4. Keytab permissions & secure storage

Regardless of how the keytab is generated, place the resulting keytab file in a secure location readable only by the gateway user (`rdpgw`):

```bash
sudo mv rdpgw.keytab /etc/keytabs/
sudo chown rdpgw:rdpgw /etc/keytabs/rdpgw.keytab
sudo chmod 600 /etc/keytabs/rdpgw.keytab
```

A shared keytab read by the auth container is made mode `0644` by
`rdpgw-auth` so the gateway can read it through a shared volume; a keytab
that only the gateway reads should stay `0600`.

### 5. Start winbind and verify

```bash
sudo systemctl enable --now winbind

# Trust secret between this host and the domain is valid
wbinfo -t
# A domain account can be verified through ntlm_auth
ntlm_auth --username=alice --password='secret'
```

See [Manual domain join and provisioning](advanced-auth-configuration.md#manual-domain-join-and-provisioning)
for the full manual winbind setup, including the `winbindd_priv` group.
