# Changelog

All user-visible changes to rdpgw will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The auth container entrypoint is now the `rdpgw-auth` daemon itself:
  `dev/docker/run-auth-winbind.sh` and the `yq-go`/`su-exec` dependencies
  are gone. Provisioning (`smb.conf`/`krb5.conf`), the domain join, keytab
  and SPN maintenance, PAM stack generation and `winbindd` supervision all
  happen inside the binary. Container flags are unchanged. See
  [UPGRADING.md](UPGRADING.md).
- The auth image is published as `rdpgw-auth:`; the legacy tag
  `rdpgw-auth-winbind:` is still published as an alias of the same build.
- `rdpgw-auth` has one unified configuration schema: `AuthProtocols`
  (`Kerberos` keytab share + `spns`, `Ntlm` ordered backends, `Basic`
  generated PAM stack) plus modern `Winbind`, `Ldap`, `Oath` and `Users`
  blocks. Configurations without `AuthProtocols` (the legacy `Ntlm:`-based
  schema) keep working and are mapped automatically — `Ntlm.Backend: winbind`
  now also enables the Kerberos keytab share, and `Ntlm.Winbind.Spns` carry
  over to `AuthProtocols.Kerberos.Spns`.
- When the configuration has winbind capability, `rdpgw-auth` provisions
  `/etc/samba/smb.conf` (append-only merge; operator values are never
  overwritten) and `/etc/krb5.conf`. Conflicting operator values, or required
  settings that cannot be added to a read-only mount, stop the daemon with a
  fatal error naming every offending setting; semantically identical
  read-only files are accepted.
- `AuthProtocols.Basic.Enabled` makes `rdpgw-auth` generate
  `/etc/pam.d/rdpgw` on every start (winbind/ldap/unix/users backends,
  optional OATH 2FA per entry, session-tracked account phase) together with
  `/tmp/rdpgw/users.pwd` (SHA-512 crypt), per-profile LDAP client files and
  `/opt/rdpgw/session_manager.sh`. Without an enabled Basic protocol the
  daemon never touches the PAM service file, so hand-written PAM
  configurations keep working unchanged.
- Domain join timing is now governed by `Winbind.autojoin` /
  `Winbind.jointimeout` instead of the presence of `AD_JOIN_USER`/
  `AD_JOIN_PASSWORD`. The default is `autojoin: false`: log the manual
  instructions and wait up to 10 minutes, then exit with a remediation
  playbook instead of waiting forever.
- Multiple NTLM backends (`AuthProtocols.Ntlm.Backends`) are tried in the
  configured order per handshake; credential-verification failures are never
  retried on another backend once a challenge was issued, and a missing or
  disabled chain denies logons explicitly instead of falling back silently.
- `krb5.conf` is no longer regenerated wholesale every start: like
  `smb.conf` it is reconciled against the generated settings and existing
  operator values are never overwritten, now uniformly for both files. A
  `[realms]` block is treated as one setting whose value is the collected
  `{ … }` text (interior lines and EOLs kept verbatim), so a missing realm
  block is appended exactly as generated while a differing one is reported
  as drift instead of being merged into. Realm names must be upper case
  (AD convention); a block name that differs only in case is drift, never a
  duplicate block. Single relations (`[libdefaults]`,
  `[domain_realm]`) are appended inside their section when missing. See
  [docs/configuration-provisioning.md](docs/configuration-provisioning.md).
- Provisioning drift in operator-managed files is reported per the new
  `--relaxed` policy instead of only strict: an operator value that differs
  from the generated settings, or settings that cannot be appended to a
  read-only target, stop the daemon in strict mode (containers catch drift
  at deploy time) and only produce a warning with `--relaxed` (systemd
  deployments keep running). The policy is identical for `smb.conf` and
  `krb5.conf`; a read-only file that already carries everything is accepted.
- `Winbind.hostname` becomes the stable `netbios name` (AD computer account)
  in the generated `smb.conf`, so ephemeral container hostnames no longer
  affect domain membership across pod restarts.

- The dev container image no longer ships a baked-in TLS key/cert.
  The runtime image carries `openssl` and the entrypoint generates an
  ephemeral self-signed cert at first start if none is mounted at the
  configured path; each container instance gets its own key. The
  entrypoint also runs entirely as UID 1001 (no more `USER 0`).
- rdpgw refuses to start when any of `Server.SessionKey`,
  `Server.SessionEncryptionKey`, `Security.PAATokenSigningKey`,
  `Security.PAATokenEncryptionKey`, `Security.UserTokenSigningKey`,
  `Security.UserTokenEncryptionKey`, or `Security.QueryTokenSigningKey`
  matches a published placeholder value from `README.md` / the dev
  compose files. See [UPGRADING.md](UPGRADING.md) for the full list.
- `rdpgw-auth` now creates its socket with mode `0660` and accepts only
  connections whose peer UID is on an allow-list (default: the daemon's
  own UID). Operators running rdpgw and rdpgw-auth as different users
  must list the gateway's UID via `--allow-uid` or share a group via
  `--allow-gid`. See [UPGRADING.md](UPGRADING.md).
- `X-Forwarded-For` is now honored only when the request arrives from
  a `Server.TrustedProxies` CIDR. The default `Server.TrustedProxies`
  is empty, so by default the request's `RemoteAddr` (host portion) is
  the source of `AttrClientIp`. See [UPGRADING.md](UPGRADING.md) if
  your deployment relies on a fronting proxy stamping XFF.
- `server.hostselection: any` now refuses destinations that resolve to
  loopback, RFC1918, link-local, IPv6 ULA, unspecified, or multicast
  addresses, and only forwards to ports in `Server.AllowedDestinationPorts`
  (default `[3389]`). Operators that need the old behavior can opt back in
  with `Server.AllowPrivateDestinations: true` and an extended port list.
  See [UPGRADING.md](UPGRADING.md) for migration notes. The other
  host-selection modes (`roundrobin`, `signed`, `unsigned`) already used
  the operator-curated `Server.Hosts` list and are unaffected.

### Added

- `rdpgw-auth`: `AuthProtocols.Kerberos` (keytab sharing with the gateway,
  `keytabPath` and SPN management), `AuthProtocols.Ntlm` (ordered
  `winbind`/`users` backends), `AuthProtocols.Basic` (generated PAM stack)
  and the modern `Winbind` schema (`domain` FQDN, `workgroup`, `hostname`,
  `requiremembershipof`, `ntlmauthpath`, `timeout`, `autojoin`,
  `jointimeout`, `stripdomain`, `separator`, `domaincontrollers` with
  host/port objects or plain hosts). See
  [docs/advanced-auth-configuration.md](docs/advanced-auth-configuration.md).
- SPN collection from the gateway configuration via `RDPGW_CONF` (default
  `/opt/rdpgw/rdpgw.yaml`): `HTTP/<Server.GatewayAddress>` is derived
  automatically, mirroring the removed startup script.
- Supervisor deployment overrides: `RDPGW_WINBIND_PATH` and
  `RDPGW_WINBIND_DEBUG` (e.g. `-d 5`); external winbindd mode via
  `RDPGW_AUTH_EXTERNAL_WINBIND=1` with a 30s readiness budget.
- Automatic AD domain joins via `AD_JOIN_USER`/`AD_JOIN_PASSWORD` (the same
  variable names the legacy startup script used) with
  `Winbind.autojoin: true`.
- Named `Ldap` and `Oath` profiles (mapping or list form) referenced by the
  generated Basic stack, validated at startup.

- `rdpgw-auth`: NTLM logons can now be verified against Active Directory
  via Samba winbind (`Ntlm.Backend: winbind`). The helper delegates the
  handshake to `ntlm_auth`, so no passwords are stored on the gateway.
  New settings: `Ntlm.Backend` (default `file`, the existing behavior),
  `Ntlm.Winbind.NtlmAuthPath`, `Ntlm.Winbind.Domain`,
  `Ntlm.Winbind.RequireMembershipOf`, `Ntlm.Winbind.Timeout`,
  `Ntlm.Winbind.StripDomain`, `Ntlm.Winbind.Separator`. See
  [docs/ntlm-authentication.md](docs/ntlm-authentication.md).
- `rdpgw-auth --relaxed`: warn about operator-managed system files
  (`smb.conf`/`krb5.conf`) differing from the generated configuration
  instead of refusing to start. Strict is the default; see
  [docs/advanced-auth-configuration.md](docs/advanced-auth-configuration.md).
- Brace-aware krb5.conf merge: a `[realms]` block is one setting whose value
  is the collected `{ … }` text, so a missing block is appended verbatim and
  a differing one is drift; missing single relations are inserted inside
  their section. Documented together with the smb.conf merge in
  [docs/configuration-provisioning.md](docs/configuration-provisioning.md).
- `rdpgw-auth --allow-uid` and `--allow-gid` flags (repeatable).
- `Server.TrustedProxies` (`[]string`, CIDR, default empty).
- `Server.AllowedDestinationPorts` (`[]int`, default `[3389]`).
- `Server.AllowPrivateDestinations` (`bool`, default `false`).
