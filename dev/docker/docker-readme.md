# RDPGW
## What is RDPGW?
Remote Desktop Gateway (RDPGW, RDG or RD Gateway) provides a secure encrypted connection 
to user desktops via RDP. It enhances control by removing all remote user direct access to 
your system and replaces it with a point-to-point remote desktop connection.

## How to use this image
The remote desktop gateway relies on an OpenID Connect authentication service, such as Keycloak, 
Azure AD or Google, and a backend remote desktop service such as XRDP, gnome-remote-desktop, or
Windows VMs. Make sure that these services have been properly setup and can be reached from
where you will run this image. 

This image works stateless, which means it does not store any state by default. In case you configure
the session store to be a `filestore` a little bit of session information is stored temporarily. This means
that a load balancer would need to maintain state for a while, which typically is the case.

Session and token encryption keys will be randomized on startup. As a consequence sessions will be
invalidated on restarts and if you are load balancing the different instances will not be able to share
user sessions. Make sure to set these encryption keys to something static, so they can be shared 
across the different instances if this is not what you want.

## Configuration through environment variables
```bash
docker --run name rdpgw bolkedebruin/rdpgw:latest \
  -e RDPGW_SERVER__CERT_FILE=/etc/rdpgw/cert.pem
  -e RDPGW_SERVER__KEY_FILE=/etc/rdpgw.cert.pem
  -e RDPGW_SERVER__GATEWAY_ADDRESS=https://localhost:443
  -e RDPGW_SERVER__SESSION_KEY=thisisasessionkeyreplacethisjetz  # 32 characters
  -e RDPGW_SERVER__SESSION_ENCRYPTION_KEY=thisisasessionkeyreplacethisnunu # 32 characters
  -e RDPGW_OPEN_ID__PROVIDER_URL=http://keycloak:8080/auth/realms/rdpgw
  -e RDPGW_OPEN_ID__CLIENT_ID=rdpgw
  -e RDPGW_OPEN_ID__CLIENT_SECRET=01cd304c-6f43-4480-9479-618eb6fd578f
  -e RDPGW_SECURITY__SECURITY_PAA_TOKEN_SIGNING_KEY=prettypleasereplacemeinproductio # 32 characters
  -v conf:/etc/rdpgw
```

## NTLM and Kerberos authentication against Active Directory (winbind)

`Dockerfile.auth-winbind` builds an `rdpgw-auth` image that contains Samba
winbind and `ntlm_auth`, for use with a winbind-capable configuration
(`AuthProtocols.Ntlm`/`Kerberos`/`Basic` using the winbind backend, or the
legacy `Ntlm.Backend: winbind`). It builds from the
local source tree, so run the build from the repository root:

```bash
docker build -f dev/docker/Dockerfile.auth-winbind -t rdpgw-auth .
```

The image is published both as `rdpgw-auth` and (legacy alias)
`rdpgw-auth-winbind`; both tags point at the same build. See
[docs/advanced-auth-configuration.md](../../docs/advanced-auth-configuration.md)
for the configuration reference and
[docs/ntlm-authentication.md](../../docs/ntlm-authentication.md) for the
setup details.

The entrypoint is the `rdpgw-auth` daemon itself, which fully provisions the
container at startup: staged/reconciled `smb.conf` and `krb5.conf`, the
generated PAM stack when `AuthProtocols.Basic` is enabled, the domain join
(`AD_JOIN_USER`/`AD_JOIN_PASSWORD` with `Winbind.autojoin: true`, or a clean
wait for a manual join), shared keytab refresh and SPN registration, and then
`winbindd` supervision (`wbinfo -p` readiness, graceful stop on SIGTERM) with
the gRPC server running as UID 1001. There is no shell startup script and no
`yq`/`su-exec` anymore.

The daemon's default configuration path is `/opt/rdpgw/rdpgw-auth.yaml` (its
working directory); either mount the file there or pass the chosen path with
`--conf`. It also accepts the usual flags (`-c`, `-s`, `--allow-uid`,
`--allow-gid`, `--serve-user`) as container arguments; `--relaxed` downgrades
file-drift explosions to warnings (for host/systemd deployments).

`winbind` only works on a host that is joined to the domain. Choose one of two
ways to provide that:

1. **Run winbindd in the container.** Mount a persistent `/var/lib/samba`
   volume so the domain membership survives restarts. Mounting a domain member
   `smb.conf` and `krb5.conf` is optional now: `rdpgw-auth` provisions them
   from the configuration (operator files keep winning: missing settings are
   appended, values are never overwritten; a value that differs refuses to
   start, unless the daemon runs with `--relaxed`, which logs the drift and
   keeps running — the mode designed for long-lived systemd services).

   ```bash
   # Automatic join on first start:
   docker run -d --name rdpgw-auth --hostname rdpgw-auth \
     -e AD_JOIN_USER=Administrator -e AD_JOIN_PASSWORD=your_password \
     -v ./rdpgw-auth.yaml:/opt/rdpgw/rdpgw-auth.yaml:ro \
     -v samba-state:/var/lib/samba \
     -v auth-socket:/tmp \
     ghcr.io/example-org/rdpgw-auth:latest

   # Or manual one-time join via interactive exec:
   docker run --rm -it --entrypoint net \
     -v samba-state:/var/lib/samba \
     ghcr.io/example-org/rdpgw-auth:latest ads join -U Administrator
   ```

   Keep the machine account name stable
   (`Winbind.hostname: rdpgw-auth` in the configuration): it is the computer account name in the domain.

2. **Use the winbind of a domain-joined Docker host.** Set
   `RDPGW_AUTH_EXTERNAL_WINBIND=1` and mount the host's `/run/samba` and
   `/var/lib/samba/winbindd_privileged`. The host's privileged pipe directory
   must be accessible to UID 1001, for example through a group whose GID matches
   the host's `winbindd_priv` group.

In both cases the socket in `/tmp` is shared with the `rdpgw` container, which
also runs as UID 1001, so no `--allow-uid` flag is needed. The distroless image
does not contain Samba and cannot be used with the winbind backend.

