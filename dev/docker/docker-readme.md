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

## NTLM authentication against Active Directory (winbind)

`Dockerfile.auth-winbind` builds an `rdpgw-auth` image that contains Samba
winbind and `ntlm_auth`, for use with `Ntlm.Backend: winbind` (see
[docs/ntlm-authentication.md](../../docs/ntlm-authentication.md)). It builds from
the local source tree, so run the build from the repository root:

```bash
docker build -f dev/docker/Dockerfile.auth-winbind -t rdpgw-auth-winbind .
```

`winbind` only works on a host that is joined to the domain. Choose one of two
ways to provide that:

1. **Run winbindd in the container.** Mount a domain member `smb.conf` and a
   persistent `/var/lib/samba` volume, join the domain once, then start the
   container normally. The entrypoint starts `winbindd`, waits for it, and runs
   `rdpgw-auth` as UID 1001.

   ```bash
   docker run --rm -it --entrypoint net \
     -v ./smb.conf:/etc/samba/smb.conf:ro -v samba-state:/var/lib/samba \
     rdpgw-auth-winbind ads join -U Administrator

   docker run -d --name rdpgw-auth --hostname rdpgw-auth \
     -v ./smb.conf:/etc/samba/smb.conf:ro -v samba-state:/var/lib/samba \
     -v ./rdpgw-auth.yaml:/opt/rdpgw/rdpgw-auth.yaml:ro \
     -v auth-socket:/tmp \
     rdpgw-auth-winbind
   ```

   Keep the container hostname stable: it is the computer account name in the
   domain.

2. **Use the winbind of a domain-joined Docker host.** Set
   `RDPGW_AUTH_EXTERNAL_WINBIND=1` and mount the host's `/run/samba` and
   `/var/lib/samba/winbindd_privileged`. The host's privileged pipe directory
   must be accessible to UID 1001, for example through a group whose GID matches
   the host's `winbindd_priv` group.

In both cases the socket in `/tmp` is shared with the `rdpgw` container, which
also runs as UID 1001, so no `--allow-uid` flag is needed. The distroless image
does not contain Samba and cannot be used with the winbind backend.

