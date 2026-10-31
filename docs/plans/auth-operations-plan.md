# Incremental Operational Tracking Plan: `rdpgw-auth` Modernization

This document outlines the shippable, incremental milestones for migrating `rdpgw-auth` from its legacy shell-script wrapper architecture to a fully self-contained, native Go microservice with unified auth pipelines, automated domain joining, process supervision, and modular template-fused PAM generation.

---

## Critical Architecture Note: Winbind Hostname / Machine Account Name Handling
In containerized environments (Kubernetes/Docker), pods receive ephemeral, randomly generated hostnames (e.g., `rdpgw-auth-6585fd5899-wsmks`). Samba winbind and Active Directory require a stable, predictable machine account NetBIOS name (`netbios name` in `smb.conf`) so that the computer object in Active Directory and its corresponding Kerberos SPNs remain consistent across pod restarts, rather than using the ephemeral container hostname.
- **Resolution**: `rdpgw-auth` configuration explicitly separates the domain/workgroup name (`netbios: "CORP"`) from the machine computer account name (`netbiosName: "rdpgw-auth"`), ensuring the AD machine account name never relies on ephemeral pod hostnames.

---

## Milestone 1: Winbind Configuration Schema & Kerberos Share
### Scope
- Implement Go struct definitions for `WinbindConfig` (including domain controllers list supporting both string lists and detailed host/port objects, and explicit NetBIOS/hostname management).
- Implement `AuthProtocols.Kerberos` (`share: true/false`, `keytabPath`).
- Add legacy backward compatibility mapping specifically for NTLM/Kerberos and `smb.conf` keytab sharing.

### Deliverables
- Updated `cmd/auth/config/configuration.go`.
- Unit tests (`configuration_test.go`) validating NetBIOS resolution and legacy mapping.

---

## Milestone 2: Go-Based Template Engine (`smb.conf` & `krb5.conf`)
### Scope
- Implement file staging in `/tmp/rdpgw/` and mount safety checks (detecting read-only operator mounts).
- Build the Go template engine using embedded templates (`smb.conf.tmpl`, `krb5.conf.tmpl`).
- Implement the strict explode policy (`log.Fatalf`) when the required generated `[global]` settings cannot be applied to an operator-mounted `smb.conf` (read-only volume, or a `[global]` section ending in a continuation backslash), or when an operator value differs from the generated one. Missing settings are appended; existing values are never overwritten, and drift terminates the daemon with an error naming every conflict.

### Deliverables
- Embedded template assets in `cmd/auth/provisioning/templates/` (`smb.conf.tmpl`, `krb5.conf.tmpl`, embedded via `//go:embed templates/*.tmpl`).
- Initialization provisioning logic in `cmd/auth/provisioning/provisioning.go`.

---

## Milestone 3: Process Supervision, Domain Join, and Script Migration

Split into two shippable deliverables so the container can switch to the
Go supervisor before the join logic moves.

### Milestone 3a: `winbindd` Supervision (delivered, `77e3ab9`)
#### Status
- Completed on `feature/milestone-3a-winbindd-supervision`.

#### Scope
- Supervise `winbindd` from `rdpgw-auth` (`os/exec`): command line mirrors the legacy `winbindd -F --no-process-group --debug-stdout -d 2`, with `RDPGW_WINBIND_PATH` and `RDPGW_WINBIND_DEBUG` as deployment overrides (environment variables, not configuration schema). stdout/stderr are mirrored into the Go logger with a `[winbindd]` prefix.
- `wbinfo -p` readiness polling before the gRPC socket is opened.
- Graceful signal propagation (`SIGTERM`/`SIGINT`): stop `winbindd` (SIGTERM, then SIGKILL after a grace period), remove the socket and exit cleanly.
- Honour `RDPGW_AUTH_EXTERNAL_WINBIND=1`: wait for the host-provided winbindd instead of spawning one.
- Replace the `winbindd ... &` / `wbinfo -p` wait block at the end of `run-auth-winbind.sh` with `exec rdpgw-auth --serve-user rdpgw`; the script keeps the filesystem/join/keytab preparation for now.
- The parent process stays root (it needs the rights to stop `winbindd`) and re-executes the gRPC server as `--serve-user rdpgw` (UID 1001), replacing the old `su-exec` step. The socket therefore keeps its previous owner and the UID/GID gate is unchanged.

#### Deliverables
- `cmd/auth/supervisor/` (winbindd supervisor, readiness probe, shutdown, re-exec child runner).
- `cmd/auth/serve/` (unix socket, peer-credential gate, gRPC lifecycle, `--serve-user` privilege drop).
- `cmd/auth/service/` (PAM/NTLM gRPC API and backend selection).
- Wiring in `cmd/auth/auth.go`.
- Slimmed `dev/docker/run-auth-winbind.sh`.

### Milestone 3b: Domain Join, Keytab and SPN Management
#### Status
- Delivered on `feature/milestone-3b-domain-join`.

#### Scope
- Implement `net ads testjoin` pre-checks, exponential backoff auto-join loop (2s → 30s), configurable `JoinTimeout` (default 10 min), and explicit failure explosion (`log.Fatalf`) with clear troubleshooting instructions when unjoined. `autoJoin: false` waits for a manual join and prints the instructions immediately.
- Run the join in the root supervisor before `winbindd` starts (external-winbind deployments delegate the join to the host).
- Migrate the join/wait logic out of `run-auth-winbind.sh` into `cmd/auth/join/`.
- Migrate keytab creation and SPN management into `cmd/auth/join/`: refresh the keytab (`net ads keytab create -P`), collect SPNs from `AuthProtocols.Kerberos.Spns` (legacy `ntlm.winbind.spns` maps there), `KERBEROS_SPNS` and `HTTP/<GatewayAddress>` from `RDPGW_CONF`, register missing SPNs with the join credentials, otherwise print manual instructions and wait for them to appear in `klist -k`, then make the keytab readable by the gateway (0644).
- When rewriting keytab directives, update mis-pointed directive lines in place rather than appending duplicates (Milestone 2's append policy would leave both lines on a writable mis-pointed operator file; samba reads them ambiguously). The authoritative directives are `kerberos method`, `dedicated keytab file` and `sync machine password to keytab`.

#### Deliverables
- `cmd/auth/join/` (domain join, keytab and SPN management), the in-place keytab rewrite in `cmd/auth/provisioning/`, and the corresponding script cleanup.

---

## Milestone 4: NTLM Backends & Ordering
### Scope
- Implement `AuthProtocols.Ntlm` parsing and execution.
- Support ordered backend execution for NTLM (`winbind`, `users` as alternative/exclusive verifiers).

### Deliverables
- Updated gRPC `NTLM` handler in `cmd/auth/auth.go` supporting ordered NTLM backend execution.

---

## Milestone 5: Modular PAM Stack Generation & Static Users (`users.pwd`)
### Scope
- Implement static YAML users to `pam_pwdfile` integration (`users.pwd` generation under `/tmp/rdpgw/`).
- Deploy `session_manager.sh` alongside `rdpgw-auth` at `/opt/rdpgw/session_manager.sh`.
- Build the dynamic PAM stack generator by fusing ready smaller template blocks (Winbind, LDAP, Unix, Users + OATH) into one unified `/etc/pam.d/rdpgw` file using robust `success=ok default=...` skip logic.

### Deliverables
- PAM template fragment definitions and dynamic fusion engine.
- Session manager script deployment.

---

## Milestone 6: Container Streamlining & Final Release (`rdpgw-auth`)
### Scope
- Update `Dockerfile.auth-winbind` to remove legacy shell scripts (`run-auth-winbind.sh`) and CLI dependencies (`yq-go`).
- Rename binary and container image references to lightweight **`rdpgw-auth`**.
- Update CI/CD build pipelines.
- Verify end-to-end integration on the K3s cluster.

### Deliverables
- Streamlined `Dockerfile.auth-winbind` and updated Kubernetes manifests.
