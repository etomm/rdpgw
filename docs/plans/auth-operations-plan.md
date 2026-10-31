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
- The remaining filesystem/`secrets.ldb` preparation and the entrypoint replacement stay in `run-auth-winbind.sh` for Milestone 6 (container streamlining), together with the `yq-go`/`su-exec` removal.

#### Deliverables
- `cmd/auth/join/` (domain join, keytab and SPN management), the in-place keytab rewrite in `cmd/auth/provisioning/`, and the corresponding script cleanup.

---

## Milestone 4: NTLM Backends & Ordering
### Status
- Implementation landed with the configuration work (`b5cb193`): `cmd/auth/ntlm/orderedbackend.go`, `nullbackend.go` and `newNtlmBackend` in `cmd/auth/auth.go`.
- Verified on `feature/milestone-4-ntlm-backends`; coverage lives in `orderedbackend_test.go` and `backendcompat_test.go`.
- The baked fallback `/etc/pam.d/rdpgw` was made self-contained (`pam_deny`): Alpine does not ship the `base-auth`/`base-account` includes the old file referenced.

### Scope
- Implement `AuthProtocols.Ntlm` parsing and execution.
- Support ordered backend execution for NTLM (`winbind`, `users` as alternative/exclusive verifiers).

### Deliverables
- Updated gRPC `NTLM` handler in `cmd/auth/auth.go` supporting ordered NTLM backend execution.

---

## Milestone 5: Modular PAM Stack Generation & Static Users (`users.pwd`)
### Status
- Delivered on `feature/milestone-5-pam-stack`.

### Scope
- Implement static YAML users to `pam_pwdfile` integration (`users.pwd` generation under `/tmp/rdpgw/`).
- Deploy `session_manager.sh` alongside `rdpgw-auth` at `/opt/rdpgw/session_manager.sh`.
- Build the dynamic PAM stack generator by fusing ready smaller template blocks (Winbind, LDAP, Unix, Users + OATH) into one unified `/etc/pam.d/rdpgw` file using robust `success=ok default=...` skip logic. A top-level `pam_stack.tmpl` composes the per-backend blocks (it invokes `auth_block.tmpl` and `account_block.tmpl`) instead of concatenating rendered strings in Go.
- Configuration schema: `Ldap` and `Oath` profiles plus `AuthProtocols.Basic` (`enabled`, ordered `stack` of `backend`/`name`/`oath`), validated against the referenced profiles.
- `users.pwd` stores SHA-512 crypt (`$6$`) hashes with a fresh random salt per start; the file is mode 0600.
- LDAP profiles render a per-profile `pam_ldap` client config under `/tmp/rdpgw/` (host/port/base/binddn/bindpw/TLS), mode 0600.
- Auth phase: each block is `[success=ok default=N]` so a failed OATH/module jumps over the rest of its block; the successful module records the backend via `session_manager.sh create`.
- The daemon injects `RDPGW_SESSION_ID` (a fresh GUID per authentication attempt) into the PAM environment before `pam_authenticate`; `session_manager.sh` keys its state only on that id (no username fallback), so concurrent logins for the same user cannot overwrite each other and a missing id fails closed.
- Failure semantics: `create` uses `success=done default=die`, so authentication cannot proceed if the backend record cannot be written; a failed `check` skips its block and the final `pam_deny` fails the account phase; `cleanup` is best effort (`default=done`) because the account module already decided.
- Account phase: `check` must match the recorded backend; only then does that backend's account module run, with `cleanup` terminating the stack. A final `pam_deny` covers the no-match case.

### Deliverables
- `cmd/auth/pamstack/` (fusion engine, `templates/` fragments, `session_manager.sh`, and the PAM `Session`/`StartSession` helper that injects `RDPGW_SESSION_ID`).
- `AuthProtocols.Basic`/`Ldap`/`Oath` schema and validation in `cmd/auth/config/configuration.go`.
- Wiring in `cmd/auth/auth.go`.

---

## Milestone 6: Container Streamlining & Final Release (`rdpgw-auth`)
### Status
- Delivered on `feature/milestone-6-container`.
- Verified locally: the image builds, the binary is PID 1 as root with the gRPC server as UID 1001, the generated PAM stack is installed, and a real gRPC `Authenticate` call with the `users` backend succeeds for the right password and is denied for a wrong one. SIGTERM produces a clean shutdown.
- The container check also caught and fixed two PAM invocation bugs from Milestone 5: `pam_pwdfile` needs `pwdfile=<path>`, and the session manager must be invoked through `pam_exec.so`.
- Remaining operator step: the K3s end-to-end check needs the image published (CI) and the cluster manifests updated; both live outside this repository.

### Scope
- Absorb the last shell block: `cmd/auth/samba.go` creates the samba runtime directories, ownership (`private` root-only, `winbindd_privileged` for the group) and `secrets.ldb` before the join.
- Remove `run-auth-winbind.sh`; the Dockerfile entrypoint is the binary itself (`rdpgw-auth --serve-user rdpgw`), which then provisions, joins, generates PAM and supervises winbindd.
- Remove the now-unused `su-exec` and `yq-go` packages; add the PAM modules referenced by the generated stack (`pam-winbind`, `oath-toolkit-pam_oath`, `nss-pam-ldapd`, and `pam_pwdfile` built from source because Alpine does not package it).
- Publish the image as **`rdpgw-auth`**, keeping `rdpgw-auth-winbind` as a compatibility alias in the CI tags.
- Update CI/CD build pipelines and the Docker documentation.

### Deliverables
- `cmd/auth/samba.go`, streamlined `Dockerfile.auth-winbind` (no shell entrypoint), updated `.github/workflows/docker-image.yml`, `dev/docker/docker-readme.md`.
