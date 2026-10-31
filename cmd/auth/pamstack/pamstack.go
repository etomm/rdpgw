// Package pamstack generates the rdpgw PAM stack and its companion files
// (users.pwd, LDAP profiles, session_manager.sh) from the rdpgw-auth
// configuration. It replaces the hand-maintained dev/docker/rdpgw-pam file.
package pamstack

import (
	"embed"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed session_manager.sh
var sessionManagerScript []byte

// Paths holds the runtime locations the generated stack refers to.
type Paths struct {
	// PamFile is the generated PAM service file.
	PamFile string
	// UsersFile is the pam_pwdfile database generated from Users.
	UsersFile string
	// LdapConfDir holds the generated per-profile LDAP client files.
	LdapConfDir string
	// SessionManager is the backend-tracking helper used by pam_exec.
	SessionManager string
}

// DefaultPaths returns the container paths for the configured PAM service.
// The service name is also the generated file name under /etc/pam.d, so
// `rdpgw-auth -n custom-service` and the generated stack agree on it.
func DefaultPaths(serviceName string) Paths {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = "rdpgw"
	}
	return Paths{
		PamFile:        filepath.Join("/etc/pam.d", serviceName),
		UsersFile:      "/tmp/rdpgw/users.pwd",
		LdapConfDir:    "/tmp/rdpgw",
		SessionManager: "/opt/rdpgw/session_manager.sh",
	}
}

// Install renders and writes the PAM stack and its companion files. It is a
// no-op unless AuthProtocols.Basic is enabled. The users database is
// regenerated on every call (the plan requires a fresh users.pwd each start).
// runtimeUser is the unprivileged user the gRPC server runs as (may be empty
// when the daemon serves in-process); the PAM-readable files are shared with
// its group accordingly.
func Install(conf config.Configuration, paths Paths, runtimeUser string) error {
	content, err := Generate(conf, paths)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}

	if err := writeFileIfChanged(paths.SessionManager, sessionManagerScript, 0o755); err != nil {
		return fmt.Errorf("pamstack: cannot install session manager: %w", err)
	}

	usedBackends := basicBackends(conf)
	ldapProfiles := referencedLdapProfiles(conf, usedBackends)

	if usedBackends[config.BasicBackendUsers] {
		usersPwd, err := GenerateUsersPwd(conf.Users)
		if err != nil {
			return err
		}
		if err := writeFile(paths.UsersFile, usersPwd, 0o600); err != nil {
			return fmt.Errorf("pamstack: cannot write users database: %w", err)
		}
	}

	if err := installLdapConfigs(ldapProfiles, paths.LdapConfDir); err != nil {
		return err
	}

	// The PAM modules run in the unprivileged gRPC child, so the files they
	// read must be group-readable by that user. They stay hidden from others:
	// users.pwd holds hashes and the LDAP config holds the bind password.
	if usedBackends[config.BasicBackendUsers] || len(ldapProfiles) > 0 {
		shareDirWithRuntimeUser(filepath.Dir(paths.UsersFile), runtimeUser)
	}
	if usedBackends[config.BasicBackendUsers] {
		shareWithRuntimeUser(paths.UsersFile, runtimeUser, 0o640)
	}
	for name := range ldapProfiles {
		shareWithRuntimeUser(ldapConfPath(paths.LdapConfDir, name), runtimeUser, 0o640)
	}

	if err := writePamStack(paths.PamFile, content); err != nil {
		return err
	}

	log.Printf("PAM: generated %s from %d backend(s)", paths.PamFile, len(conf.AuthProtocols.Basic.Stack))
	return nil
}

// runtimeGID resolves the serving user's primary group. It is only used when
// the daemon starts as root and re-executes the gRPC server as that user.
func runtimeGID(runtimeUser string) (int, bool) {
	if runtimeUser == "" || os.Geteuid() != 0 {
		return 0, false
	}
	u, err := user.Lookup(runtimeUser)
	if err != nil {
		log.Printf("PAM: cannot resolve serving user %q: %v", runtimeUser, err)
		return 0, false
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		log.Printf("PAM: invalid gid %q for serving user %q", u.Gid, runtimeUser)
		return 0, false
	}
	return gid, true
}

func shareWithRuntimeUser(path, runtimeUser string, mode os.FileMode) {
	gid, ok := runtimeGID(runtimeUser)
	if !ok {
		return
	}
	if err := os.Chown(path, 0, gid); err != nil {
		log.Printf("PAM: cannot chown %s to root:%s: %v", path, runtimeUser, err)
		return
	}
	if err := os.Chmod(path, mode); err != nil {
		log.Printf("PAM: cannot chmod %s: %v", path, err)
	}
}

// shareDirWithRuntimeUser makes the directory traversable by the serving
// group without exposing it to everyone.
func shareDirWithRuntimeUser(dir, runtimeUser string) {
	gid, ok := runtimeGID(runtimeUser)
	if !ok {
		return
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		log.Printf("PAM: cannot chown %s to root:%s: %v", dir, runtimeUser, err)
		return
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		log.Printf("PAM: cannot chmod %s: %v", dir, err)
	}
}

// Generate renders the PAM stack. It returns an empty string when the Basic
// protocol is not enabled. The configuration must have gone through
// config.Load, which resolves Basic.Stack entries and validates the result.
func Generate(conf config.Configuration, paths Paths) (string, error) {
	if conf.AuthProtocols == nil || conf.AuthProtocols.Basic == nil || !conf.AuthProtocols.Basic.Enabled {
		return "", nil
	}
	basic := conf.AuthProtocols.Basic
	if len(basic.Stack) == 0 {
		return "", fmt.Errorf("pamstack: AuthProtocols.Basic.Stack is empty")
	}

	entries := make([]blockData, 0, len(basic.Stack))
	accountEntries := make([]blockData, 0, len(basic.Stack))
	backends := make([]string, 0, len(basic.Stack))
	seenAccount := make(map[string]bool, len(basic.Stack))
	for _, entry := range basic.Stack {
		data, err := blockDataFor(conf, entry, paths)
		if err != nil {
			return "", err
		}
		entries = append(entries, data)
		backends = append(backends, data.Backend)
		// The account phase is determined by the backend key alone (OATH only
		// participates in auth), so two blocks for the same key share one
		// account block. The key includes the Ldap profile: different profiles
		// have different account checks.
		if !seenAccount[data.Key] {
			seenAccount[data.Key] = true
			accountEntries = append(accountEntries, data)
		}
	}

	tmpl, err := template.New("pam").ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return "", fmt.Errorf("pamstack: cannot parse templates: %w", err)
	}

	var out strings.Builder
	data := stackData{
		Backends:       strings.Join(backends, " -> "),
		Entries:        entries,
		AccountEntries: accountEntries,
	}
	if err := tmpl.ExecuteTemplate(&out, "pam_stack.tmpl", data); err != nil {
		return "", fmt.Errorf("pamstack: cannot render the PAM stack: %w", err)
	}
	return out.String(), nil
}

type stackData struct {
	Backends       string
	Entries        []blockData
	AccountEntries []blockData
}

type blockData struct {
	Backend        string
	Key            string
	Module         string
	AccountModule  string
	Oath           string
	SessionManager string
}

func blockDataFor(conf config.Configuration, entry config.BasicStackEntry, paths Paths) (blockData, error) {
	backend := entry.Backend
	key := backend
	if backend == config.BasicBackendLdap && entry.Name != "" {
		key += "/" + entry.Name
	}
	data := blockData{
		Backend:        backend,
		Key:            key,
		SessionManager: paths.SessionManager,
	}

	switch backend {
	case config.BasicBackendWinbind:
		// Do not add krb5_auth: it makes pam_winbind resolve the user with
		// getpwnam() before contacting winbindd. The Alpine image has no
		// NSS winbind module (/etc/nsswitch.conf has no winbind entry), so
		// every login would fail with PAM_USER_UNKNOWN. Password
		// authentication itself does not need NSS; winbindd validates the
		// credentials directly, including disabled/expired accounts.
		data.Module = "pam_winbind.so"
		// pam_winbind's account phase calls getpwnam() through valid_user()
		// and therefore also needs NSS winbind. Authentication already ran
		// the full AD logon, so permit the account phase here.
		data.AccountModule = "pam_permit.so"
	case config.BasicBackendLdap:
		profileKey := strings.ToLower(strings.TrimSpace(entry.Name))
		if _, ok := conf.Ldap[profileKey]; !ok {
			return data, fmt.Errorf("pamstack: ldap backend references unknown profile %q", entry.Name)
		}
		data.Module = "pam_ldap.so config=" + ldapConfPath(paths.LdapConfDir, profileKey)
		data.AccountModule = "pam_ldap.so"
	case config.BasicBackendUnix:
		data.Module = "pam_unix.so nullok try_first_pass"
		data.AccountModule = "pam_unix.so"
	case config.BasicBackendUsers:
		data.Module = "pam_pwdfile.so pwdfile=" + paths.UsersFile
		data.AccountModule = "pam_permit.so"
	default:
		return data, fmt.Errorf("pamstack: unknown Basic backend %q", entry.Backend)
	}

	if entry.Oath != "" {
		profile, ok := conf.Oath[strings.ToLower(strings.TrimSpace(entry.Oath))]
		if !ok {
			return data, fmt.Errorf("pamstack: backend %s references unknown Oath %q", backend, entry.Oath)
		}
		data.Oath = "pam_oath.so usersfile=" + profile.UsersFile
		if profile.Window > 0 {
			data.Oath += fmt.Sprintf(" window=%d", profile.Window)
		}
	}
	return data, nil
}

func ldapConfPath(dir, name string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
	return filepath.Join(dir, "ldap-"+safe+".conf")
}

// ldapConfTemplate renders the pam_ldap client configuration. Keeping it in
// templates/ (like the PAM stack fragments) makes the output reviewable
// without reading Go string concatenation.
var ldapConfTemplate = template.Must(template.New("ldap.conf.tmpl").ParseFS(templatesFS, "templates/ldap.conf.tmpl"))

// basicBackends reports which Basic stack backends are actually used, so
// Install does not generate companion files for backends that are not in the
// stack (notably users.pwd when there is no users entry).
func basicBackends(conf config.Configuration) map[string]bool {
	used := make(map[string]bool)
	if conf.AuthProtocols == nil || conf.AuthProtocols.Basic == nil {
		return used
	}
	for _, entry := range conf.AuthProtocols.Basic.Stack {
		used[strings.ToLower(strings.TrimSpace(entry.Backend))] = true
	}
	return used
}

// referencedLdapProfiles returns only the Ldap profiles named by the stack.
func referencedLdapProfiles(conf config.Configuration, used map[string]bool) config.LdapProfiles {
	profiles := make(config.LdapProfiles)
	if !used[config.BasicBackendLdap] {
		return profiles
	}
	for _, entry := range conf.AuthProtocols.Basic.Stack {
		if !strings.EqualFold(entry.Backend, config.BasicBackendLdap) {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(entry.Name))
		if profile, ok := conf.Ldap[key]; ok {
			profiles[key] = profile
		}
	}
	return profiles
}

func installLdapConfigs(profiles config.LdapProfiles, dir string) error {
	for name, profile := range profiles {
		body, err := ldapConfBody(profile)
		if err != nil {
			return fmt.Errorf("pamstack: cannot render LDAP profile %q: %w", name, err)
		}
		if err := writeFile(ldapConfPath(dir, name), []byte(body), 0o600); err != nil {
			return fmt.Errorf("pamstack: cannot write LDAP profile %q: %w", name, err)
		}
	}
	return nil
}

// ldapConfBody renders the subset of the pam_ldap client configuration the
// rdpgw-auth schema exposes. The file contains bind credentials: mode 0600.
func ldapConfBody(profile config.LdapConfig) (string, error) {
	var b strings.Builder
	if err := ldapConfTemplate.Execute(&b, profile); err != nil {
		return "", err
	}
	return b.String(), nil
}

// writeFile is the single filesystem primitive: it writes data, enforces the
// file mode (os.WriteFile only applies it on creation) and derives the parent
// directory mode by turning the file's read bits into traversal bits:
// 0600 -> 0700, 0644 -> 0755. That keeps secret directories owner-only while
// the generated PAM file is traversable like a normal /etc/pam.d entry.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), directoryMode(mode)); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// directoryMode mirrors the file's read bits as execute bits.
func directoryMode(fileMode os.FileMode) os.FileMode {
	return fileMode | (fileMode&0o444)>>2
}

// writeFileIfChanged avoids touching the session manager script while a
// concurrent pam_exec invocation may still be executing it.
func writeFileIfChanged(path string, data []byte, mode os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(data) {
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() == mode {
			return nil
		}
	}
	return writeFile(path, data, mode)
}

// writePamStack adds the operator-file policy on top of writeFile: a
// read-only file that differs is kept with a warning (mirroring
// smb.conf/krb5.conf), while a missing/unwritable file is fatal.
func writePamStack(path, content string) error {
	if err := writeFile(path, []byte(content), 0o644); err == nil {
		return nil
	} else {
		existing, readErr := os.ReadFile(path)
		if readErr == nil && string(existing) == content {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("pamstack: cannot write %s: %w", path, err)
		}
		log.Printf("WARNING: %s is not writable and differs from the generated PAM stack. "+
			"The operator-managed file wins; Basic authentication may fail until it matches.", path)
		return nil
	}
}
