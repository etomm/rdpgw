package pamstack

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

func testPaths(dir string) Paths {
	return Paths{
		PamFile:        filepath.Join(dir, "pam.d", "rdpgw"),
		UsersFile:      filepath.Join(dir, "users.pwd"),
		LdapConfDir:    dir,
		SessionManager: filepath.Join(dir, "session_manager.sh"),
	}
}

func testConf() config.Configuration {
	return config.Configuration{
		Users: []config.UserConfig{{Username: "alice", Password: "s3cret"}},
		Ldap: config.LdapProfiles{"corp": {
			Name:   "corp",
			Host:   "ldap.example.com",
			Port:   636,
			TLS:    true,
			Base:   "dc=example,dc=com",
			BindDN: "cn=readonly,dc=example,dc=com",
			BindPW: "bind-secret",
		}},
		Oath: config.OathProfiles{"totp": {Name: "totp", UsersFile: "/etc/users.oath", Window: 30}},
		AuthProtocols: &config.AuthProtocolsConfig{
			Basic: &config.BasicProtocolConfig{
				Enabled: true,
				Stack: []config.BasicStackEntry{
					{Backend: config.BasicBackendWinbind, Oath: "totp"},
					{Backend: config.BasicBackendLdap, Name: "corp"},
					{Backend: config.BasicBackendUsers},
				},
			},
		},
	}
}

func TestGenerateStack(t *testing.T) {
	paths := testPaths("/runtime")
	got, err := Generate(testConf(), paths)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for _, want := range []string{
		"# Backend order: winbind -> ldap -> users",
		"auth [success=ok default=2] pam_oath.so usersfile=/etc/users.oath window=30",
		"auth [success=ok default=1] pam_winbind.so",
		"auth [success=done default=die] pam_exec.so /runtime/session_manager.sh create winbind",
		"auth [success=ok default=1] pam_ldap.so config=/runtime/ldap-corp.conf",
		"auth [success=done default=die] pam_exec.so /runtime/session_manager.sh create ldap/corp",
		"auth [success=ok default=1] pam_pwdfile.so pwdfile=/runtime/users.pwd",
		"auth [success=done default=die] pam_exec.so /runtime/session_manager.sh create users",
		"auth required pam_deny.so",
		"account [success=ok default=2] pam_exec.so quiet /runtime/session_manager.sh check winbind",
		"account [success=ok default=die] pam_permit.so",
		"account [success=done default=done] pam_exec.so quiet /runtime/session_manager.sh cleanup",
		"account [success=ok default=die] pam_permit.so",
		"account required pam_deny.so",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated stack missing %q:\n%s", want, got)
		}
	}

	if n := strings.Count(got, "pam_oath.so"); n != 1 {
		t.Errorf("pam_oath lines = %d, want 1 (only the winbind block)", n)
	}
	if strings.Contains(got, "krb5_auth") {
		t.Errorf("pam_winbind must not use krb5_auth without NSS winbind support:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "account ") && strings.Contains(line, "pam_winbind.so") {
			t.Errorf("pam_winbind account phase needs NSS winbind, which the image lacks: %q", line)
		}
	}
	if strings.Index(got, "create winbind") > strings.Index(got, "create ldap/corp") ||
		strings.Index(got, "create ldap/corp") > strings.Index(got, "create users") {
		t.Errorf("backend blocks are not in the configured order:\n%s", got)
	}
	if strings.Contains(got, "PAM_USER") {
		t.Errorf("generated stack leaks template text:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, paths.SessionManager) && !strings.Contains(line, "pam_exec.so") {
			t.Errorf("session manager line must go through pam_exec.so: %q", line)
		}
	}
	t.Logf("generated PAM stack:\n%s", got)
}

func TestGenerateDisabled(t *testing.T) {
	conf := testConf()
	conf.AuthProtocols.Basic.Enabled = false
	got, err := Generate(conf, testPaths(t.TempDir()))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got != "" {
		t.Errorf("disabled Basic must generate nothing, got:\n%s", got)
	}
}

func TestGenerateRejectsUnknownBackend(t *testing.T) {
	conf := testConf()
	conf.AuthProtocols.Basic.Stack = []config.BasicStackEntry{{Backend: "pam"}}
	if _, err := Generate(conf, testPaths(t.TempDir())); err == nil {
		t.Fatal("unknown backend must fail generation")
	}
}

func TestGenerateUsersPwd(t *testing.T) {
	data, err := GenerateUsersPwd([]config.UserConfig{{Username: "alice", Password: "s3cret"}})
	if err != nil {
		t.Fatalf("GenerateUsersPwd: %v", err)
	}
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 || parts[0] != "alice" {
		t.Fatalf("users.pwd line = %q, want alice:<hash>", line)
	}
	if !strings.HasPrefix(parts[1], "$6$") {
		t.Errorf("hash = %q, want a SHA-512 crypt ($6$) hash", parts[1])
	}
	crypt := sha512_crypt.New()
	if err := crypt.Verify(parts[1], []byte("s3cret")); err != nil {
		t.Errorf("generated hash does not verify: %v", err)
	}
	if err := crypt.Verify(parts[1], []byte("wrong")); err == nil {
		t.Error("wrong password verified against the generated hash")
	}
	if strings.Contains(string(data), "s3cret") {
		t.Error("users.pwd contains the clear-text password")
	}
}

func TestInstallWritesAllCompanions(t *testing.T) {
	dir := t.TempDir()
	paths := testPaths(dir)
	if err := Install(testConf(), paths, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}

	pam, err := os.ReadFile(paths.PamFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pam), "auth [success=done default=die] pam_exec.so "+paths.SessionManager+" create winbind") {
		t.Errorf("pam file does not reference the session manager:\n%s", pam)
	}

	assertMode(t, paths.UsersFile, 0o600)
	users, err := os.ReadFile(paths.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(users)), "alice:$6$") {
		t.Errorf("users.pwd = %q", users)
	}

	assertMode(t, paths.SessionManager, 0o755)

	ldapConf := filepath.Join(dir, "ldap-corp.conf")
	assertMode(t, ldapConf, 0o600)
	ldapBody, err := os.ReadFile(ldapConf)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"host ldap.example.com", "port 636", "base dc=example,dc=com", "binddn cn=readonly,dc=example,dc=com", "bindpw bind-secret", "ssl on"} {
		if !strings.Contains(string(ldapBody), want) {
			t.Errorf("ldap profile missing %q:\n%s", want, ldapBody)
		}
	}
}

func TestInstallSkipsUnusedCompanions(t *testing.T) {
	// users.pwd and LDAP profiles are only generated for backends that are
	// actually in the stack.
	dir := t.TempDir()
	paths := testPaths(dir)
	conf := testConf()
	conf.AuthProtocols.Basic.Stack = []config.BasicStackEntry{{Backend: config.BasicBackendUnix}}
	conf.Ldap["unused"] = config.LdapConfig{Name: "unused", Host: "unused.example.com"}

	if err := Install(conf, paths, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(paths.UsersFile); !os.IsNotExist(err) {
		t.Errorf("users.pwd was generated without a users backend: %v", err)
	}
	for _, name := range []string{"corp", "unused"} {
		if _, err := os.Stat(filepath.Join(dir, "ldap-"+name+".conf")); !os.IsNotExist(err) {
			t.Errorf("LDAP profile %q was generated without an ldap stack entry: %v", name, err)
		}
	}
	if _, err := os.Stat(paths.PamFile); err != nil {
		t.Errorf("PAM stack missing: %v", err)
	}
}

func TestDefaultPathsUsesServiceName(t *testing.T) {
	if got := DefaultPaths("custom-service").PamFile; got != "/etc/pam.d/custom-service" {
		t.Errorf("PamFile = %q, want /etc/pam.d/custom-service", got)
	}
	if got := DefaultPaths("").PamFile; got != "/etc/pam.d/rdpgw" {
		t.Errorf("default PamFile = %q, want /etc/pam.d/rdpgw", got)
	}
}

func TestInstallEnforcesCompanionModes(t *testing.T) {
	// The companion files carry password hashes and bind credentials. On
	// restart their previous (possibly looser) modes must be tightened, not
	// left as os.WriteFile found them.
	dir := t.TempDir()
	paths := testPaths(dir)
	if err := os.MkdirAll(filepath.Dir(paths.PamFile), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{
		paths.UsersFile:                      0o666,
		paths.SessionManager:                 0o777,
		paths.PamFile:                        0o666,
		filepath.Join(dir, "ldap-corp.conf"): 0o666,
	} {
		if err := os.WriteFile(path, []byte("stale"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}

	if err := Install(testConf(), paths, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}

	assertMode(t, paths.UsersFile, 0o600)
	assertMode(t, paths.SessionManager, 0o755)
	assertMode(t, paths.PamFile, 0o644)
	assertMode(t, filepath.Join(dir, "ldap-corp.conf"), 0o600)
}

func TestInstallDisabledWritesNothing(t *testing.T) {
	dir := t.TempDir()
	conf := testConf()
	conf.AuthProtocols.Basic.Enabled = false
	if err := Install(conf, testPaths(dir), ""); err != nil {
		t.Fatalf("Install: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("disabled Basic wrote files: %v", entries)
	}
}

func TestSessionManagerScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "session_manager.sh")
	if err := os.WriteFile(script, sessionManagerScript, 0o755); err != nil {
		t.Fatal(err)
	}
	sessionDir := filepath.Join(dir, "sessions")
	run := func(sessionID string, args ...string) error {
		cmd := exec.Command(script, args...)
		env := append(os.Environ(), "RDPGW_PAM_SESSION_DIR="+sessionDir)
		if sessionID != "" {
			env = append(env, "RDPGW_SESSION_ID="+sessionID)
		}
		cmd.Env = env
		return cmd.Run()
	}

	const aliceSession = "11111111-1111-4111-8111-111111111111"
	const otherSession = "22222222-2222-4222-8222-222222222222"

	// The injected id is the only key: two sessions are independent. The
	// recorded value is the backend name; OATH only affects the auth phase.
	if err := run(aliceSession, "create", "winbind"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := run(aliceSession, "check", "winbind"); err != nil {
		t.Errorf("check the recorded backend: %v", err)
	}
	if err := run(aliceSession, "check", "users"); err == nil {
		t.Error("check must fail for a different backend")
	}
	if err := run(otherSession, "check", "winbind"); err == nil {
		t.Error("another session id must not inherit the state")
	}
	if err := run(aliceSession, "cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := run(aliceSession, "check", "winbind"); err == nil {
		t.Error("state must be gone after cleanup")
	}
	if err := run(aliceSession, "bogus"); err == nil {
		t.Error("unknown operation must fail")
	}

	// The key stays a single argument even when it contains '/'.
	if err := run(aliceSession, "create", "ldap/corp"); err != nil {
		t.Fatalf("create ldap/corp: %v", err)
	}
	if err := run(aliceSession, "check", "ldap/corp"); err != nil {
		t.Errorf("check ldap/corp: %v", err)
	}
	if err := run(aliceSession, "check", "ldap/other"); err == nil {
		t.Error("check must fail for a different Ldap profile")
	}
	if err := run(aliceSession, "cleanup"); err != nil {
		t.Fatalf("cleanup ldap/corp: %v", err)
	}

	// No username fallback: a missing id fails every operation.
	for _, args := range [][]string{{"create", "users"}, {"check", "users"}, {"cleanup"}} {
		if err := run("", args...); err == nil {
			t.Errorf("%v without RDPGW_SESSION_ID must fail", args)
		}
	}

	// State whose cleanup never ran is pruned by the next create.
	stale := filepath.Join(sessionDir, "stale")
	if err := os.WriteFile(stale, []byte("winbind\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := run(aliceSession, "create", "users"); err != nil {
		t.Fatalf("create after stale state: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale session state was not pruned: %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}

func TestGenerateResolvedStackEntry(t *testing.T) {
	conf := testConf()
	conf.AuthProtocols.Basic.Stack = []config.BasicStackEntry{{
		Backend: config.BasicBackendLdap,
		Name:    "corp",
		Oath:    "totp",
	}}

	got, err := Generate(conf, testPaths("/runtime"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		"auth [success=ok default=2] pam_oath.so usersfile=/etc/users.oath window=30",
		"auth [success=ok default=1] pam_ldap.so config=/runtime/ldap-corp.conf",
		"create ldap/corp",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("resolved named entry missing %q:\n%s", want, got)
		}
	}
}

func TestGenerateCollapsesAccountBlocks(t *testing.T) {
	conf := testConf()
	conf.AuthProtocols.Basic.Stack = []config.BasicStackEntry{
		{Backend: config.BasicBackendUsers, Oath: "totp"},
		{Backend: config.BasicBackendUsers},
	}

	got, err := Generate(conf, testPaths("/runtime"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if n := strings.Count(got, "session_manager.sh create users"); n != 2 {
		t.Errorf("create users lines = %d, want 2 auth blocks:\n%s", n, got)
	}
	if n := strings.Count(got, "session_manager.sh check users"); n != 1 {
		t.Errorf("check users lines = %d, want one collapsed account block:\n%s", n, got)
	}
	if n := strings.Count(got, "session_manager.sh cleanup"); n != 1 {
		t.Errorf("cleanup lines = %d, want one collapsed account block:\n%s", n, got)
	}
}

func TestGenerateKeepsDistinctLdapAccountBlocks(t *testing.T) {
	conf := testConf()
	conf.Ldap["other"] = config.LdapConfig{Name: "other", Host: "ldap2.example.com"}
	conf.AuthProtocols.Basic.Stack = []config.BasicStackEntry{
		{Backend: config.BasicBackendLdap, Name: "corp", Oath: "totp"},
		{Backend: config.BasicBackendLdap, Name: "corp"},
		{Backend: config.BasicBackendLdap, Name: "other"},
	}

	got, err := Generate(conf, testPaths("/runtime"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, tc := range []struct {
		needle string
		want   int
	}{
		{"create ldap/corp", 2}, // two auth blocks: with and without OATH
		{"check ldap/corp", 1},  // collapsed account block
		{"create ldap/other", 1},
		{"check ldap/other", 1}, // different profile, different account check
	} {
		if n := strings.Count(got, tc.needle); n != tc.want {
			t.Errorf("%q lines = %d, want %d:\n%s", tc.needle, n, tc.want, got)
		}
	}
}
