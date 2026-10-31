package provisioning

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// testSambaState builds a sambaState rooted in a temporary directory with
// injectable ownership calls (the tests may not run as root).
func testSambaState(t *testing.T) (*sambaState, *[]string) {
	t.Helper()
	dir := t.TempDir()
	smbConf := filepath.Join(dir, "smb.conf")
	if err := os.WriteFile(smbConf, []byte("[global]\n    security = ads\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var chowns []string
	s := &sambaState{
		SmbConf:     smbConf,
		RunDir:      filepath.Join(dir, "run-samba"),
		PrivDir:     filepath.Join(dir, "winbindd_privileged"),
		PrivateDir:  filepath.Join(dir, "private"),
		LockDir:     filepath.Join(dir, "lock"),
		CoresDir:    filepath.Join(dir, "cores"),
		CacheDir:    filepath.Join(dir, "cache"),
		LogDir:      filepath.Join(dir, "log"),
		SecretsLDB:  filepath.Join(dir, "private", "secrets.ldb"),
		lookPath:    func(string) (string, error) { return "", os.ErrNotExist },
		lookupGroup: func(string) (*user.Group, error) { return &user.Group{Name: winbinddPrivGroup, Gid: "4242"}, nil },
		chown: func(name string, uid, gid int) error {
			chowns = append(chowns, name)
			return nil
		},
	}
	return s, &chowns
}

func TestPrepareSambaStateCreatesLayout(t *testing.T) {
	s, chowns := testSambaState(t)
	if err := s.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	for _, dir := range []string{s.RunDir, s.PrivDir, s.PrivateDir, s.LockDir, s.CoresDir, s.CacheDir, s.LogDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %s was not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}
	assertPerm(t, s.PrivateDir, 0o700)
	assertPerm(t, s.PrivDir, 0o750)

	if len(*chowns) != 2 {
		t.Errorf("chown calls = %v, want private and privileged directories", *chowns)
	}

	if _, err := os.Stat(s.SecretsLDB); err != nil {
		t.Errorf("secrets.ldb was not created: %v", err)
	}
}

func TestPrepareSambaStateKeepsExistingSecrets(t *testing.T) {
	s, _ := testSambaState(t)
	if err := os.MkdirAll(s.PrivateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const content = "existing-secrets"
	if err := os.WriteFile(s.SecretsLDB, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got, err := os.ReadFile(s.SecretsLDB)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("secrets.ldb was modified: %q", got)
	}
}

func TestPrepareSambaStateMissingSmbConf(t *testing.T) {
	s, _ := testSambaState(t)
	s.SmbConf = filepath.Join(t.TempDir(), "missing.conf")
	if err := s.prepare(); err == nil {
		t.Fatal("a missing smb.conf must fail")
	}
}

func TestPrepareSambaStateMissingGroupTolerated(t *testing.T) {
	s, _ := testSambaState(t)
	s.lookupGroup = func(string) (*user.Group, error) { return nil, os.ErrNotExist }
	if err := s.prepare(); err != nil {
		t.Fatalf("a missing winbindd_priv group must not fail: %v", err)
	}
	if _, err := os.Stat(s.PrivDir); err != nil {
		t.Errorf("privileged directory was not created: %v", err)
	}
}

func TestPrepareSambaStateInvalidGID(t *testing.T) {
	s, _ := testSambaState(t)
	s.lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "not-a-number"}, nil }
	if err := s.prepare(); err == nil {
		t.Fatal("an invalid winbindd_priv gid must fail")
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}
