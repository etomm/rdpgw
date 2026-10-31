package provisioning

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

const (
	// winbinddPrivGroup owns /var/lib/samba/winbindd_privileged so ntlm_auth
	// can reach winbindd's privileged pipe.
	winbinddPrivGroup = "winbindd_priv"
	// secretsLDBInit is the minimal valid LDB header samba needs to open the
	// file instead of failing its module checks on an empty one.
	secretsLDBInit = "dn: @ATTRIBUTES\n\n"
	ldbaddBinary   = "ldbadd"
)

// sambaState prepares the samba runtime directories and secrets.ldb that
// winbindd and "net ads join" expect. It replaces the filesystem block of the
// old run-auth-winbind.sh entrypoint.
type sambaState struct {
	SmbConf    string
	RunDir     string
	PrivDir    string
	PrivateDir string
	LockDir    string
	CoresDir   string
	CacheDir   string
	LogDir     string
	SecretsLDB string

	// Injectable for tests (the daemon itself runs as root in the image).
	chown       func(name string, uid, gid int) error
	lookupGroup func(name string) (*user.Group, error)
	lookPath    func(file string) (string, error)
}

func defaultSambaState() *sambaState {
	return &sambaState{
		SmbConf:     defaultSmbTarget,
		RunDir:      "/run/samba",
		PrivDir:     "/var/lib/samba/winbindd_privileged",
		PrivateDir:  "/var/lib/samba/private",
		LockDir:     "/var/lib/samba/lock",
		CoresDir:    "/var/lib/samba/cores",
		CacheDir:    "/var/cache/samba",
		LogDir:      "/var/log/samba",
		SecretsLDB:  "/var/lib/samba/private/secrets.ldb",
		chown:       os.Chown,
		lookupGroup: user.LookupGroup,
		lookPath:    exec.LookPath,
	}
}

// prepareSambaState is a variable so tests can observe Provision's
// managed-versus-host-provided branch. It prepares the Samba runtime
// directories and secrets.ldb that winbindd and "net ads join" expect.
var prepareSambaState = func() error {
	return defaultSambaState().prepare()
}

func (s *sambaState) prepare() error {
	if _, err := os.Stat(s.SmbConf); err != nil {
		return fmt.Errorf("samba: %s is missing (provisioning did not create it): %w", s.SmbConf, err)
	}

	for _, dir := range []string{
		s.RunDir, s.PrivDir, s.PrivateDir, s.LockDir, s.CoresDir, s.CacheDir, s.LogDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("samba: cannot create %s: %w", dir, err)
		}
	}

	// The private directory holds the machine account secrets: root only.
	if err := s.chown(s.PrivateDir, 0, 0); err != nil {
		return fmt.Errorf("samba: cannot chown %s to root: %w", s.PrivateDir, err)
	}
	if err := os.Chmod(s.PrivateDir, 0o700); err != nil {
		return fmt.Errorf("samba: cannot chmod %s: %w", s.PrivateDir, err)
	}

	// winbindd creates its privileged pipe here; ntlm_auth (spawned by the
	// daemon) must be able to reach it through the group.
	if group, err := s.lookupGroup(winbinddPrivGroup); err != nil {
		log.Printf("Samba: group %s not found, leaving %s ownership unchanged", winbinddPrivGroup, s.PrivDir)
	} else {
		gid, convErr := strconv.Atoi(group.Gid)
		if convErr != nil {
			return fmt.Errorf("samba: invalid gid %q for group %s", group.Gid, winbinddPrivGroup)
		}
		if err := s.chown(s.PrivDir, 0, gid); err != nil {
			return fmt.Errorf("samba: cannot chown %s to root:%s: %w", s.PrivDir, winbinddPrivGroup, err)
		}
	}
	if err := os.Chmod(s.PrivDir, 0o750); err != nil {
		return fmt.Errorf("samba: cannot chmod %s: %w", s.PrivDir, err)
	}

	return s.ensureSecretsLDB()
}

// ensureSecretsLDB creates an empty secrets.ldb when the volume does not
// carry one yet, using ldbadd (which writes a valid LDB) and falling back to
// a plain file when ldb-tools is unavailable.
func (s *sambaState) ensureSecretsLDB() error {
	if _, err := os.Stat(s.SecretsLDB); err == nil {
		return nil
	}

	if path, err := s.lookPath(ldbaddBinary); err == nil {
		cmd := exec.Command(path, "-H", s.SecretsLDB)
		cmd.Stdin = strings.NewReader(secretsLDBInit)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Samba: ldbadd could not initialize %s: %v (%s); creating an empty file instead",
				s.SecretsLDB, err, strings.TrimSpace(string(out)))
		} else if _, statErr := os.Stat(s.SecretsLDB); statErr == nil {
			return nil
		}
	}

	f, err := os.OpenFile(s.SecretsLDB, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("samba: cannot create %s: %w", s.SecretsLDB, err)
	}
	return f.Close()
}
