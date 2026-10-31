package join

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	sigyaml "sigs.k8s.io/yaml"
)

const (
	// klistBinary lists the principals in the shared keytab.
	klistBinary = "klist"

	// spnPollInterval is how often a missing SPN is re-checked (the legacy
	// wrapper used 5s as well).
	spnPollInterval = 5 * time.Second

	// KERBEROS_SPNS is the legacy, comma/space separated SPN list.
	kerberosSPNsEnv = "KERBEROS_SPNS"
	// RDPGW_CONF points at the gateway configuration used to derive the
	// HTTP/<GatewayAddress> SPN.
	rdpgwConfigEnv   = "RDPGW_CONF"
	defaultRDPGWConf = "/opt/rdpgw/rdpgw.yaml"
)

// runOutput executes a command and returns its combined output. Replaced in
// tests.
var runOutput = func(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// SPNManager owns the shared keytab: it refreshes it, registers the configured
// SPNs with the join credentials when available and otherwise waits (with
// operator instructions) until the SPN appears in the keytab. It replaces the
// keytab/SPN block of run-auth-winbind.sh (Milestone 3).
type SPNManager struct {
	enabled bool
	conf    config.Configuration
	keytab  string
	spns    []string

	poll time.Duration
	run  func(context.Context, string, ...string) (string, error)
	env  func(string) string
}

func NewSPNManager(conf config.Configuration) *SPNManager {
	m := &SPNManager{
		conf: conf,
		poll: spnPollInterval,
		run:  runOutput,
		env:  os.Getenv,
	}
	if conf.AuthProtocols == nil || conf.AuthProtocols.Kerberos == nil ||
		!conf.AuthProtocols.Kerberos.Share {
		// No shared keytab in this deployment: nothing to create or check.
		return m
	}
	m.enabled = true
	m.keytab = conf.AuthProtocols.Kerberos.KeytabPath
	if m.keytab == "" {
		m.keytab = config.DefaultSharedKeytab
	}

	var spns []string
	spns = append(spns, conf.AuthProtocols.Kerberos.Spns...)
	spns = append(spns, splitList(m.env(kerberosSPNsEnv))...)
	if gateway := gatewaySPN(m.env(rdpgwConfigEnv)); gateway != "" {
		spns = append(spns, gateway)
	}
	m.spns = dedupeNonEmpty(spns)
	return m
}

// EnsureSPNs refreshes the keytab, verifies every configured SPN and waits
// for missing ones. A nil error means the keytab is ready for the gateway.
func (m *SPNManager) EnsureSPNs(ctx context.Context) error {
	if !m.enabled {
		return nil
	}
	user, password := m.env(adJoinUserEnv), m.env(adJoinPasswordEnv)
	haveCredentials := user != "" && password != ""

	// Populate the keytab right after the join; failures are not fatal, the
	// per-SPN checks below report what is actually missing.
	m.refreshKeytab(ctx)

	for _, spn := range m.spns {
		if m.hasSPN(ctx, spn) {
			log.Printf("SPN: verified %s in %s", spn, m.keytab)
			continue
		}

		log.Printf("SPN: %s is missing from %s", spn, m.keytab)
		if haveCredentials {
			log.Printf("SPN: registering %s with %s", spn, user)
			if _, err := m.run(ctx, netBinary, "ads", "setspn", "add", spn, "-U", user+"%"+password); err != nil {
				log.Printf("SPN: net ads setspn add %s failed: %v", spn, err)
			}
			m.refreshKeytab(ctx)
		}

		if err := m.waitForSPN(ctx, spn, haveCredentials); err != nil {
			return err
		}
	}

	m.ensureKeytabPermissions()
	return nil
}

func (m *SPNManager) refreshKeytab(ctx context.Context) {
	if out, err := m.run(ctx, netBinary, "ads", "keytab", "create", "-P"); err != nil {
		log.Printf("SPN: net ads keytab create -P failed: %v (%s)", err, strings.TrimSpace(out))
	}
}

func (m *SPNManager) hasSPN(ctx context.Context, spn string) bool {
	out, err := m.run(ctx, klistBinary, "-k", m.keytab)
	if err != nil {
		return false
	}
	return strings.Contains(out, spn)
}

// waitForSPN blocks until the SPN shows up in the keytab. The legacy wrapper
// waited indefinitely (logging instructions every 5s); SIGTERM cancels it.
func (m *SPNManager) waitForSPN(ctx context.Context, spn string, haveCredentials bool) error {
	log.Printf("SPN: waiting for %s to appear in %s", spn, m.keytab)
	m.logManualInstructions(spn)

	ticker := time.NewTicker(m.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SPN: waiting for %s in %s: %w", spn, m.keytab, ctx.Err())
		case <-ticker.C:
		}

		if m.hasSPN(ctx, spn) {
			log.Printf("SPN: %s is now present in %s", spn, m.keytab)
			return nil
		}
		if haveCredentials {
			m.refreshKeytab(ctx)
		}
		m.logManualInstructions(spn)
	}
}

func (m *SPNManager) logManualInstructions(spn string) {
	workgroup, hostname := "", ""
	if m.conf.Winbind != nil {
		workgroup, hostname = m.conf.Winbind.Workgroup, m.conf.Winbind.Hostname
	}
	if workgroup == "" {
		workgroup = "DOMAIN"
	}
	if hostname == "" {
		hostname = "COMPUTER"
	}
	log.Printf("SPN: register it on a Windows DC:  setspn -A %s %s\\%s$", spn, workgroup, hostname)
	log.Printf("SPN: or inside this container:       net ads setspn add %s -U Administrator", spn)
	log.Printf("SPN: then run:                      net ads keytab create -P")
}

func (m *SPNManager) ensureKeytabPermissions() {
	info, err := os.Stat(m.keytab)
	if err != nil {
		log.Printf("SPN: WARNING: keytab %s not found", m.keytab)
		return
	}
	if info.Mode().Perm() == 0o644 {
		return
	}
	// The gateway container reads the keytab through the shared volume.
	if err := os.Chmod(m.keytab, 0o644); err != nil {
		log.Printf("SPN: cannot chmod %s to 0644: %v", m.keytab, err)
	}
}

// gatewaySPN derives HTTP/<host> from the gateway's configured address,
// keeping the legacy wrapper's rule: the scheme, port and path are dropped,
// and loopback addresses are ignored.
func gatewaySPN(configPath string) string {
	if configPath == "" {
		configPath = defaultRDPGWConf
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var doc map[string]any
	if err := sigyaml.Unmarshal(data, &doc); err != nil {
		log.Printf("SPN: cannot parse %s: %v", configPath, err)
		return ""
	}
	host := hostFromGateway(nestedString(doc, "server", "gatewayaddress"))
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return ""
	}
	return "HTTP/" + host
}

// nestedString walks a decoded YAML document case-insensitively.
func nestedString(doc map[string]any, path ...string) string {
	var current any = doc
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		var found any
		for k, v := range m {
			if strings.EqualFold(k, key) {
				found = v
				break
			}
		}
		if found == nil {
			return ""
		}
		current = found
	}
	s, _ := current.(string)
	return s
}

// hostFromGateway strips scheme, userinfo, port and path from the configured
// gateway address.
func hostFromGateway(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return strings.Trim(s, "[]")
}

func splitList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func dedupeNonEmpty(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
