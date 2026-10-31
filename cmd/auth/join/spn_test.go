package join

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

func TestNewSPNManagerDisabledWithoutKerberosShare(t *testing.T) {
	m := NewSPNManager(config.Configuration{
		AuthProtocols: &config.AuthProtocolsConfig{
			Ntlm: &config.NtlmProtocolConfig{Enabled: true, Backends: []string{config.NtlmBackendWinbind}},
		},
	})
	if m.enabled {
		t.Fatal("SPN manager must be disabled without a Kerberos keytab share")
	}
	if err := m.EnsureSPNs(context.Background()); err != nil {
		t.Fatalf("EnsureSPNs: %v", err)
	}
}

func TestNewSPNManagerCollectsSPNs(t *testing.T) {
	dir := t.TempDir()
	gateway := filepath.Join(dir, "rdpgw.yaml")
	if err := os.WriteFile(gateway, []byte("server:\n  gatewayaddress: https://rdpgw.example.com:8443/path\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(kerberosSPNsEnv, "HTTP/env.example.com, HTTP/rdpgw.example.com")
	t.Setenv(rdpgwConfigEnv, gateway)

	m := NewSPNManager(config.Configuration{
		AuthProtocols: &config.AuthProtocolsConfig{
			Kerberos: &config.KerberosProtocolConfig{
				Share:      true,
				KeytabPath: "/var/lib/samba/rdpgw.keytab",
				Spns:       []string{"HTTP/auth.example.com", "HTTP/env.example.com"},
			},
		},
	})
	if !m.enabled {
		t.Fatal("SPN manager must be enabled with a Kerberos share")
	}
	if m.keytab != "/var/lib/samba/rdpgw.keytab" {
		t.Errorf("keytab = %q", m.keytab)
	}
	want := []string{
		"HTTP/auth.example.com",
		"HTTP/env.example.com",
		"HTTP/rdpgw.example.com", // from the gateway address
	}
	if strings.Join(m.spns, " ") != strings.Join(want, " ") {
		t.Errorf("spns = %v, want %v (deduplicated)", m.spns, want)
	}
}

func TestGatewaySPN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{"lowercase with scheme port and path", "server:\n  gatewayaddress: https://rdpgw.example.com:8443/ui/\n", "HTTP/rdpgw.example.com"},
		{"mixed case without scheme", "Server:\n  GatewayAddress: rdpgw.example.com\n", "HTTP/rdpgw.example.com"},
		{"localhost ignored", "server:\n  gatewayaddress: http://localhost:8080\n", ""},
		{"loopback ignored", "server:\n  gatewayaddress: 127.0.0.1\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rdpgw.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := gatewaySPN(path); got != tc.want {
				t.Errorf("gatewaySPN = %q, want %q", got, tc.want)
			}
		})
	}
	if got := gatewaySPN(filepath.Join(t.TempDir(), "missing.yaml")); got != "" {
		t.Errorf("missing gateway config = %q, want empty", got)
	}
}

func TestEnsureSPNsAllPresent(t *testing.T) {
	var klistCalls, keytabCreates, setspnCalls int32
	m := &SPNManager{
		enabled: true,
		keytab:  filepath.Join(t.TempDir(), "rdpgw.keytab"),
		spns:    []string{"HTTP/a.example.com", "HTTP/b.example.com"},
		poll:    time.Millisecond,
		env:     func(string) string { return "" },
		run: func(_ context.Context, name string, args ...string) (string, error) {
			switch {
			case name == klistBinary:
				atomic.AddInt32(&klistCalls, 1)
				return "Principal HTTP/a.example.com\nPrincipal HTTP/b.example.com\n", nil
			case name == netBinary && len(args) > 1 && args[1] == "keytab":
				atomic.AddInt32(&keytabCreates, 1)
				return "", nil
			case name == netBinary && len(args) > 1 && args[1] == "setspn":
				atomic.AddInt32(&setspnCalls, 1)
				return "", nil
			}
			return "", errors.New("unexpected command")
		},
	}

	if err := m.EnsureSPNs(context.Background()); err != nil {
		t.Fatalf("EnsureSPNs: %v", err)
	}
	if got := atomic.LoadInt32(&klistCalls); got != 2 {
		t.Errorf("klist calls = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&keytabCreates); got != 1 {
		t.Errorf("keytab create calls = %d, want the initial refresh", got)
	}
	if got := atomic.LoadInt32(&setspnCalls); got != 0 {
		t.Errorf("setspn calls = %d, want 0 when every SPN is present", got)
	}
}

func TestEnsureSPNsRegistersMissingWithCredentials(t *testing.T) {
	var present atomic.Bool
	var setspn string
	m := &SPNManager{
		enabled: true,
		keytab:  filepath.Join(t.TempDir(), "rdpgw.keytab"),
		spns:    []string{"HTTP/web.example.com"},
		poll:    time.Millisecond,
		env: func(key string) string {
			switch key {
			case adJoinUserEnv:
				return "svc-join"
			case adJoinPasswordEnv:
				return "s3cret"
			}
			return ""
		},
		run: func(_ context.Context, name string, args ...string) (string, error) {
			switch {
			case name == klistBinary:
				if present.Load() {
					return "Principal HTTP/web.example.com\n", nil
				}
				return "", errors.New("not in keytab")
			case name == netBinary && len(args) > 1 && args[1] == "keytab":
				return "", nil
			case name == netBinary && len(args) > 1 && args[1] == "setspn":
				setspn = strings.Join(args, " ")
				present.Store(true)
				return "", nil
			}
			return "", errors.New("unexpected command")
		},
	}

	if err := m.EnsureSPNs(context.Background()); err != nil {
		t.Fatalf("EnsureSPNs: %v", err)
	}
	if !strings.Contains(setspn, "add HTTP/web.example.com -U svc-join%s3cret") {
		t.Errorf("setspn call = %q, want the configured credentials", setspn)
	}
}

func TestEnsureSPNsWaitsForManualRegistration(t *testing.T) {
	var setspnCalls int32
	m := &SPNManager{
		enabled: true,
		keytab:  filepath.Join(t.TempDir(), "rdpgw.keytab"),
		spns:    []string{"HTTP/web.example.com"},
		poll:    5 * time.Millisecond,
		env:     func(string) string { return "" },
		run: func(_ context.Context, name string, args ...string) (string, error) {
			switch {
			case name == klistBinary:
				return "", errors.New("not in keytab")
			case name == netBinary && len(args) > 1 && args[1] == "keytab":
				return "", nil
			case name == netBinary && len(args) > 1 && args[1] == "setspn":
				atomic.AddInt32(&setspnCalls, 1)
				return "", nil
			}
			return "", errors.New("unexpected command")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := m.EnsureSPNs(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EnsureSPNs = %v, want context deadline exceeded", err)
	}
	if got := atomic.LoadInt32(&setspnCalls); got != 0 {
		t.Errorf("setspn calls = %d, want 0 without credentials", got)
	}
}

func TestEnsureKeytabPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rdpgw.keytab")
	if err := os.WriteFile(path, []byte("keytab"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &SPNManager{keytab: path}
	m.ensureKeytabPermissions()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("keytab mode = %o, want 0644", got)
	}
}
