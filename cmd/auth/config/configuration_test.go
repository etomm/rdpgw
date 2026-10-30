package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func toJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func TestLoadDefaultsToUsersBackend(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Users:
  - Username: alice
    Password: secret
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults should be preloaded with users backend
	if c.AuthProtocols == nil || c.AuthProtocols.Ntlm == nil || !c.AuthProtocols.Ntlm.Enabled {
		t.Errorf("expected NTLM backend enabled, got %+v", c.AuthProtocols)
	}
	if len(c.AuthProtocols.Ntlm.Backends) != 1 || c.AuthProtocols.Ntlm.Backends[0] != NtlmBackendUsers {
		t.Errorf("unexpected NTLM backends: %v", c.AuthProtocols.Ntlm.Backends)
	}
	if len(c.Users) != 1 || c.Users[0].Username != "alice" || c.Users[0].Password != "secret" {
		t.Errorf("unexpected users: %+v", c.Users)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// File missing → defaults loaded: authprotocols.ntlm.enabled=true, backends=[users]
	if c.AuthProtocols == nil || c.AuthProtocols.Ntlm == nil || !c.AuthProtocols.Ntlm.Enabled {
		t.Errorf("expected NTLM backend enabled from defaults, got %+v", c.AuthProtocols)
	}
	if len(c.AuthProtocols.Ntlm.Backends) != 1 || c.AuthProtocols.Ntlm.Backends[0] != NtlmBackendUsers {
		t.Errorf("unexpected NTLM backends from defaults: %v", c.AuthProtocols.Ntlm.Backends)
	}
	if len(c.Users) != 0 {
		t.Errorf("unexpected users: %+v", c.Users)
	}
}

func TestLoadLegacyWinbind(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: `+helper+`
    Domain: EXAMPLE
    RequireMembershipOf: "EXAMPLE\\RDP Users"
    Timeout: 3
    StripDomain: true
    Separator: "+"
    Spns:
      - HTTP/rdpgw.example.com
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := Configuration{
		Winbind: &WinbindConfig{
			NtlmAuthPath:        helper,
			Workgroup:           "EXAMPLE",
			RequireMembershipOf: `EXAMPLE\RDP Users`,
			Timeout:             3,
			StripDomain:         true,
			Separator:           "+",
			Spns:                []string{"HTTP/rdpgw.example.com"},
		},
		AuthProtocols: &AuthProtocolsConfig{
			Kerberos: &KerberosProtocolConfig{
				Share:      true,
				KeytabPath: DefaultSharedKeytab,
			},
			Ntlm: &NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{NtlmBackendWinbind},
			},
		},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v, want backend winbind with %+v", toJSON(c), toJSON(want))
	}
}

func TestLoadModernWinbind(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: EXAMPLE
  Workgroup: CORP
  Timeout: 5
AuthProtocols:
  Ntlm:
    Enabled: true
    Backends:
      - winbind
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := Configuration{
		Winbind: &WinbindConfig{
			NtlmAuthPath: helper,
			Domain:       "EXAMPLE",
			Workgroup:    "CORP",
			Timeout:      5,
			StripDomain:  false,
			Separator:    "\\",
		},
		AuthProtocols: &AuthProtocolsConfig{
			Ntlm: &NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{NtlmBackendWinbind},
			},
		},
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got %+v, want backend winbind with %+v", toJSON(c), toJSON(want))
	}
}

func TestNetBiosAutoDerivationAndLegacyMapping(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: "example.corp.local"
  Workgroup: "CORP"
AuthProtocols:
  Ntlm:
    Enabled: true
    Backends:
      - winbind
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Winbind == nil || c.Winbind.Workgroup != "CORP" {
		t.Errorf("Workgroup = %v, want CORP", c.Winbind)
	}
	// Just a winbind block alone does NOT auto-enable Kerberos share per spec.
	// Domain join is only enabled when ntlm.backend=winbind or kerberos.share=true.
	if c.AuthProtocols != nil && c.AuthProtocols.Kerberos != nil && c.AuthProtocols.Kerberos.Share {
		t.Errorf("unexpected Kerberos share enabled from winbind-only config, got %+v", c.AuthProtocols)
	}
}

func TestValidate(t *testing.T) {
	helper := writeFile(t, t.TempDir(), "ntlm_auth", "#!/bin/sh\n")
	nonExistentHelper := filepath.Join(t.TempDir(), "non", "existent", "ntlm_auth")
	cases := []struct {
		name    string
		cfg     Configuration
		wantErr string
	}{
		{"file", Configuration{AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendUsers}}}}, ""},
		{"winbind ok", Configuration{Winbind: &WinbindConfig{NtlmAuthPath: helper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendUsers}}}}, ""},
		{"unknown backend", Configuration{AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{"ldap"}}}}, "unknown AuthProtocols.Ntlm.Backends"},
		{"empty backend", Configuration{AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true}}}, "unknown AuthProtocols.Ntlm.Backends"},
		{"missing NtlmAuthPath path, but no winbind", Configuration{Winbind: &WinbindConfig{Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendUsers}}}}, ""},
		{"missing NtlmAuthPath path", Configuration{Winbind: &WinbindConfig{Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "NtlmAuthPath must be set"},
		{"nonexistent path", Configuration{Winbind: &WinbindConfig{NtlmAuthPath: nonExistentHelper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "is not usable"},
		{"zero timeout", Configuration{Winbind: &WinbindConfig{NtlmAuthPath: helper, Timeout: 0}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "Timeout must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cfg
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
