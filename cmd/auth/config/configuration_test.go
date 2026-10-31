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
Winbind:
  Domain: corp.example.com
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
			Domain:              "corp.example.com",
			NtlmAuthPath:        helper,
			Workgroup:           "EXAMPLE",
			RequireMembershipOf: `EXAMPLE\RDP Users`,
			Timeout:             3,
			StripDomain:         true,
			Separator:           SingleChar('+'),
		},
		AuthProtocols: &AuthProtocolsConfig{
			Kerberos: &KerberosProtocolConfig{
				Share:        true,
				KeytabPath:   DefaultSharedKeytab,
				Krb5ConfPath: DefaultSharedKrb5Conf,
				Spns:         []string{"HTTP/rdpgw.example.com"}, // moved out of the legacy winbind block
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

func TestLoadDerivesSharedKrb5ConfPath(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	tests := []struct {
		name       string
		kerberos   string
		wantKeytab string
		wantKrb5   string
	}{
		{
			name:       "keytab default",
			kerberos:   "Share: true",
			wantKeytab: DefaultSharedKeytab,
			wantKrb5:   DefaultSharedKrb5Conf,
		},
		{
			name: "custom keytab",
			kerberos: `Share: true
    KeytabPath: /srv/rdpgw/custom.keytab`,
			wantKeytab: "/srv/rdpgw/custom.keytab",
			wantKrb5:   "/srv/rdpgw/krb5.conf",
		},
		{
			name: "explicit krb5 path wins",
			kerberos: `Share: true
    KeytabPath: /srv/rdpgw/custom.keytab
    Krb5ConfPath: /etc/rdpgw/krb5.conf`,
			wantKeytab: "/srv/rdpgw/custom.keytab",
			wantKrb5:   "/etc/rdpgw/krb5.conf",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: corp.example.com
AuthProtocols:
  Kerberos:
    `+tc.kerberos+`
  Ntlm:
    Enabled: true
    Backends:
      - winbind
`)
			c, err := load(p)
			if err != nil {
				t.Fatal(err)
			}
			if c.AuthProtocols.Kerberos.KeytabPath != tc.wantKeytab {
				t.Errorf("KeytabPath = %q, want %q", c.AuthProtocols.Kerberos.KeytabPath, tc.wantKeytab)
			}
			if c.AuthProtocols.Kerberos.Krb5ConfPath != tc.wantKrb5 {
				t.Errorf("Krb5ConfPath = %q, want %q", c.AuthProtocols.Kerberos.Krb5ConfPath, tc.wantKrb5)
			}
		})
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
			Separator:    SingleChar('\\'),
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

func TestSingleCharDecoding(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    SingleChar
		wantErr string
	}{
		{"single backslash", `"\\"`, SingleChar('\\'), ""},
		{"single plus", `"+"`, SingleChar('+'), ""},
		{"empty falls back to default", `""`, 0, ""},
		{"two characters keep the first", `"++"`, SingleChar('+'), ""},
		{"two backslashes keep the first", `"\\\\"`, SingleChar('\\'), ""},
		{"control character falls back to default", `"\n"`, 0, ""},
		{"number is still rejected", `43`, 0, "single-character string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s SingleChar
			err := s.UnmarshalJSON([]byte(tc.raw))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantStr := ""
			if tc.want != 0 {
				wantStr = string(rune(tc.want))
			}
			if s != tc.want || s.String() != wantStr {
				t.Fatalf("SingleChar = %v (%q), want %v (%q)", s, s.String(), tc.want, wantStr)
			}
		})
	}
}

func TestLoadLegacySeparatorCarryOver(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  Domain: corp.example.com
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: `+helper+`
    Separator: "+"
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Winbind.Separator != SingleChar('+') {
		t.Errorf("legacy separator not carried over: got %q", c.Winbind.Separator.String())
	}
}

func TestLoadLegacyLongSeparatorTakesFirstChar(t *testing.T) {
	// Legacy YAML accepts any string. A long value must NOT fail the load:
	// a warning points at the original value and only the first character
	// is kept, so the daemon always starts with a usable separator.
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  Domain: corp.example.com
Ntlm:
  Backend: winbind
  Winbind:
    NtlmAuthPath: `+helper+`
    Separator: "++"
`)
	c, err := load(p)
	if err != nil {
		t.Fatalf("long legacy separator must not fail the load: %v", err)
	}
	if c.Winbind.Separator != SingleChar('+') {
		t.Errorf("separator = %q, want the first character '+'", c.Winbind.Separator.String())
	}
}

func TestFlexibleDomainControllersDecoding(t *testing.T) {
	// The documented list supports both entry shapes: plain host strings and
	// detailed host/port objects. sigs.k8s.io/yaml decodes through JSON, so
	// UnmarshalJSON is the contract that matters.
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: example.corp.local
  DomainControllers:
    - dc1.example.corp.local
    - host: dc2.example.corp.local
      port: 88
      adminPort: 749
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
	dcs := c.Winbind.DomainControllers
	if len(dcs) != 2 {
		t.Fatalf("domainControllers = %d entries, want 2", len(dcs))
	}
	if dcs[0].Host != "dc1.example.corp.local" || dcs[0].Port != DefaultKdcPort || dcs[0].AdminPort != DefaultKdcAdminPort {
		t.Errorf("bare string entry defaults wrong: %+v", dcs[0])
	}
	if dcs[1].Host != "dc2.example.corp.local" || dcs[1].Port != 88 || dcs[1].AdminPort != 749 {
		t.Errorf("object entry wrong: %+v", dcs[1])
	}
}

func TestLoadCanonicalCamelCaseKeys(t *testing.T) {
	// The documentation uses the canonical field names (Domain, KeytabPath,
	// Backends, ...). sigs.k8s.io/yaml decodes through encoding/json, which
	// matches struct tags case-insensitively; this keeps the docs valid.
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  Domain: example.com
  NtlmAuthPath: `+helper+`
  Timeout: 1
  AutoJoin: true
AuthProtocols:
  Kerberos:
    Share: true
    KeytabPath: /var/lib/samba/rdpgw.keytab
    Spns:
      - HTTP/rdpgw.example.com
  Ntlm:
    Enabled: true
    Backends:
      - users
Users:
  - Username: alice
    Password: secret
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Winbind.Domain != "example.com" || c.Winbind.Workgroup != "EXAMPLE" || !c.Winbind.AutoJoin {
		t.Errorf("Winbind = %+v", c.Winbind)
	}
	if !c.AuthProtocols.Kerberos.Share || c.AuthProtocols.Kerberos.KeytabPath != "/var/lib/samba/rdpgw.keytab" {
		t.Errorf("Kerberos = %+v", c.AuthProtocols.Kerberos)
	}
	if len(c.AuthProtocols.Ntlm.Backends) != 1 || c.AuthProtocols.Ntlm.Backends[0] != NtlmBackendUsers {
		t.Errorf("Ntlm = %+v", c.AuthProtocols.Ntlm)
	}
}

func TestLoadDefaultsSharedKeytabPath(t *testing.T) {
	// The keytab path has a documented default. Enabling the share without
	// specifying it must use DefaultSharedKeytab instead of failing
	// validation or rendering an empty smb.conf directive.
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: corp.example.com
AuthProtocols:
  Kerberos:
    Share: true
  Ntlm:
    Enabled: true
    Backends:
      - winbind
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthProtocols.Kerberos.KeytabPath != DefaultSharedKeytab {
		t.Errorf("KeytabPath = %q, want %q", c.AuthProtocols.Kerberos.KeytabPath, DefaultSharedKeytab)
	}
}

func TestLoadModernKerberosSpns(t *testing.T) {
	// SPNs belong to the Kerberos block: without a keytab share there is
	// nothing to register. The modern schema must accept them there.
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Domain: corp.example.com
AuthProtocols:
  Kerberos:
    Share: true
    KeytabPath: /var/lib/samba/rdpgw.keytab
    Spns:
      - HTTP/rdpgw.corp.example.com
      - HTTP/files.example.com
  Ntlm:
    Enabled: true
    Backends:
      - winbind
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthProtocols == nil || c.AuthProtocols.Kerberos == nil {
		t.Fatal("expected the Kerberos block to be parsed")
	}
	want := []string{
		"HTTP/rdpgw.corp.example.com",
		"HTTP/files.example.com",
	}
	if !reflect.DeepEqual(c.AuthProtocols.Kerberos.Spns, want) {
		t.Errorf("Spns = %v, want %v", c.AuthProtocols.Kerberos.Spns, want)
	}
}

func TestLoadModernBasicStack(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  NtlmAuthPath: `+helper+`
  Timeout: 5
  Domain: example.com
Users:
  - Username: alice
    Password: secret
Ldap:
  - Name: corp
    Host: ldap.example.com
    Port: 636
    TLS: true
    Base: dc=example,dc=com
Oath:
  - Name: totp
    UsersFile: /etc/users.oath
    Window: 30
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - Backend: winbind
        Oath: totp
      - Backend: ldap
        Name: corp
      - Backend: users
`)
	c, err := load(p)
	if err != nil {
		t.Fatal(err)
	}
	basic := c.AuthProtocols.Basic
	if basic == nil || !basic.Enabled {
		t.Fatalf("Basic protocol not loaded: %+v", c.AuthProtocols)
	}
	if len(basic.Stack) != 3 {
		t.Fatalf("stack = %+v, want 3 entries", basic.Stack)
	}
	if basic.Stack[0].Backend != BasicBackendWinbind || basic.Stack[0].Oath != "totp" {
		t.Errorf("first stack entry = %+v", basic.Stack[0])
	}
	if basic.Stack[1].Name != "corp" {
		t.Errorf("ldap entry = %+v", basic.Stack[1])
	}
	if len(c.Oath) != 1 || c.Oath["totp"].UsersFile != "/etc/users.oath" || c.Oath["totp"].Window != 30 {
		t.Errorf("oath profiles = %+v", c.Oath)
	}
	if len(c.Ldap) != 1 || c.Ldap["corp"].Host != "ldap.example.com" || !c.Ldap["corp"].TLS {
		t.Errorf("ldap profiles = %+v", c.Ldap)
	}
}

func TestValidateBasicStack(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	valid := func() Configuration {
		return Configuration{
			Winbind: &WinbindConfig{NtlmAuthPath: helper, Timeout: 1, Domain: "example.com", Workgroup: "EXAMPLE"},
			Users:   []UserConfig{{Username: "alice", Password: "secret"}},
			Ldap:    LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
			Oath:    OathProfiles{"totp": {Name: "totp", UsersFile: "/etc/users.oath"}},
			AuthProtocols: &AuthProtocolsConfig{
				Basic: &BasicProtocolConfig{
					Enabled: true,
					Stack: []BasicStackEntry{
						{Backend: BasicBackendWinbind, Oath: "totp"},
						{Backend: BasicBackendLdap, Name: "corp"},
						{Backend: BasicBackendUsers},
					},
				},
			},
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Configuration)
		want   string
	}{
		{"valid", func(*Configuration) {}, ""},
		{"unknown backend", func(c *Configuration) { c.AuthProtocols.Basic.Stack[0].Backend = "pam" }, "unknown AuthProtocols.Basic.Stack backend"},
		{"missing ldap profile", func(c *Configuration) { c.AuthProtocols.Basic.Stack[1].Name = "nope" }, "unknown Ldap"},
		{"missing oath profile", func(c *Configuration) { c.AuthProtocols.Basic.Stack[0].Oath = "nope" }, "unknown Oath"},
		{"users backend without users", func(c *Configuration) { c.Users = nil }, "Users is empty"},
		{"duplicate backend", func(c *Configuration) {
			c.AuthProtocols.Basic.Stack = []BasicStackEntry{{Backend: BasicBackendUnix}, {Backend: BasicBackendUnix}}
		}, "duplicate AuthProtocols.Basic.Stack entry"},
		{"winbind without config", func(c *Configuration) { c.Winbind = nil }, "Winbind must be configured"},
		{"empty stack", func(c *Configuration) { c.AuthProtocols.Basic.Stack = nil }, "Stack must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(&c)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateBasicOnlyStackNeedsNoWinbind(t *testing.T) {
	c := Configuration{
		AuthProtocols: &AuthProtocolsConfig{
			Basic: &BasicProtocolConfig{
				Enabled: true,
				Stack:   []BasicStackEntry{{Backend: BasicBackendUnix}},
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Basic-only unix stack must validate without Winbind: %v", err)
	}
}

func TestValidateProfiles(t *testing.T) {
	base := func() Configuration {
		return Configuration{
			Ldap: LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
			Oath: OathProfiles{"totp": {Name: "totp", UsersFile: "/etc/users.oath"}},
			AuthProtocols: &AuthProtocolsConfig{
				Basic: &BasicProtocolConfig{
					Enabled: true,
					Stack:   []BasicStackEntry{{Backend: BasicBackendUnix}},
				},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Configuration)
		want   string
	}{
		{"valid", func(*Configuration) {}, ""},
		{"ldap name", func(c *Configuration) {
			c.Ldap = LdapProfiles{"": {Host: "ldap.example.com"}}
		}, "Ldap.Name must be set"},
		{"ldap host", func(c *Configuration) {
			profile := c.Ldap["corp"]
			profile.Host = ""
			c.Ldap["corp"] = profile
		}, "Host must be set"},
		{"oath name", func(c *Configuration) {
			c.Oath = OathProfiles{"": {UsersFile: "/etc/users.oath"}}
		}, "Oath.Name must be set"},
		{"oath usersfile", func(c *Configuration) {
			profile := c.Oath["totp"]
			profile.UsersFile = ""
			c.Oath["totp"] = profile
		}, "UsersFile must be set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.want)
			}
		})
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
		{"missing domain and workgroup", Configuration{Winbind: &WinbindConfig{NtlmAuthPath: helper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "Winbind.Domain"},
		{"missing NtlmAuthPath path", Configuration{Winbind: &WinbindConfig{Domain: "example.com", Workgroup: "EXAMPLE", Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "NtlmAuthPath must be set"},
		{"nonexistent path", Configuration{Winbind: &WinbindConfig{Domain: "example.com", Workgroup: "EXAMPLE", NtlmAuthPath: nonExistentHelper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "is not usable"},
		{"zero timeout", Configuration{Winbind: &WinbindConfig{Domain: "example.com", Workgroup: "EXAMPLE", NtlmAuthPath: helper, Timeout: 0}, AuthProtocols: &AuthProtocolsConfig{Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendWinbind}}}}, "Timeout must be positive"},
		{"missing keytab path", Configuration{Winbind: &WinbindConfig{Domain: "example.com", Workgroup: "EXAMPLE", NtlmAuthPath: helper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Kerberos: &KerberosProtocolConfig{Share: true}}}, "Kerberos.KeytabPath must be set"},
		{"missing shared krb5 path", Configuration{Winbind: &WinbindConfig{Domain: "example.com", Workgroup: "EXAMPLE", NtlmAuthPath: helper, Timeout: 1}, AuthProtocols: &AuthProtocolsConfig{Kerberos: &KerberosProtocolConfig{Share: true, KeytabPath: DefaultSharedKeytab}}}, "Kerberos.Krb5ConfPath must be set"},
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
