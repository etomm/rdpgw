package config

import (
	"reflect"
	"strings"
	"testing"

	yaml "sigs.k8s.io/yaml"
)

func TestBasicStackEntryUnmarshal(t *testing.T) {
	var entries []BasicStackEntry
	data := []byte(`- corp
- users
- backend: ldap
  name: other
  oath: totp
`)
	if err := yaml.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal stack: %v", err)
	}
	want := []BasicStackEntry{
		{Name: "corp"},
		{Name: "users"},
		{Backend: BasicBackendLdap, Name: "other", Oath: "totp"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("stack = %+v, want %+v", entries, want)
	}
}

func TestLoadBasicStackNamedEntries(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Ldap:
  - Name: corp
    Host: ldap.example.com
Users:
  - Username: alice
    Password: secret
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - backend: unix
      - corp
      - backend: users
`)
	c, err := load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	basic := c.AuthProtocols.Basic
	if len(basic.Stack) != 3 {
		t.Fatalf("stack = %+v, want 3 entries", basic.Stack)
	}
	if basic.Stack[0].Backend != BasicBackendUnix {
		t.Errorf("stack[0] = %+v, want unix", basic.Stack[0])
	}
	if basic.Stack[1].Backend != BasicBackendLdap || basic.Stack[1].Name != "corp" {
		t.Errorf("stack[1] = %+v, want ldap/corp", basic.Stack[1])
	}
	if basic.Stack[2].Backend != BasicBackendUsers {
		t.Errorf("stack[2] = %+v, want users", basic.Stack[2])
	}
}

func TestLoadBasicStackRejectsUnresolvedBareName(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - nope
`)
	if _, err := load(p); err == nil || !strings.Contains(err.Error(), "unknown Ldap profile") {
		t.Fatalf("load = %v, want an unknown Ldap profile error", err)
	}
}

func TestLoadBasicStackBareBackends(t *testing.T) {
	dir := t.TempDir()
	helper := writeFile(t, dir, "ntlm_auth", "#!/bin/sh\n")
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Winbind:
  Domain: example.com
  NtlmAuthPath: `+helper+`
  Timeout: 1
Ldap:
  corp:
    host: ldap.example.com
Users:
  - Username: alice
    Password: secret
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - winbind
      - corp
      - unix
      - users
`)
	c, err := load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []BasicStackEntry{
		{Backend: BasicBackendWinbind},
		{Backend: BasicBackendLdap, Name: "corp"},
		{Backend: BasicBackendUnix},
		{Backend: BasicBackendUsers},
	}
	if !reflect.DeepEqual(c.AuthProtocols.Basic.Stack, want) {
		t.Errorf("stack = %+v, want %+v", c.AuthProtocols.Basic.Stack, want)
	}
}

func TestLoadBasicStackBareLdapNeedsProfile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - ldap
`)
	if _, err := load(p); err == nil || !strings.Contains(err.Error(), "needs a profile name") {
		t.Fatalf("load = %v, want a missing profile error", err)
	}
}

func TestLoadMixedConfiguration(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "rdpgw-auth.yaml", `
Ldap:
  - name: corp
    host: ldap.example.com
Oath:
  totp:
    usersfile: /etc/users.oath
Users:
  - Username: alice
    Password: secret
AuthProtocols:
  Basic:
    Enabled: true
    Stack:
      - corp
      - backend: users
        oath: totp
      - unix
`)
	c, err := load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Ldap) != 1 || c.Ldap["corp"].Name != "corp" {
		t.Errorf("ldap profiles = %+v", c.Ldap)
	}
	if len(c.Oath) != 1 || c.Oath["totp"].Name != "totp" {
		t.Errorf("oath profiles = %+v", c.Oath)
	}
	want := []BasicStackEntry{
		{Backend: BasicBackendLdap, Name: "corp"},
		{Backend: BasicBackendUsers, Oath: "totp"},
		{Backend: BasicBackendUnix},
	}
	if !reflect.DeepEqual(c.AuthProtocols.Basic.Stack, want) {
		t.Errorf("stack = %+v, want %+v", c.AuthProtocols.Basic.Stack, want)
	}
}

func TestValidateNamedStackErrors(t *testing.T) {
	base := func(stack ...BasicStackEntry) Configuration {
		return Configuration{
			Ldap: LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
			AuthProtocols: &AuthProtocolsConfig{
				Basic: &BasicProtocolConfig{Enabled: true, Stack: stack},
			},
		}
	}

	for _, tc := range []struct {
		name    string
		stack   []BasicStackEntry
		wantErr string
	}{
		{"unknown bare name", []BasicStackEntry{{Name: "nope"}}, "unknown Ldap profile"},
		{"bare backend type is not a profile", []BasicStackEntry{{Name: "users"}}, "unknown Ldap profile"},
		{"missing backend and name", []BasicStackEntry{{}}, "missing a backend"},
		{"ldap without profile", []BasicStackEntry{{Backend: BasicBackendLdap}}, "needs a profile name"},
		{"non-ldap backend with name", []BasicStackEntry{{Backend: BasicBackendUnix, Name: "corp"}}, "does not take a profile name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base(tc.stack...)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateReservedBasicProfileNames(t *testing.T) {
	base := func() Configuration {
		return Configuration{
			Ldap: LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
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
	}{
		{"ldap profile named winbind", func(c *Configuration) {
			c.Ldap = LdapProfiles{"winbind": {Name: "winbind", Host: "ldap.example.com"}}
		}},
		{"ldap profile named oath", func(c *Configuration) {
			c.Ldap = LdapProfiles{BasicPluginOath: {Name: BasicPluginOath, Host: "ldap.example.com"}}
		}},
		{"oath profile named ldap", func(c *Configuration) {
			c.Oath = OathProfiles{"ldap": {Name: "ldap", UsersFile: "/etc/users.oath"}}
		}},
		{"oath profile named users", func(c *Configuration) {
			c.Oath = OathProfiles{"users": {Name: "users", UsersFile: "/etc/users.oath"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("Validate = %v, want a reserved-name error", err)
			}
		})
	}
}

func TestValidateDuplicateBasicStack(t *testing.T) {
	c := Configuration{
		Ldap: LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
		AuthProtocols: &AuthProtocolsConfig{
			Basic: &BasicProtocolConfig{
				Enabled: true,
				Stack: []BasicStackEntry{
					{Backend: BasicBackendLdap, Name: "corp"},
					{Backend: BasicBackendLdap, Name: "corp"},
				},
			},
		},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Validate = %v, want a duplicate error", err)
	}
}

func TestProfilesUnmarshal(t *testing.T) {
	t.Run("mapping form", func(t *testing.T) {
		var p LdapProfiles
		data := []byte("corp:\n  host: ldap.example.com\nother:\n  host: ldap2.example.com\n")
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		if len(p) != 2 || p["corp"].Host != "ldap.example.com" || p["other"].Host != "ldap2.example.com" {
			t.Fatalf("profiles = %+v", p)
		}
		if p["corp"].Name != "corp" || p["other"].Name != "other" {
			t.Errorf("names must be set from the mapping key: %+v", p)
		}
	})

	t.Run("list form", func(t *testing.T) {
		var p OathProfiles
		data := []byte("- name: totp\n  usersfile: /etc/users.oath\n- name: hotp\n  usersfile: /etc/users.hotp\n")
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		if len(p) != 2 || p["totp"].UsersFile != "/etc/users.oath" || p["hotp"].UsersFile != "/etc/users.hotp" {
			t.Fatalf("profiles = %+v", p)
		}
		if p["totp"].Name != "totp" || p["hotp"].Name != "hotp" {
			t.Errorf("names must be set from the list entry: %+v", p)
		}
	})

	t.Run("names are case-insensitive keys", func(t *testing.T) {
		var p LdapProfiles
		data := []byte("- name: Corp\n  host: ldap.example.com\n")
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		if got := p["corp"]; got.Host != "ldap.example.com" || got.Name != "Corp" {
			t.Fatalf("profiles = %+v", p)
		}

		var m LdapProfiles
		if err := yaml.Unmarshal([]byte("Corp:\n  host: ldap.example.com\n"), &m); err != nil {
			t.Fatal(err)
		}
		if got := m["corp"]; got.Host != "ldap.example.com" || got.Name != "Corp" {
			t.Fatalf("mapping profiles = %+v", m)
		}
	})

	for _, tc := range []struct {
		name string
		data string
	}{
		// Exact duplicate mapping keys are collapsed by the YAML-to-JSON
		// conversion, so only case variants can be caught here.
		{"mapping keys differing by case", "corp:\n  host: a\nCorp:\n  host: b\n"},
		{"duplicate list names", "- name: corp\n  host: a\n- name: CORP\n  host: b\n"},
		{"missing list name", "- host: a\n"},
		{"mapping name mismatch", "corp:\n  name: other\n  host: a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p LdapProfiles
			if err := yaml.Unmarshal([]byte(tc.data), &p); err == nil {
				t.Fatalf("unmarshal = %+v, want an error", p)
			}
		})
	}
}

func TestValidateProfilesOnlyWithBasic(t *testing.T) {
	conf := func(basic bool) Configuration {
		return Configuration{
			Ldap: LdapProfiles{"corp": {Name: "corp"}}, // Host missing: invalid profile
			AuthProtocols: &AuthProtocolsConfig{
				Ntlm: &NtlmProtocolConfig{Enabled: true, Backends: []string{NtlmBackendUsers}},
				Basic: &BasicProtocolConfig{
					Enabled: basic,
					Stack:   []BasicStackEntry{{Backend: BasicBackendUnix}},
				},
			},
		}
	}

	disabled := conf(false)
	if err := disabled.Validate(); err != nil {
		t.Errorf("Ldap profiles must be ignored when Basic is disabled: %v", err)
	}
	enabled := conf(true)
	if err := enabled.Validate(); err == nil || !strings.Contains(err.Error(), "Host must be set") {
		t.Fatalf("Validate = %v, want the invalid Ldap profile error", err)
	}
}

func TestValidateDistinctOathKeys(t *testing.T) {
	c := Configuration{
		Users: []UserConfig{{Username: "alice", Password: "secret"}},
		Oath:  OathProfiles{"totp": {Name: "totp", UsersFile: "/etc/users.oath"}},
		AuthProtocols: &AuthProtocolsConfig{
			Basic: &BasicProtocolConfig{
				Enabled: true,
				Stack: []BasicStackEntry{
					{Backend: BasicBackendUsers, Oath: "totp"},
					{Backend: BasicBackendUsers},
				},
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the same backend with different OATH policies must be allowed: %v", err)
	}
}

func TestValidateDuplicateWithOath(t *testing.T) {
	c := Configuration{
		Users: []UserConfig{{Username: "alice", Password: "secret"}},
		Oath:  OathProfiles{"totp": {Name: "totp", UsersFile: "/etc/users.oath"}},
		AuthProtocols: &AuthProtocolsConfig{
			Basic: &BasicProtocolConfig{
				Enabled: true,
				Stack: []BasicStackEntry{
					{Backend: BasicBackendUsers, Oath: "totp"},
					{Backend: BasicBackendUsers, Oath: "totp"},
				},
			},
		},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Validate = %v, want a duplicate error", err)
	}
}

func TestValidateProfileNameCharset(t *testing.T) {
	base := func() Configuration {
		return Configuration{
			Ldap: LdapProfiles{"corp": {Name: "corp", Host: "ldap.example.com"}},
			AuthProtocols: &AuthProtocolsConfig{
				Basic: &BasicProtocolConfig{
					Enabled: true,
					Stack:   []BasicStackEntry{{Backend: BasicBackendUnix}},
				},
			},
		}
	}

	for _, name := range []string{"corp ldap", "corp/ldap", "corp+ldap", "corp:ldap"} {
		ldap := base()
		ldap.Ldap = LdapProfiles{strings.ToLower(name): {Name: name, Host: "ldap.example.com"}}
		if err := ldap.Validate(); err == nil || !strings.Contains(err.Error(), "may only contain") {
			t.Errorf("Ldap name %q must be rejected: %v", name, err)
		}

		oath := base()
		oath.Oath = OathProfiles{strings.ToLower(name): {Name: name, UsersFile: "/etc/users.oath"}}
		if err := oath.Validate(); err == nil || !strings.Contains(err.Error(), "may only contain") {
			t.Errorf("Oath name %q must be rejected: %v", name, err)
		}
	}

	valid := base()
	valid.Ldap = LdapProfiles{"corp-ldap.1": {Name: "corp-ldap.1", Host: "ldap.example.com"}}
	valid.Oath = OathProfiles{"totp-1.2": {Name: "totp-1.2", UsersFile: "/etc/users.oath"}}
	if err := valid.Validate(); err != nil {
		t.Errorf("names with letters/digits/._- must be accepted: %v", err)
	}
}
