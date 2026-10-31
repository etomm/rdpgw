package config

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/mitchellh/copystructure"
	"github.com/samber/lo"
	yaml "sigs.k8s.io/yaml"
)

const (
	// NtlmBackendLegacyFile verifies NTLM responses against the users listed in
	// this configuration file (plain text passwords).
	NtlmBackendLegacyFile = "file"
	// NtlmBackendWinbind delegates the NTLM handshake to Samba's ntlm_auth
	// helper, which in turn asks a domain controller (pass-through
	// authentication via winbindd). The host must be joined to the domain.
	NtlmBackendWinbind = "winbind"
	// NtlmBackendUsers verifies NTLM responses against local YAML users.
	NtlmBackendUsers = "users"

	// Backends accepted by AuthProtocols.Basic.Stack.
	BasicBackendWinbind = "winbind"
	BasicBackendLdap    = "ldap"
	BasicBackendUnix    = "unix"
	BasicBackendUsers   = "users"

	// BasicPluginOath names the Oath section/profile namespace. Like the
	// backend types it is reserved, so a bare Basic.Stack string is never
	// ambiguous.
	BasicPluginOath = "oath"

	// Default configuration constants
	DefaultNtlmAuthPath   = "/usr/bin/ntlm_auth"
	DefaultWinbindTimeout = 10
	// DefaultSeparator matches winbind's own documented default. A backslash
	// separator is rendered by OMITTING the smb.conf directive (the file
	// parser has no escape syntax and any line ending in a backslash
	// continues onto the next line); see cmd/auth/provisioning.
	DefaultSeparator    SingleChar = '\\'
	DefaultSharedKeytab            = "/var/lib/samba/rdpgw.keytab"
	// DefaultSharedKrb5Conf is the published path when the default keytab is
	// used; normally the shared krb5.conf sits next to the configured keytab.
	DefaultSharedKrb5Conf = "/var/lib/samba/krb5.conf"
	DefaultKdcPort        = 88
	DefaultKdcAdminPort   = 749
	DefaultStripDomain    = false
)

// DefaultConfig holds the default configuration values applied via yaml.
// These defaults are loaded first, then overridden by the YAML config file
// if present. Winbind values are loaded but winbind domain join is only
// enabled when actually referenced by authprotocols (ntlm/basic backends
// or kerberos share). In this case users is the default backend for NTLM.
var DefaultConfig = &Configuration{
	AuthProtocols: &AuthProtocolsConfig{
		Ntlm: &NtlmProtocolConfig{
			Enabled:  true,
			Backends: []string{NtlmBackendUsers},
		},
	},
	Winbind: &WinbindConfig{
		NtlmAuthPath: DefaultNtlmAuthPath,
		Timeout:      DefaultWinbindTimeout,
		StripDomain:  DefaultStripDomain,
		Separator:    DefaultSeparator,
	},
}

// Configuration holds the modern (new schema) rdpgw-auth configuration.
type Configuration struct {
	Winbind       *WinbindConfig       `json:"winbind" yaml:"winbind"`
	Ldap          LdapProfiles         `json:"ldap" yaml:"ldap"`
	Users         []UserConfig         `json:"users" yaml:"users"`
	Oath          OathProfiles         `json:"oath" yaml:"oath"`
	AuthProtocols *AuthProtocolsConfig `json:"authprotocols" yaml:"authprotocols"`
}

// LdapConfig names a directory used by the Basic (PAM) stack. pam_ldap reads
// its connection settings from the system LDAP configuration; the profile
// name is what AuthProtocols.Basic.Stack references.
type LdapConfig struct {
	// Name is the profile name, set from the list form's name or from the
	// mapping key.
	Name   string `json:"name" yaml:"name"`
	Host   string `json:"host" yaml:"host"`
	Port   int    `json:"port" yaml:"port"`
	TLS    bool   `json:"tls" yaml:"tls"`
	Base   string `json:"base" yaml:"base"`
	BindDN string `json:"binddn" yaml:"binddn"`
	BindPW string `json:"bindpw" yaml:"bindpw"`
}

// OathConfig names a PAM OATH policy (TOTP/HOTP) and its user file.
type OathConfig struct {
	// Name is the profile name, set from the list form's name or from the
	// mapping key.
	Name      string `json:"name" yaml:"name"`
	UsersFile string `json:"usersfile" yaml:"usersfile"`
	Window    int    `json:"window" yaml:"window"`
}

// LdapProfiles maps the lowercased Ldap profile name to its configuration.
type LdapProfiles = Profiles[LdapConfig]

// OathProfiles maps the lowercased Oath profile name to its configuration.
type OathProfiles = Profiles[OathConfig]

// ProfileName implements NamedProfile.
func (c LdapConfig) ProfileName() string { return c.Name }

// WithProfileName implements NamedProfile.
func (c LdapConfig) WithProfileName(name string) LdapConfig {
	c.Name = name
	return c
}

// ProfileName implements NamedProfile.
func (o OathConfig) ProfileName() string { return o.Name }

// WithProfileName implements NamedProfile.
func (o OathConfig) WithProfileName(name string) OathConfig {
	o.Name = name
	return o
}

type UserConfig struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

// WinbindConfig represents the modern Active Directory Winbind configuration.
type WinbindConfig struct {
	// Domain is the FQDN of the domain (DNS Realm).
	Domain string `json:"domain" yaml:"domain"`
	// Workgroup is the NetBIOS Domain Name / Workgroup (Pre-Windows 2000 domain).
	Workgroup string `json:"workgroup" yaml:"workgroup"`
	// Hostname is the Machine Computer Name in AD (sets 'netbios name' in smb.conf).
	Hostname string `json:"hostname" yaml:"hostname"`
	// RequireMembershipOf is passed to ntlm_auth as
	// --require-membership-of. Optional; accepts a SID or DOMAIN\Group.
	RequireMembershipOf string `json:"requiremembershipof" yaml:"requiremembershipof"`
	// NtlmAuthPath is the path to Samba's ntlm_auth binary.
	NtlmAuthPath string `json:"ntlmauthpath" yaml:"ntlmauthpath"`
	// Timeout (seconds) for a single exchange with ntlm_auth.
	Timeout int `json:"timeout" yaml:"timeout"`
	// AutoJoin controls whether rdpgw-auth automatically attempts to join the domain if unjoined.
	AutoJoin bool `json:"autojoin" yaml:"autojoin"`
	// JoinTimeout is the max minutes to attempt automatic AD domain join or wait for manual join.
	JoinTimeout int `json:"jointimeout" yaml:"jointimeout"`
	// StripDomain removes the "DOMAIN<separator>" prefix from the user
	// name that winbind reports, so rdpgw sees the bare account name.
	StripDomain bool `json:"stripdomain" yaml:"stripdomain"`
	// Separator is the winbind separator configured in smb.conf ("winbind separator", default "\").
	Separator SingleChar `json:"separator" yaml:"separator"`
	// DomainControllers lists domain controllers supporting both host strings and host/port objects.
	DomainControllers []FlexibleDomainController `json:"domaincontrollers" yaml:"domaincontrollers"`
}

type AuthProtocolsConfig struct {
	Kerberos *KerberosProtocolConfig `json:"kerberos" yaml:"kerberos"`
	Ntlm     *NtlmProtocolConfig     `json:"ntlm" yaml:"ntlm"`
	Basic    *BasicProtocolConfig    `json:"basic" yaml:"basic"`
}

// BasicProtocolConfig drives the generated PAM stack. Backends are tried in
// the configured order; each entry may attach an OATH policy.
type BasicProtocolConfig struct {
	Enabled bool              `json:"enabled" yaml:"enabled"`
	Stack   []BasicStackEntry `json:"stack" yaml:"stack"`
}

type KerberosProtocolConfig struct {
	Share      bool   `json:"share" yaml:"share"`
	KeytabPath string `json:"keytabpath" yaml:"keytabpath"`
	// Krb5ConfPath is where rdpgw-auth publishes the generated krb5.conf for
	// the gateway when Share is true. Empty means next to the shared keytab
	// (dir(KeytabPath)/krb5.conf); the default keytab therefore publishes to
	// /var/lib/samba/krb5.conf.
	Krb5ConfPath string `json:"krb5confpath" yaml:"krb5confpath"`
	// Spns is the list of Kerberos Service Principal Names to register in
	// Active Directory and keep present in the shared keytab. SPNs are a
	// Kerberos concern: without a keytab share there is nothing to register,
	// so they live here rather than under Winbind.
	Spns []string `json:"spns" yaml:"spns"`
}

type NtlmProtocolConfig struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Backends []string `json:"backends" yaml:"backends"`
}

// LegacyConfiguration holds legacy schema fields parsed only when the modern
// AuthProtocols block is missing from the configuration file.
type LegacyConfiguration struct {
	// Ntlm holds the legacy NTLM backend configuration (yaml field: ntlm).
	Ntlm *LegacyNtlmConfig `json:"ntlm" yaml:"ntlm"`
}

// LegacyNtlmConfig defines the legacy NTLM backend configuration.
type LegacyNtlmConfig struct {
	// Backend selects how NTLM AUTHENTICATE messages are verified:
	// "file" (default), "winbind", or "users".
	Backend string              `json:"backend" yaml:"backend"`
	Winbind LegacyWinbindConfig `json:"winbind" yaml:"winbind"`
}

// LegacyWinbindConfig defines the legacy winbind sub-configuration.
type LegacyWinbindConfig struct {
	// NtlmAuthPath is the path to Samba's ntlm_auth binary.
	NtlmAuthPath string `json:"ntlmauthpath" yaml:"ntlmauthpath"`
	// Domain is passed to ntlm_auth as --domain. Optional; winbind uses its
	// own domain when empty. In legacy configuration, domain represented the workgroup/NetBIOS domain.
	Domain string `json:"domain" yaml:"domain"`
	// RequireMembershipOf is passed to ntlm_auth as
	// --require-membership-of. Optional; accepts a SID or DOMAIN\Group.
	RequireMembershipOf string `json:"requiremembershipof" yaml:"requiremembershipof"`
	// Timeout (seconds) for a single exchange with ntlm_auth.
	Timeout int `json:"timeout" yaml:"timeout"`
	// StripDomain removes the "DOMAIN<separator>" prefix from the user
	// name that winbind reports, so rdpgw sees the bare account name.
	StripDomain bool `json:"stripdomain" yaml:"stripdomain"`
	// Separator is the winbind separator configured in smb.conf
	// ("winbind separator", default "\").
	Separator string `json:"separator" yaml:"separator"`
	// Spns is a list of Kerberos Service Principal Names (SPNs) to register
	// in Active Directory and ensure are present in the keytab.
	Spns []string `json:"spns" yaml:"spns"`
}

var Conf Configuration

// Load reads the rdpgw-auth configuration file, applies defaults, normalizes
// shorthand entries and validates the result. Invalid configuration is fatal.
func Load(configFile string) Configuration {
	c, err := load(configFile)
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	Conf = c
	return Conf
}

func load(configFile string) (Configuration, error) {
	cRaw, err := copystructure.Copy(DefaultConfig)
	var c Configuration = *(cRaw.(*Configuration))
	if err != nil {
		return c, fmt.Errorf("error loading dafault configuration: %w", err)
	}

	// Parse the YAML config file if present. If missing, defaults remain in effect.
	fileBytes, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Config file %s not found, skipping config file", configFile)
	} else {
		c.AuthProtocols = nil
		// Unmarshal directly into config struct (case-insensitive via sigs.k8s.io/yaml)
		if err := yaml.Unmarshal(fileBytes, &c); err != nil {
			return c, fmt.Errorf("error loading config from file: %w", err)
		}
	}

	// Convert legacy configuration into modern structure.
	// Runs when authprotocols is undefined, meaning that the file still holds the legacy configuration
	if c.AuthProtocols == nil {
		// Unmarshal legacy configuration section (yaml field: ntlm) separately.
		var legacyC LegacyConfiguration
		yaml.Unmarshal(fileBytes, &legacyC)

		c.AuthProtocols = &AuthProtocolsConfig{}

		var legacyBackend = NtlmBackendLegacyFile
		var legacyNtlm = legacyC.Ntlm
		if legacyNtlm != nil && legacyNtlm.Backend != "" {
			legacyBackend = legacyNtlm.Backend
		}
		switch legacyBackend {
		case NtlmBackendWinbind:
			c.AuthProtocols.Kerberos = &KerberosProtocolConfig{
				Share:      true,
				KeytabPath: DefaultSharedKeytab,
			}
			c.AuthProtocols.Ntlm = &NtlmProtocolConfig{
				Enabled:  true,
				Backends: []string{NtlmBackendWinbind},
			}

			// Carry over legacy winbind configuration to modern WinbindConfig if present
			if c.Winbind == nil {
				c.Winbind = &WinbindConfig{}
			}

			if legacyNtlm.Winbind.Domain != "" && c.Winbind.Workgroup == DefaultConfig.Winbind.Workgroup {
				c.Winbind.Workgroup = legacyNtlm.Winbind.Domain
			}

			if legacyNtlm.Winbind.RequireMembershipOf != "" && c.Winbind.RequireMembershipOf == DefaultConfig.Winbind.RequireMembershipOf {
				c.Winbind.RequireMembershipOf = legacyNtlm.Winbind.RequireMembershipOf
			}

			if legacyNtlm.Winbind.NtlmAuthPath != "" && c.Winbind.NtlmAuthPath == DefaultConfig.Winbind.NtlmAuthPath {
				c.Winbind.NtlmAuthPath = legacyNtlm.Winbind.NtlmAuthPath
			}

			if legacyNtlm.Winbind.Timeout > 0 && c.Winbind.Timeout == DefaultConfig.Winbind.Timeout {
				c.Winbind.Timeout = legacyNtlm.Winbind.Timeout
			}

			if c.Winbind.StripDomain == DefaultConfig.Winbind.StripDomain {
				c.Winbind.StripDomain = legacyNtlm.Winbind.StripDomain
			}

			if legacyNtlm.Winbind.Separator != "" && c.Winbind.Separator == DefaultConfig.Winbind.Separator {
				c.Winbind.Separator = newSingleChar(legacyNtlm.Winbind.Separator)
			}

			// The legacy schema nested SPNs under winbind because the old
			// wrapper used them while registering keytab entries; they are a
			// Kerberos concern and carry over to the Kerberos block, which
			// this legacy mapping enables (share = true) above.
			if len(legacyNtlm.Winbind.Spns) > 0 && c.AuthProtocols.Kerberos != nil && len(c.AuthProtocols.Kerberos.Spns) == 0 {
				c.AuthProtocols.Kerberos.Spns = legacyNtlm.Winbind.Spns
			}
		case NtlmBackendLegacyFile:
			fallthrough
		default:
			if len(c.Users) > 0 {
				c.AuthProtocols.Ntlm = &NtlmProtocolConfig{
					Enabled:  true,
					Backends: []string{NtlmBackendUsers},
				}
			}
		}
	}

	// NetBIOS auto-derivation for modern WinbindConfig.
	if c.Winbind != nil && c.Winbind.Workgroup == "" && c.Winbind.Domain != "" {
		parts := strings.Split(c.Winbind.Domain, ".")
		c.Winbind.Workgroup = strings.ToUpper(parts[0])
	}

	// The keytab and the generated krb5.conf are both published for the
	// gateway. Apply the documented keytab default first, then derive the
	// krb5.conf path from it unless the operator set one explicitly.
	if c.AuthProtocols != nil && c.AuthProtocols.Kerberos != nil && c.AuthProtocols.Kerberos.Share {
		if c.AuthProtocols.Kerberos.KeytabPath == "" {
			c.AuthProtocols.Kerberos.KeytabPath = DefaultSharedKeytab
		}
		if c.AuthProtocols.Kerberos.Krb5ConfPath == "" {
			c.AuthProtocols.Kerberos.Krb5ConfPath = path.Join(path.Dir(c.AuthProtocols.Kerberos.KeytabPath), "krb5.conf")
		}
	}

	// Resolve the Basic.Stack shorthand: a bare Ldap profile name becomes the
	// ldap backend (and entries are trimmed/case-normalized). Everything else
	// is left for Validate, which reports missing or invalid entries.
	if c.AuthProtocols != nil && c.AuthProtocols.Basic != nil && c.AuthProtocols.Basic.Enabled {
		basic := c.AuthProtocols.Basic
		for i, entry := range basic.Stack {
			entry.Backend = strings.ToLower(strings.TrimSpace(entry.Backend))
			entry.Name = strings.TrimSpace(entry.Name)
			entry.Oath = strings.TrimSpace(entry.Oath)
			if entry.Backend == "" && entry.Name != "" {
				name := strings.ToLower(entry.Name)
				switch name {
				case BasicBackendWinbind, BasicBackendLdap, BasicBackendUnix, BasicBackendUsers:
					// A bare reserved name is the backend. Bare "ldap" has no
					// profile name; Validate reports the missing profile.
					entry.Backend = name
					entry.Name = ""
				default:
					if _, ok := c.Ldap[name]; ok {
						entry.Backend = BasicBackendLdap
					}
				}
			}
			basic.Stack[i] = entry
		}
	}

	return c, c.Validate()
}

// Validate checks the authentication protocol settings.
func (c *Configuration) Validate() error {
	authProtocols := c.AuthProtocols
	if authProtocols == nil {
		return errors.New("unknown AuthProtocols")
	}
	kerberos := authProtocols.Kerberos
	hasKerberos := kerberos != nil && kerberos.Share
	ntlm := authProtocols.Ntlm
	hasNtlm := ntlm != nil && ntlm.Enabled
	basic := authProtocols.Basic
	hasBasic := basic != nil && basic.Enabled

	if !hasKerberos && !hasNtlm && !hasBasic {
		return errors.New("unknown AuthProtocols")
	}

	if hasKerberos {
		if kerberos.KeytabPath == "" {
			return errors.New("AuthProtocols.Kerberos.KeytabPath must be set when you are sharing Kerberos")
		}
		if kerberos.Krb5ConfPath == "" {
			return errors.New("AuthProtocols.Kerberos.Krb5ConfPath must be set when you are sharing Kerberos")
		}
	}

	var hasNtlmWithWinbindBackend = false
	if hasNtlm {
		if len(ntlm.Backends) == 0 {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends")
		}

		lowerBackends := lo.Map(ntlm.Backends, func(b string, _ int) string { return strings.ToLower(b) })
		distinctBackends := lo.Uniq(lowerBackends)

		if len(distinctBackends) > 2 {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends %q (expected %q and/or %q)", ntlm.Backends, NtlmBackendUsers, NtlmBackendWinbind)
		}

		ntlmBackendWinbindLower := strings.ToLower(NtlmBackendWinbind)
		permitted := []string{strings.ToLower(NtlmBackendUsers), ntlmBackendWinbindLower}
		if !lo.Every(permitted, distinctBackends) {
			return fmt.Errorf("unknown AuthProtocols.Ntlm.Backends %q (expected %q and/or %q)", ntlm.Backends, NtlmBackendUsers, NtlmBackendWinbind)
		}

		hasNtlmWithWinbindBackend = lo.Contains(distinctBackends, ntlmBackendWinbindLower)
	}

	basicUsesWinbind := false
	if hasBasic {
		if err := validateProfiles(c); err != nil {
			return err
		}
		if len(basic.Stack) == 0 {
			return errors.New("AuthProtocols.Basic.Stack must not be empty")
		}
		seen := make(map[[3]string]bool, len(basic.Stack))
		for i, entry := range basic.Stack {
			backend := strings.ToLower(strings.TrimSpace(entry.Backend))
			name := strings.TrimSpace(entry.Name)
			oath := strings.TrimSpace(entry.Oath)

			if backend == "" {
				if name == "" {
					return fmt.Errorf("AuthProtocols.Basic.Stack[%d] is missing a backend or Ldap profile name", i)
				}
				return fmt.Errorf("AuthProtocols.Basic.Stack[%d] references unknown Ldap profile %q", i, name)
			}

			key := [3]string{backend, name, oath}
			switch backend {
			case BasicBackendWinbind:
				basicUsesWinbind = true
			case BasicBackendLdap:
				if name == "" {
					return fmt.Errorf("AuthProtocols.Basic.Stack[%d] ldap backend needs a profile name", i)
				}
				if _, ok := c.Ldap[strings.ToLower(name)]; !ok {
					return fmt.Errorf("AuthProtocols.Basic.Stack[%d] references unknown Ldap %q", i, name)
				}
			case BasicBackendUnix:
				// Local system accounts, no profile.
			case BasicBackendUsers:
				if len(c.Users) == 0 {
					return errors.New("AuthProtocols.Basic.Stack uses the users backend but Users is empty")
				}
				for _, user := range c.Users {
					if user.Username == "" || user.Password == "" {
						return errors.New("Users entries need a username and password for the Basic stack")
					}
				}
			default:
				return fmt.Errorf("unknown AuthProtocols.Basic.Stack backend %q", entry.Backend)
			}
			if backend != BasicBackendLdap && name != "" {
				return fmt.Errorf("AuthProtocols.Basic.Stack[%d] %s backend does not take a profile name", i, backend)
			}
			if oath != "" {
				if _, ok := c.Oath[strings.ToLower(oath)]; !ok {
					return fmt.Errorf("AuthProtocols.Basic.Stack[%d] references unknown Oath %q", i, oath)
				}
			}
			if seen[key] {
				parts := []string{backend}
				if name != "" {
					parts = append(parts, name)
				}
				if oath != "" {
					parts = append(parts, oath)
				}
				return fmt.Errorf("duplicate AuthProtocols.Basic.Stack entry %s", strings.Join(parts, "+"))
			}
			seen[key] = true
		}
	}

	if !hasKerberos && !hasNtlmWithWinbindBackend && !basicUsesWinbind {
		// NTLM/Basic with only local verifiers: no Winbind configuration is needed.
		return nil
	}

	winbind := c.Winbind
	if winbind == nil {
		return errors.New("Winbind must be configured when AuthProtocols Kerberos, NTLM or Basic use the winbind backend")
	}

	// The generated smb.conf 'realm' and krb5.conf 'default_realm' are the
	// Kerberos/DNS realm, not the NetBIOS workgroup. A NetBIOS name is not a
	// valid substitute, so Domain is mandatory. config.Load derives
	// Workgroup from Domain when it is omitted.
	if winbind.Domain == "" {
		return errors.New("Winbind.Domain (the DNS realm/FQDN, e.g. corp.example.com) must be set when a winbind backend is enabled")
	}
	if winbind.Workgroup == "" {
		return errors.New("Winbind.Workgroup must be set (config.Load derives it from Winbind.Domain)")
	}

	for i, dc := range winbind.DomainControllers {
		if strings.TrimSpace(dc.Host) == "" {
			return fmt.Errorf("Winbind.DomainControllers[%d].Host must be set", i)
		}
	}

	if winbind.NtlmAuthPath == "" {
		return errors.New("Winbind.NtlmAuthPath must be set")
	}

	if _, err := os.Stat(winbind.NtlmAuthPath); err != nil {
		return fmt.Errorf("Winbind.NtlmAuthPath %q is not usable: %w", winbind.NtlmAuthPath, err)
	}

	if winbind.Timeout <= 0 {
		return errors.New("Winbind.Timeout must be positive")
	}
	return nil
}

// validProfileName reports whether a profile name only uses letters, digits,
// '.', '_' and '-'.
func validProfileName(name string) bool {
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// validateProfiles checks the named LDAP and OATH profiles referenced by the
// Basic stack. Profiles are keyed by name, so uniqueness is structural; keys
// are visited in sorted order to keep the first reported error deterministic.
func validateProfiles(c *Configuration) error {
	for _, name := range slices.Sorted(maps.Keys(c.Ldap)) {
		profile := c.Ldap[name]
		if name == "" {
			return errors.New("Ldap.Name must be set")
		}
		if !validProfileName(name) {
			return fmt.Errorf("Ldap name %q may only contain letters, digits, '.', '_' and '-'", name)
		}
		switch strings.ToLower(name) {
		case BasicBackendWinbind, BasicBackendLdap, BasicBackendUnix, BasicBackendUsers, BasicPluginOath:
			return fmt.Errorf("Ldap name %q is reserved for a Basic stack backend type", name)
		}
		if profile.Host == "" {
			return fmt.Errorf("Ldap %q Host must be set", name)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(c.Oath)) {
		profile := c.Oath[name]
		if name == "" {
			return errors.New("Oath.Name must be set")
		}
		if !validProfileName(name) {
			return fmt.Errorf("Oath name %q may only contain letters, digits, '.', '_' and '-'", name)
		}
		switch strings.ToLower(name) {
		case BasicBackendWinbind, BasicBackendLdap, BasicBackendUnix, BasicBackendUsers, BasicPluginOath:
			return fmt.Errorf("Oath name %q is reserved for a Basic stack backend type", name)
		}
		if profile.UsersFile == "" {
			return fmt.Errorf("Oath %q UsersFile must be set", name)
		}
	}
	return nil
}
