package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"unicode"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/templates"
)

const (
	// defaultStageDir is transient and owned by the container image; it is
	// never an operator mount. Rendering happens here first, then the
	// operator's targets are reconciled against the staged result.
	defaultStageDir = "/tmp/rdpgw"

	defaultSmbTarget  = "/etc/samba/smb.conf"
	defaultKrb5Target = "/etc/krb5.conf"

	// Mandatory smb.conf directives when AuthProtocols.Kerberos.Share is
	// enabled: the gateway reads the machine keytab at exactly this path,
	// so winbind has to refresh the file on every machine password rotate.
	keytabDirectiveKeytab   = "dedicated keytab file"
	keytabDirectiveSyncPass = "sync machine password to keytab"
)

// provisionOptions parameterizes the filesystem locations so the
// provisioner can be exercised inside temporary directories by tests.
type provisionOptions struct {
	StageDir   string
	SmbTarget  string
	Krb5Target string
}

// ErrExplosion is returned when the strict deploy policy rejects an
// operator-managed smb.conf lacking the mandatory keytab sync directives
// while the volume holding it is mounted read-only. Provision escalates it
// via log.Fatalf with the operator playbook attached.
var ErrExplosion = errors.New("rdpgw-auth: read-only smb.conf without mandatory keytab sync directives")

// smbTemplateData carries the fields rendered into smb.conf.tmpl. Realm is
// the FQDN of the domain (winbind.Domain), falling back to the NetBIOS
// workgroup name for legacy deployments that only configure the shorthand.
type smbTemplateData struct {
	Realm     string
	Workgroup string
	Hostname  string
	// SeparatorDirective is the exact text following "winbind separator ="
	// in the rendered file. Empty means the directive is OMITTED: that is
	// the only correct spelling for the default backslash separator, since
	// smb.conf has no escape syntax and any line ending in a backslash is
	// continued onto the next line.
	SeparatorDirective string
	KerberosShare      bool
	KeytabPath         string
}

// krb5TemplateData carries the fields rendered into krb5.conf.tmpl. KDCs
// and admin servers come from the configured DomainControllers; without
// any, kerberos falls back to SRV record discovery.
type krb5TemplateData struct {
	// Realm is the kerberos realm in upper case (AD convention).
	Realm string
	// Domain is the DNS domain as configured, used for [domain_realm].
	Domain            string
	DomainControllers []config.FlexibleDomainController
}

// Provision prepares the container's Samba and Kerberos configuration for
// a winbind-backed deployment: it renders both templates into the staging
// directory and then reconciles the operator targets. Deployments without
// any winbind capability (no Kerberos keytab share and no winbind NTLM
// backend) skip provisioning entirely.
//
// An operator-managed smb.conf on a read-only volume that lacks the
// mandatory keytab directives terminates the daemon via log.Fatalf: the
// gateway must never run half-configured against the domain (strict
// explode policy of the operations plan, Milestone 2).
func Provision(conf config.Configuration) error {
	if !usesWinbind(conf) {
		log.Printf("Provisioning: no Kerberos keytab share and no winbind NTLM backend enabled, skipping smb.conf/krb5.conf provisioning")
		return nil
	}
	if conf.Winbind == nil {
		// Unreachable through config.Load (Validate requires Winbind for
		// every winbind-capable deployment); guarded for direct callers.
		return fmt.Errorf("provisioning: winbind capability requested but the Winbind configuration block is missing")
	}
	return provision(conf, provisionOptions{
		StageDir:   defaultStageDir,
		SmbTarget:  defaultSmbTarget,
		Krb5Target: defaultKrb5Target,
	})
}

// usesWinbind reports whether the deployment needs Samba/Kerberos files at
// all: either the Kerberos keytab share or a winbind NTLM backend is on.
func usesWinbind(conf config.Configuration) bool {
	if conf.AuthProtocols == nil {
		return false
	}
	if kerberos := conf.AuthProtocols.Kerberos; kerberos != nil && kerberos.Share {
		return true
	}
	if ntlm := conf.AuthProtocols.Ntlm; ntlm != nil && ntlm.Enabled {
		for _, b := range ntlm.Backends {
			if strings.EqualFold(b, config.NtlmBackendWinbind) {
				return true
			}
		}
	}
	return false
}

func provision(conf config.Configuration, p provisionOptions) error {
	if err := os.MkdirAll(p.StageDir, 0o700); err != nil {
		return fmt.Errorf("provisioning: cannot create staging dir %s: %w", p.StageDir, err)
	}

	kerberos := conf.AuthProtocols.Kerberos
	keytabSharing := kerberos != nil && kerberos.Share
	keytabPath := ""
	if keytabSharing {
		keytabPath = kerberos.KeytabPath
	}

	smbData, err := buildSmbData(conf)
	if err != nil {
		return err
	}
	krb5Data := buildKrb5Data(conf)

	smbStaged, err := stageTemplate("smb.conf.tmpl", smbData, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage smb.conf: %w", err)
	}
	krb5Staged, err := stageTemplate("krb5.conf.tmpl", krb5Data, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage krb5.conf: %w", err)
	}
	log.Printf("Provisioning: staged configuration under %s (smb.conf, krb5.conf)", p.StageDir)

	if err := reconcileSmb(smbStaged, p.SmbTarget, keytabSharing, keytabPath); err != nil {
		return err
	}
	return reconcileKrb5(krb5Staged, p.Krb5Target)
}

// buildSmbData fills the smb.conf template view model from any schema
// shape: with the legacy workgroup shorthand the realm falls back to the
// NetBIOS name so net ads can still discover the real FQDN via DNS.
func buildSmbData(conf config.Configuration) (smbTemplateData, error) {
	kerberos := conf.AuthProtocols.Kerberos
	keytabSharing := kerberos != nil && kerberos.Share
	keytabPath := ""
	if keytabSharing {
		keytabPath = kerberos.KeytabPath
	}
	data := smbTemplateData{
		// Samba's `realm` is the kerberos realm; AD issues tickets with the
		// upper-case realm, so normalize it (same as krb5.conf).
		Realm: strings.ToUpper(conf.Winbind.Domain),
		// NetBIOS name of the machine account in AD; empty means Samba
		// derives it from the container hostname, which the operations
		// plan flags as deficit-prone for pod restarts.
		Hostname:      conf.Winbind.Hostname,
		Workgroup:     conf.Winbind.Workgroup,
		KerberosShare: keytabSharing,
		KeytabPath:    keytabPath,
	}
	if data.Realm == "" {
		data.Realm = strings.ToUpper(data.Workgroup)
	}

	// Format the separator for the smb.conf parser:
	//   - the zero value means "samba default", which is exactly the backslash;
	//   - backslash itself is rendered by OMITTING the directive: the file
	//     parser performs no escape resolution and any line ending in a
	//     backslash continues onto the next line (verified with testparm);
	//   - any other single character (the Separator type guarantees exactly
	//     one, non-control rune) is written verbatim.
	sep := conf.Winbind.Separator
	if sep == 0 {
		sep = config.DefaultSeparator
	}
	if sep != config.DefaultSeparator {
		data.SeparatorDirective = sep.String()
	}

	// smb.conf values are written verbatim: no control characters and no
	// trailing backslash are tolerated, the latter because it would make
	// the rendered parameter line continue onto the next one.
	for name, value := range map[string]string{
		"winbind.domain":      data.Realm,
		"winbind.workgroup":   data.Workgroup,
		"winbind.hostname":    data.Hostname,
		"kerberos.keytabPath": data.KeytabPath,
	} {
		if value == "" {
			continue
		}
		if strings.HasSuffix(value, `\`) {
			return smbTemplateData{}, fmt.Errorf(
				"provisioning: %s %q ends with a backslash, which would make the rendered smb.conf line continue onto the next one", name, value)
		}
		if strings.ContainsAny(value, "\r\n") || containsControlRune(value) {
			return smbTemplateData{}, fmt.Errorf(
				"provisioning: %s %q contains a newline or control character and cannot be written to smb.conf", name, value)
		}
	}
	return data, nil
}

// containsControlRune rejects smb.conf injection vectors: unprintable runes
// make the rendered parameter line untrustworthy. Plain spaces are fine,
// internal whitespace is preserved by the samba parser.
func containsControlRune(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// buildKrb5Data fills the krb5.conf template view model. Kerberos realms are
// upper-case by convention (and Active Directory issues tickets with the
// upper-case realm), so Realm is normalized to upper case while Domain keeps
// the operator's spelling for the [domain_realm] lookups, which are DNS
// domain names and conventionally lower case.
func buildKrb5Data(conf config.Configuration) krb5TemplateData {
	domain := conf.Winbind.Domain
	if domain == "" {
		domain = conf.Winbind.Workgroup
	}
	return krb5TemplateData{
		Realm:             strings.ToUpper(domain),
		Domain:            domain,
		DomainControllers: conf.Winbind.DomainControllers,
	}
}

// stageTemplate renders one embedded template into the staging directory
// and returns the path of the rendered artifact.
func stageTemplate(name string, data interface{}, stageDir string) (string, error) {
	body, err := templates.FS.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("template %s not packaged: %w", name, err)
	}
	t, err := template.New(name).Parse(string(body))
	if err != nil {
		return "", fmt.Errorf("template %s is invalid: %w", name, err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", fmt.Errorf("cannot render %s: %w", name, err)
	}
	staged := strings.TrimSuffix(filepath.Join(stageDir, name), ".tmpl")
	if err := os.WriteFile(staged, out.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("cannot write staged file %s: %w", staged, err)
	}
	return staged, nil
}

// reconcileSmb reconciles the staged smb.conf against the operator target
// with the strict explode policy:
//   - missing target: install the staged file;
//   - existing writable target without keytab requirements: untouched
//     (the operator owns the file);
//   - existing writable target with keytab requirements: append every
//     missing or mis-pointed mandatory directive;
//   - existing read-only target: explode when directives are missing or
//     point elsewhere, plain notice otherwise.
func reconcileSmb(staged, target string, keytabSharing bool, keytabPath string) error {
	if _, err := os.Stat(target); os.IsNotExist(err) {
		if err := copyStaged(staged, target); err != nil {
			return fmt.Errorf("provisioning: cannot install %s: %w", target, err)
		}
		log.Printf("Provisioning: installed %s", target)
		return nil
	}

	content, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read %s: %w", target, err)
	}

	if !keytabSharing {
		log.Printf("Provisioning: keytab share is disabled, leaving operator-managed %s untouched", target)
		return nil
	}

	missing := missingKeytabDirectives(string(content), keytabPath)
	if len(missing) == 0 {
		log.Printf("Provisioning: %s already carries the keytab sync directives", target)
		return nil
	}

	if err := writableProbe(target); err != nil {
		if errors.Is(err, syscall.EROFS) {
			return explode(target, missing, keytabPath)
		}
		return fmt.Errorf("provisioning: cannot write %s: %w", target, err)
	}
	if err := appendDirectives(target, missing, keytabPath); err != nil {
		return fmt.Errorf("provisioning: cannot append mandatory keytab directives to %s: %w", target, err)
	}
	log.Printf("Provisioning: appended missing keytab sync directives to %s", target)
	return nil
}

// reconcileKrb5 installs krb5.conf when absent and refreshes writable
// files. There is no explode policy for krb5.conf: an operator-managed
// read-only file is simply honored.
func reconcileKrb5(staged, target string) error {
	if _, err := os.Stat(target); os.IsNotExist(err) {
		if err := copyStaged(staged, target); err != nil {
			return fmt.Errorf("provisioning: cannot install %s: %w", target, err)
		}
		log.Printf("Provisioning: installed %s", target)
		return nil
	}
	if err := writableProbe(target); err != nil && errors.Is(err, syscall.EROFS) {
		log.Printf("Provisioning: %s is on a read-only volume, leaving the operator-managed file untouched", target)
		return nil
	}
	if err := copyStaged(staged, target); err != nil {
		return fmt.Errorf("provisioning: cannot refresh %s: %w", target, err)
	}
	log.Printf("Provisioning: refreshed %s from staged templates", target)
	return nil
}

// explode refuses to run: the gateway requires the shared keytab to be
// correct BEFORE any client touches it, so a silent best-effort deployment
// would mask an authentication failure that only shows up in production.
func explode(target string, missing []string, keytabPath string) error {
	directives := "\n"
	directives += fmt.Sprintf("    %s = %s\n", keytabDirectiveKeytab, keytabPath)
	directives += fmt.Sprintf("    %s = %q\n", keytabDirectiveSyncPass,
		fmt.Sprintf("%s:sync_spns:sync_kvno:machine_password", keytabPath))
	return fmt.Errorf(
		"%w: %s misses %v and is mounted read-only. Add one of:\n"+
			" 1. add the directives to the mounted file%s 2. remount the volume read-write\n"+
			" 3. drop the volume mount to let rdpgw-auth generate %s",
		ErrExplosion, target, missing, directives, target)
}

// writableProbe probes whether the target can be appended to and returns
// syscall.EROFS-shaped errors for operator read-only mounts. Decoupled as a
// variable so tests can deterministically simulate read-only volumes.
var writableProbe = defaultWritableProbe

func defaultWritableProbe(target string) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

// missingKeytabDirectives lists which mandatory smb.conf directives are
// absent, or present but pointing at a different keytab file than the
// configured one: the keytab path is part of the agreement between the
// gateway and Samba, so a mismatch is equivalent to a missing directive.
func missingKeytabDirectives(content, keytabPath string) []string {
	var missing []string
	if !directiveWithKeytab(content, keytabDirectiveKeytab, keytabPath) {
		missing = append(missing, keytabDirectiveKeytab)
	}
	if !directiveWithKeytab(content, keytabDirectiveSyncPass, keytabPath) {
		missing = append(missing, keytabDirectiveSyncPass)
	}
	return missing
}

func directiveWithKeytab(content, directive, keytabPath string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, directive) {
			continue
		}
		if !strings.Contains(line, keytabPath) {
			return false
		}
		return true
	}
	return false
}

// appendDirectives appends missing mandatory directives to an existing,
// writable smb.conf.
func appendDirectives(target string, missing []string, keytabPath string) error {
	var buf bytes.Buffer
	for _, d := range missing {
		switch d {
		case keytabDirectiveKeytab:
			fmt.Fprintf(&buf, "\n# appended by rdpgw-auth provisioning\n")
			fmt.Fprintf(&buf, "%s = %s\n", d, keytabPath)
		case keytabDirectiveSyncPass:
			fmt.Fprintf(&buf, "%s = %q\n", d, fmt.Sprintf("%s:sync_spns:sync_kvno:machine_password", keytabPath))
		default:
			return fmt.Errorf("unknown missing directive %q", d)
		}
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	// fsync so a subsequent read from winbind/ntlm_auth never sees half of
	// the appended block.
	return f.Sync()
}

func copyStaged(staged, target string) error {
	body, err := os.ReadFile(staged)
	if err != nil {
		return err
	}
	return os.WriteFile(target, body, 0o644)
}
