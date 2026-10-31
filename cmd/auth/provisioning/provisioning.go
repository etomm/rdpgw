package provisioning

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

const (
	// defaultStageDir is transient and owned by the container image; it is
	// never an operator mount. Rendering happens here first, then the
	// operator's targets are reconciled against the staged result.
	defaultStageDir = "/tmp/rdpgw"

	defaultSmbTarget  = "/etc/samba/smb.conf"
	defaultKrb5Target = "/etc/krb5.conf"
)

// Options controls Provision. The zero value leaves Samba's runtime state
// alone, which is the right choice when the host provides winbindd.
type Options struct {
	// ManagedWinbind means rdpgw-auth runs winbindd itself, so provisioning
	// also prepares the Samba runtime directories and secrets.ldb that
	// winbindd and "net ads join" expect. Leave it false when the host
	// provides winbindd and owns that state.
	ManagedWinbind bool
}

// provisionOptions parameterizes the filesystem locations so the provisioner
// can be exercised inside temporary directories by tests. Empty values use
// the packaged defaults.
type provisionOptions struct {
	StageDir   string
	SmbTarget  string
	Krb5Target string
}

func (p provisionOptions) withDefaults() provisionOptions {
	if p.StageDir == "" {
		p.StageDir = defaultStageDir
	}
	if p.SmbTarget == "" {
		p.SmbTarget = defaultSmbTarget
	}
	if p.Krb5Target == "" {
		p.Krb5Target = defaultKrb5Target
	}
	return p
}

// ErrExplosion marks provisioning failures that must abort startup because the
// generated configuration cannot be applied without operator action: a missing
// target that cannot be created, a required setting that cannot be added, or
// an operator value that differs from the generated one.
var ErrExplosion = errors.New("operator action required")

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

// Provision prepares the container's Samba and Kerberos configuration for a
// winbind-backed deployment: it renders both templates into the staging
// directory and then reconciles the operator targets. Deployments without
// any winbind capability (no Kerberos keytab share and no winbind NTLM
// backend) skip provisioning entirely.
//
// When Options.ManagedWinbind is set, Provision also prepares the Samba
// runtime directories and secrets.ldb that winbindd and "net ads join"
// expect. With a host-provided winbindd the host owns that state, so only the
// client-side smb.conf/krb5.conf used by pam_winbind, ntlm_auth and Kerberos
// are reconciled.
//
// An operator-managed smb.conf that cannot receive the generated settings it
// is missing (read-only volume, or a [global] section ending in a continuation
// backslash) terminates the daemon via log.Fatalf: the gateway must never run
// half-configured against the domain (strict explode policy of the operations
// plan, Milestone 2). Existing operator values are never replaced: drift
// terminates the daemon with an error naming every conflicting setting.
func Provision(conf config.Configuration, opts Options) error {
	return provisionWith(conf, opts, provisionOptions{})
}

// provisionWith is Provision with injectable filesystem locations for tests.
func provisionWith(conf config.Configuration, opts Options, p provisionOptions) error {
	if !UsesWinbind(conf) {
		log.Printf("Provisioning: no Kerberos keytab share and no winbind NTLM backend enabled, skipping smb.conf/krb5.conf provisioning")
		return nil
	}
	if conf.Winbind == nil {
		// Unreachable through config.Load (Validate requires Winbind for
		// every winbind-capable deployment); guarded for direct callers.
		return fmt.Errorf("provisioning: winbind capability requested but the Winbind configuration block is missing")
	}
	if err := conf.Validate(); err != nil {
		return fmt.Errorf("provisioning: invalid configuration: %w", err)
	}
	if err := provision(conf, p); err != nil {
		return err
	}
	if !opts.ManagedWinbind {
		log.Printf("Provisioning: winbindd is host-provided, leaving the Samba runtime state alone")
		return nil
	}
	return prepareSambaState()
}

// UsesWinbind reports whether the deployment needs Samba/Kerberos files at
// all: either the Kerberos keytab share or a winbind NTLM backend is on.
func UsesWinbind(conf config.Configuration) bool {
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
	p = p.withDefaults()
	if err := os.MkdirAll(p.StageDir, 0o700); err != nil {
		return fmt.Errorf("provisioning: cannot create staging dir %s: %w", p.StageDir, err)
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

	if err := reconcile(smbStaged, p.SmbTarget, true, smbConfSemanticallyEqual); err != nil {
		return err
	}
	if err := reconcile(krb5Staged, p.Krb5Target, false, krb5ConfSemanticallyEqual); err != nil {
		return err
	}
	return publishSharedKrb5(conf, p)
}

// publishSharedKrb5 copies the final reconciled krb5.conf to the shared
// Krb5ConfPath so the gateway can load it from the same volume as the keytab.
// Publishing the final file, not the staged template, preserves any settings an
// operator merged into the auth-side target. The write is atomic because rdpgw
// watches the published file and may reload it at any time.
func publishSharedKrb5(conf config.Configuration, p provisionOptions) error {
	kerberos := conf.AuthProtocols.Kerberos
	if kerberos == nil || !kerberos.Share {
		return nil
	}
	target := kerberos.Krb5ConfPath
	if samePath(p.Krb5Target, target) {
		return nil
	}

	data, err := os.ReadFile(p.Krb5Target)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read %s for the shared krb5.conf: %w", p.Krb5Target, err)
	}
	if err := writeStagedFile(target, data, 0o644); err != nil {
		return fmt.Errorf("provisioning: cannot publish shared krb5.conf %s: %w", target, err)
	}
	log.Printf("Provisioning: published shared krb5.conf at %s", target)
	return nil
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		return filepath.Clean(absA) == filepath.Clean(absB)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// writeFileAtomic writes data to path via a temporary file in the same
// directory, then renames it into place. Readers therefore never observe a
// partially written file. On Windows, where rename cannot replace an existing
// destination, the old file is removed first.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		// Windows does not replace an existing destination atomically.
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	return nil
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
	body, err := templatesFS.ReadFile(templatesDir + name)
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

// reconcile applies the uniform provisioning policy to one target file:
//
//  1. target missing: write the staged file — if that is impossible the
//     daemon refuses to start (ErrExplosion), because the file is required;
//  2. smb.conf present: append the generated settings it lacks, but never
//     replace an existing operator value. A key whose value differs is a
//     hard failure (ErrExplosion naming every conflict);
//  3. required settings cannot be added (read-only target, or a [global]
//     section ending in a continuation backslash): the daemon refuses to
//     start, because it would run half-configured;
//  4. krb5.conf present: overwrite it when writable;
//  5. target not writable: accept when it is semantically equal to the
//     generated configuration, otherwise warn that the operator file wins and
//     expected features may fail until reconciled.
func reconcile(staged, target string, merge bool, semanticallyEqual func(staged, current string) (bool, string)) error {
	stagedContent, err := os.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read staged %s: %w", staged, err)
	}

	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		if err := writeStagedFile(target, stagedContent, 0o644); err != nil {
			return fmt.Errorf("%w: %s does not exist and cannot be created (%v): "+
				"provide the file or a writable location for it", ErrExplosion, target, err)
		}
		log.Printf("Provisioning: installed %s", target)
		return nil
	}

	current, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read %s: %w", target, err)
	}

	if merge {
		addedKeys, mergeErr := mergeSmbConf(target, staged, string(stagedContent), string(current))
		if mergeErr != nil {
			return mergeErr
		}
		if len(addedKeys) > 0 {
			log.Printf("Provisioning: merged missing settings into %s: %v", target, addedKeys)
		} else {
			log.Printf("Provisioning: %s already carries all generated settings", target)
		}
		return nil
	}

	if err := writeStagedFile(target, stagedContent, 0o644); err == nil {
		log.Printf("Provisioning: wrote %s", target)
		return nil
	}

	if equal, key := semanticallyEqual(string(stagedContent), string(current)); equal {
		log.Printf("Provisioning: %s is read-only but semantically identical to the generated configuration", target)
		return nil
	} else {
		log.Printf("WARNING: %s is not writable and differs from the generated configuration (%s). "+
			"The operator-managed file wins; expected features such as Kerberos/winbind authentication "+
			"may fail until it matches.", target, describeDrift(target, key))
		return nil
	}
}

// smbConflictError builds the explosion for operator values that differ from
// the generated ones. It shows the generated setting next to the operator
// value and points at the staged file, so the operator can reconcile the file.
func smbConflictError(target, stagedPath string, conflicts []smbConflict) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s has operator settings that differ from the generated configuration:", target)
	for _, c := range conflicts {
		fmt.Fprintf(&b, "\n  %s = %q\n  generated: %s", c.Key, c.Current, c.Line)
	}
	fmt.Fprintf(&b, "\nExisting operator values are never overwritten.\n"+
		"To fix, update %s so it matches the generated configuration (%s), "+
		"or fix the rdpgw-auth configuration that produced it. Then restart.", target, stagedPath)
	return fmt.Errorf("%w: %s", ErrExplosion, b.String())
}

// missingSettingsError builds the explosion for required settings that could
// not be added, listing every generated line the operator file is missing and
// where the full generated file lives.
func missingSettingsError(target, stagedPath, reason string, missing []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "cannot add the required settings to %s (%s):", target, reason)
	for _, line := range missing {
		fmt.Fprintf(&b, "\n  %s", line)
	}
	fmt.Fprintf(&b, "\nGenerated configuration: %s\n"+
		"To fix, remove the obstacle above so these settings can be added, "+
		"or fix the rdpgw-auth configuration that produced them. Then restart.", stagedPath)
	return fmt.Errorf("%w: %s", ErrExplosion, b.String())
}

// mergeSmbConf adds the generated settings that the operator file does not
// carry yet, inside [global]. Existing operator values are never replaced.
// Anything that prevents the generated configuration from being complete — a
// conflicting operator value, a read-only target, or a [global] section
// ending in a continuation backslash — is an ErrExplosion naming every
// offending setting and the generated file: the daemon must not run
// half-configured.
func mergeSmbConf(target, stagedPath, staged, current string) (addedKeys []string, err error) {
	missing, conflicts := smbMergePlan(staged, current)
	if len(conflicts) > 0 {
		return nil, smbConflictError(target, stagedPath, conflicts)
	}
	if len(missing) == 0 {
		return nil, nil
	}

	if smbGlobalEndsWithBackslash(current) {
		return nil, missingSettingsError(target, stagedPath,
			"the last [global] line ends with a backslash continuation, which would swallow them", missing)
	}

	updated := insertAtGlobalEnd(current, missing)
	if err := writeStagedFile(target, []byte(updated), 0o644); err != nil {
		return nil, missingSettingsError(target, stagedPath, err.Error(), missing)
	}
	return settingKeys(missing), nil
}

// settingKeys returns the lower-cased keys of the given "key = value" lines.
func settingKeys(lines []string) []string {
	keys := make([]string, 0, len(lines))
	for _, line := range lines {
		eq := strings.Index(line, "=")
		if eq > 0 {
			keys = append(keys, strings.ToLower(strings.TrimSpace(line[:eq])))
		}
	}
	return keys
}

// insertAtGlobalEnd places the given setting lines at the end of the
// [global] section: directly before the next section header, or at EOF when
// no further section exists. A file without a [global] section gets one
// prepended, because parameters are only legal inside a section.
func insertAtGlobalEnd(content string, lines []string) string {
	kept := strings.SplitAfter(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	globalStart := -1
	for i, line := range kept {
		if strings.EqualFold(strings.TrimSpace(line), "[global]") {
			globalStart = i
			break
		}
	}
	if globalStart == -1 {
		var b strings.Builder
		b.WriteString("[global]\n")
		for _, line := range lines {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
		b.WriteString(content)
		return b.String()
	}

	insertAt := len(kept)
	for i := globalStart + 1; i < len(kept); i++ {
		trimmed := strings.TrimSpace(kept[i])
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			insertAt = i
			break
		}
	}

	var b strings.Builder
	for i := 0; i < insertAt; i++ {
		b.WriteString(kept[i])
	}
	for _, line := range lines {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	if insertAt < len(kept) {
		b.WriteString("\n")
	}
	for i := insertAt; i < len(kept); i++ {
		b.WriteString(kept[i])
	}
	return b.String()
}

// writeStagedFile is swappable in tests so read-only mounts can be simulated
// deterministically (a real read-only mount needs privileges unavailable on
// CI). It is also used for the published krb5.conf so both writes share the
// same atomic implementation.
var writeStagedFile = writeFileAtomic
