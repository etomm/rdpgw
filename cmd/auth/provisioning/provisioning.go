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
	// Relaxed downgrades provisioning drift in operator-managed files from
	// fatal to warnings: conflicts and settings that cannot be applied are
	// logged and the daemon keeps running. Operator values are never
	// replaced in either mode. Strict (the default) refuses to start
	// instead, so container deployments catch drift at deploy time.
	Relaxed bool
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
// plan, Milestone 2). Existing operator values are never replaced: drift fails
// the daemon with an error naming every conflicting setting, or — with
// Options.Relaxed — only logs a warning, so long systemd deployments keep
// running. The generated configuration then lives in the staging directory and
// is what the operator file should be reconciled against.
func Provision(conf config.Configuration, opts Options) error {
	return provisionWith(conf, opts, provisionOptions{})
}

// provisionWith is Provision with injectable filesystem locations for tests.
// It is the single entry that actually provisions, so it also owns the
// validation contract: provisioning consumes normalized values (derived
// workgroup, default keytab path, validated domain/DC list), and a caller
// that bypasses config.Load must not be able to render an incoherent
// smb.conf/krb5.conf.
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
	// Validate only after establishing that this deployment actually needs
	// provisioning: a non-winbind config must remain a no-op.
	if err := conf.Validate(); err != nil {
		return fmt.Errorf("provisioning: invalid configuration: %w", err)
	}
	if err := provision(conf, p, opts.Relaxed); err != nil {
		return err
	}
	if !opts.ManagedWinbind {
		log.Printf("Provisioning: winbindd is host-provided, leaving the Samba runtime state alone")
		return nil
	}
	return prepareSambaState()
}

// UsesWinbind reports whether the deployment needs Samba/Kerberos files at
// all: either the Kerberos keytab share, or a winbind verifier in the NTLM or
// Basic stack.
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
	if basic := conf.AuthProtocols.Basic; basic != nil && basic.Enabled {
		for _, entry := range basic.Stack {
			if strings.EqualFold(entry.Backend, config.BasicBackendWinbind) {
				return true
			}
		}
	}
	return false
}

func provision(conf config.Configuration, p provisionOptions, relaxed bool) error {
	p = p.withDefaults()
	if err := os.MkdirAll(p.StageDir, 0o700); err != nil {
		return fmt.Errorf("provisioning: cannot create staging dir %s: %w", p.StageDir, err)
	}

	smbData, err := buildSmbData(conf)
	if err != nil {
		return err
	}
	krb5Data, err := buildKrb5Data(conf)
	if err != nil {
		return err
	}

	smbStaged, err := stageTemplate("smb.conf.tmpl", smbData, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage smb.conf: %w", err)
	}
	krb5Staged, err := stageTemplate("krb5.conf.tmpl", krb5Data, p.StageDir)
	if err != nil {
		return fmt.Errorf("provisioning: cannot stage krb5.conf: %w", err)
	}
	log.Printf("Provisioning: staged configuration under %s (smb.conf, krb5.conf)", p.StageDir)

	if err := reconcileSmb(smbStaged, p.SmbTarget, relaxed); err != nil {
		return err
	}
	if err := reconcileKrb5(krb5Staged, p.Krb5Target, relaxed); err != nil {
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

// buildSmbData fills the smb.conf template view model from the normalized
// configuration. Winbind.Domain is the DNS/Kerberos realm; it is never
// substituted with the NetBIOS workgroup (that would produce an invalid AD
// realm).
func buildSmbData(conf config.Configuration) (smbTemplateData, error) {
	kerberos := conf.AuthProtocols.Kerberos
	keytabSharing := kerberos != nil && kerberos.Share
	keytabPath := ""
	if keytabSharing {
		// config.Load applies DefaultSharedKeytab and config.Validate
		// requires the path for a keytab share; provisioning does not
		// repeat those configuration rules.
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
//
// Values are validated against the krb5.conf parser grammar: unlike smb.conf
// there is no line continuation and no quoting, but relations can open
// subsections with a trailing `{` and comments start with `#`/`;` — so any
// value carrying a brace (or a newline/control character) would corrupt the
// file structure and is rejected. See docs/configuration-provisioning.md.
func buildKrb5Data(conf config.Configuration) (krb5TemplateData, error) {
	domain := conf.Winbind.Domain
	data := krb5TemplateData{
		Realm:             strings.ToUpper(domain),
		Domain:            domain,
		DomainControllers: conf.Winbind.DomainControllers,
	}

	// Realm/Domain are rendered both as section tags and block headers
	// (`REALM = {`), where a `{`, `}` or control character would break the
	// brace structure; the KDC hosts are rendered inline in relations, where
	// a newline or control character would swallow the rest of the line.
	for _, v := range []struct{ name, value string }{
		{"winbind.domain", data.Realm},
		{"winbind.domain", data.Domain},
	} {
		if strings.ContainsAny(v.value, "{}\r\n") || containsControlRune(v.value) {
			return krb5TemplateData{}, fmt.Errorf(
				"provisioning: %s %q contains a brace, newline or control character and cannot be written to krb5.conf", v.name, v.value)
		}
	}
	for i, dc := range data.DomainControllers {
		// The "host must be set" rule is operator-input validation and lives
		// in config.Validate; this loop only enforces the krb5.conf file
		// grammar (a brace/newline would corrupt the rendered structure).
		if strings.ContainsAny(dc.Host, "{}\r\n") || containsControlRune(dc.Host) {
			return krb5TemplateData{}, fmt.Errorf(
				"provisioning: winbind.domainControllers[%d] %q contains a brace, newline or control character and cannot be written to krb5.conf", i, dc.Host)
		}
	}
	return data, nil
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

// reconciler applies the uniform provisioning policy to one target file:
//
//  1. target missing: write the staged file — if that is impossible the
//     daemon refuses to start (ErrExplosion), because the file is required;
//  2. file present: merge the generated settings it lacks, but never replace
//     an existing operator value;
//  3. a setting the operator defined differently from the generated one:
//     strict mode fails the daemon naming every conflict, relaxed mode only
//     warns (the merge still applies the missing settings);
//  4. required settings that cannot be added (read-only target, or a [global]
//     section ending in a continuation backslash): strict fails the daemon,
//     relaxed warns that the operator file wins and expected features may
//     fail until reconciled;
//  5. when nothing can be written at all, accept a semantically equal target;
//     otherwise warn that the operator file wins.
//
// The validators report drift through the shared error/warning helper.
type reconciler struct {
	target  string
	staged  string
	relaxed bool

	stagedContent  string
	currentContent string
}

// failDrift either explodes or logs a warning, per the policy.
func (r reconciler) failDrift(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	if r.relaxed {
		log.Printf("WARNING: %s", msg)
		return nil
	}
	return fmt.Errorf("%w: %s", ErrExplosion, msg)
}

func reconcileSmb(staged, target string, relaxed bool) error {
	r := reconciler{target: target, staged: staged, relaxed: relaxed}
	return r.reconcile(mergeSmb)
}

func reconcileKrb5(staged, target string, relaxed bool) error {
	r := reconciler{target: target, staged: staged, relaxed: relaxed}
	return r.reconcile(mergeKrb5)
}

// reconcile implements the policy above: read the staged file, then either
// install or merge the target using the provided merge function.
func (r reconciler) reconcile(merge func(reconciler) (addedKeys []string, err error)) error {
	stagedContent, err := os.ReadFile(r.staged)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read staged %s: %w", r.staged, err)
	}

	if _, err := os.Stat(r.target); errors.Is(err, os.ErrNotExist) {
		if err := writeStagedFile(r.target, stagedContent, 0o644); err != nil {
			return fmt.Errorf("%w: %s does not exist and cannot be created (%v): "+
				"provide the file or a writable location for it", ErrExplosion, r.target, err)
		}
		log.Printf("Provisioning: installed %s", r.target)
		return nil
	}

	current, err := os.ReadFile(r.target)
	if err != nil {
		return fmt.Errorf("provisioning: cannot read %s: %w", r.target, err)
	}

	r.stagedContent = string(stagedContent)
	r.currentContent = string(current)
	addedKeys, mergeErr := merge(r)
	if mergeErr != nil {
		return mergeErr
	}
	if len(addedKeys) > 0 {
		log.Printf("Provisioning: merged missing settings into %s: %v", r.target, addedKeys)
	} else {
		log.Printf("Provisioning: %s carries all generated settings (consult the warnings above when the file is not reconciled)", r.target)
	}
	return nil
}

// mergeSmb adds the generated settings that the operator file does not
// carry yet, inside [global]. Existing operator values are never replaced.
// Anything that prevents the generated configuration from being complete — a
// conflicting operator value, a read-only target, or a [global] section
// ending in a continuation backslash — follows the strict/relaxed policy:
// strict fails the daemon naming every offending setting and the generated
// file, relaxed only warns (the daemon must not run half-configured silently,
// but a long-running systemd service reports and continues). Returns the
// lower-cased keys of the inserted lines.
func mergeSmb(r reconciler) ([]string, error) {
	plan := smbMergePlan(r.stagedContent, r.currentContent)
	if len(plan.conflicts) > 0 {
		if err := r.failDrift("%s", conflictMessage(r, plan.conflicts)); err != nil {
			return nil, err
		}
	}
	if len(plan.missing) == 0 {
		return nil, nil
	}
	missingLines := settingLines(plan.missing)

	if smbGlobalEndsWithBackslash(r.currentContent) {
		if err := r.failDrift("%s", missingSettingsMessage(r,
			"the last [global] line ends with a backslash continuation, which would swallow them", missingLines)); err != nil {
			return nil, err
		}
		return nil, nil
	}

	updated := insertAtGlobalEnd(r.currentContent, missingLines)
	if err := writeStagedFile(r.target, []byte(updated), 0o644); err != nil {
		if err := r.failDrift("%s", missingSettingsMessage(r, err.Error(), missingLines)); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return settingKeys(missingLines), nil
}

// mergeKrb5 merges the generated settings into the operator's krb5.conf with
// exactly the same policy as smb.conf: never replace an operator value, add
// what is missing, and treat conflicts — or a target that cannot be appended
// to — as drift. Strict mode explodes; --relaxed warns and keeps running.
// A read-only file that already carries everything is accepted implicitly
// (nothing is missing, so nothing is written). The structural markers are
// braces around subsections (there are no continuation lines), documented in
// docs/configuration-provisioning.md.
func mergeKrb5(r reconciler) ([]string, error) {
	plan, err := krb5MergePlan(r.stagedContent, r.currentContent)
	if err != nil {
		if err := r.failDrift("%s", err.Error()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if len(plan.conflicts) > 0 {
		if err := r.failDrift("%s", conflictMessage(r, plan.conflicts)); err != nil {
			return nil, err
		}
	}
	if len(plan.missing) == 0 {
		return nil, nil
	}
	missingLines := settingLines(plan.missing)

	updated, err := insertKrb5Settings(r.currentContent, plan.missing)
	if err != nil {
		if err := r.failDrift("%s", missingSettingsMessage(r, err.Error(), missingLines)); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err := writeStagedFile(r.target, []byte(updated), 0o644); err != nil {
		if err := r.failDrift("%s", missingSettingsMessage(r, err.Error(), missingLines)); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return settingKeys(missingLines), nil
}

// renderValue indents a multi-line value (krb5 realm block) so drift text
// stays readable, truncating very long blocks to their first lines.
func renderValue(value string) string {
	lines := strings.Split(value, "\n")
	const maxLines = 8
	more := 0
	if len(lines) > maxLines {
		more = len(lines) - maxLines
		lines = lines[:maxLines]
	}
	out := strings.Join(lines, "\n    ")
	if more > 0 {
		out += fmt.Sprintf("\n    ... (%d more line(s))", more)
	}
	return out
}

// conflictMessage describes operator values that differ from the generated
// ones. It is shared by both formats: the normalized comparison produced the
// same conflicts shape for smb.conf and krb5.conf. Multi-line values (krb5
// realm blocks) are rendered as indented blocks.
func conflictMessage(r reconciler, conflicts []fileConflict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s has operator settings that differ from the generated configuration:", r.target)
	for _, c := range conflicts {
		if strings.Contains(c.Current, "\n") || strings.Contains(c.Want, "\n") {
			fmt.Fprintf(&b, "\n  %s:\n  operator:\n    %s\n  generated:\n    %s",
				c.Key, renderValue(c.Current), renderValue(c.Want))
			continue
		}
		fmt.Fprintf(&b, "\n  %s: operator value %q\n  generated: %s", c.Key, c.Current, strings.Join(c.Lines, " / "))
	}
	fmt.Fprintf(&b, "\nExisting operator values are never overwritten.\n"+
		"To fix, update %s so it matches the generated configuration (%s), "+
		"or fix the rdpgw-auth configuration that produced it. Then restart. "+
		"Alternatively start with --relaxed to log the drift and keep running.", r.target, r.staged)
	return b.String()
}

// missingSettingsMessage describes the required settings that could not be
// added, listing every generated line the operator file is missing and where
// the full generated file lives.
func missingSettingsMessage(r reconciler, reason string, missing []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "cannot add the required settings to %s (%s):", r.target, reason)
	for _, line := range missing {
		fmt.Fprintf(&b, "\n  %s", line)
	}
	fmt.Fprintf(&b, "\nGenerated configuration: %s\n"+
		"To fix, remove the obstacle above so these settings can be added, "+
		"or fix the rdpgw-auth configuration that produced them. Then restart.",
		r.staged)
	return b.String()
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
	// A file that does not end with a newline would otherwise swallow the
	// first inserted setting onto the last operator line.
	ensureLineBreakBefore(kept, insertAt)

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
