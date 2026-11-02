package provisioning

import (
	"fmt"
	"sort"
	"strings"
)

// The provisioner compares the staged (desired) configuration with an
// operator-managed target. Equality is semantic, not byte-wise: only the
// settings this program manages are compared, after normalizing formatting,
// comments, continuation lines and insignificant case. Extra operator
// settings are always acceptable, and existing operator values are never
// replaced — the caller decides whether drift is a warning or fatal.
//
// Both file formats normalize into the same representation (fileSetting),
// so planSettings is the single comparison: normalization differs per
// format, the comparison and the drift report do not (see
// docs/configuration-provisioning.md).

// fileSetting is one managed setting normalized out of its file format.
// The format parser resolved the structural markers into the flattened Key
// and Value (smb.conf: continuation backslashes; krb5.conf: subsections
// become whole-block settings), so Lines are the setting's ready-to-write
// text in its native format and the comparison works identically for both.
type fileSetting struct {
	// Key is the flattened path: "global/<tag>", "<section>/<tag>" or
	// "realms/<realm>" for a whole realm block.
	Key string
	// Value is the raw value exactly as written; the per-format normalize
	// function makes it comparable at plan time. For a realm block the
	// value is the verbatim aggregated block text `{ ... }` (interior
	// lines and EOL characters preserved, brace-aware).
	Value string
	// Lines is the ready-to-write text: smb.conf one logical line with
	// continuations resolved; smb/krb5 relations one line; a krb5 realm
	// block its full `REALM = {` ... `}` text, byte-exact from the file it
	// was parsed from.
	Lines []string
	// Section is the [section] (lower-cased) the setting belongs to.
	Section string
}

// fileConflict is a generated setting that the operator file already defines
// with a different value. The operator value wins: it is reported, never
// replaced. One representation serves both formats.
type fileConflict struct {
	Key     string
	Current string
	Want    string
	// Lines are the generated setting lines, for the operator-facing text.
	Lines []string
}

// settingsPlan is the result of the shared comparison for one target file.
type settingsPlan struct {
	missing   []fileSetting
	conflicts []fileConflict
}

// settingsIndex groups normalized settings by flattened key, preserving the
// in-file order inside each group.
func settingsIndex(list []fileSetting) map[string][]fileSetting {
	out := make(map[string][]fileSetting)
	for _, s := range list {
		out[s.Key] = append(out[s.Key], s)
	}
	return out
}

// planSettings compares the generated settings against the operator's with
// one method for every format. normalize decides the comparable form of a
// raw value (per-format rules: keytab paths stay case-sensitive in smb.conf,
// krb5.conf compares the collected text verbatim). A setting absent from the
// operator's file comes back in plan.missing for insertion; a setting that
// is present with different text comes back as a conflict whose values are
// reported but never replaced.
func planSettings(generated, existing []fileSetting, normalize func(key, raw string) string) settingsPlan {
	want := settingsIndex(generated)
	got := settingsIndex(existing)

	keys := make([]string, 0, len(want))
	for key := range want {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var plan settingsPlan
	for _, key := range keys {
		gen := want[key]
		have, present := got[key]
		if !present {
			plan.missing = append(plan.missing, gen...)
			continue
		}

		wantValues := make([]string, 0, len(gen))
		lines := make([]string, 0, len(gen))
		conflict := false
		for _, s := range gen {
			wantValues = append(wantValues, s.Value)
			lines = append(lines, s.Lines...)
			if normalize(key, s.Value) != normalize(key, have[0].Value) {
				conflict = true
			}
		}
		if conflict {
			current := make([]string, 0, len(have))
			for _, h := range have {
				current = append(current, h.Value)
			}
			plan.conflicts = append(plan.conflicts, fileConflict{
				Key:     key,
				Current: strings.Join(current, ", "),
				Want:    strings.Join(wantValues, ", "),
				Lines:   lines,
			})
		}
	}
	return plan
}

// settingLines flattens missing settings into their insertion lines.
func settingLines(missing []fileSetting) []string {
	var out []string
	for _, s := range missing {
		out = append(out, s.Lines...)
	}
	return out
}

// ----------------------------------------------------------------------------
// smb.conf normalization
// ----------------------------------------------------------------------------

// smbConfSemanticallyEqual reports whether current already carries the
// settings of the generated smb.conf. The second return value names the
// first drifted setting, for the operator-facing warning.
func smbConfSemanticallyEqual(staged, current string) (bool, string) {
	want := parseSmbConf(staged)
	got := parseSmbConf(current)

	// samba defaults for managed settings that the generated file may omit
	// on purpose: the backslash separator is expressed by NOT writing it.
	want["global/winbind separator"] = wantOr(want["global/winbind separator"], `\`)
	got["global/winbind separator"] = wantOr(got["global/winbind separator"], `\`)

	for _, key := range sortedKeys(want) {
		if normalizeSmbValue(key, got[key]) != normalizeSmbValue(key, want[key]) {
			return false, key
		}
	}
	return true, ""
}

// wantOr returns value unless empty, in which case fallback applies.
func wantOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// parseSmbSettings normalizes an smb.conf into ordered fileSettings: the
// walker applies the format rules that matter for both comparison and
// re-insertion (docs/configuration-provisioning.md): line continuation on a
// trailing backslash, comment/blank line removal, first '=' only, keys
// case-insensitive, inner whitespace collapsed.
func parseSmbSettings(content string) []fileSetting {
	var out []fileSetting
	section := ""

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// Continuation: a line ending in a backslash joins the next one.
		// There is no escape processing, so the resolved Lines are exactly
		// the text a re-insertion needs.
		for strings.HasSuffix(strings.TrimRight(line, " \t"), `\`) && i+1 < len(lines) {
			line = strings.TrimRight(line, " \t")
			line = line[:len(line)-1] + lines[i+1]
			i++
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(trimmed[:eq]), " "))
		value := strings.Join(strings.Fields(trimmed[eq+1:]), " ")
		out = append(out, fileSetting{
			Key:     section + "/" + key,
			Value:   value,
			Lines:   []string{trimmed},
			Section: section,
		})
	}
	return out
}

// smbMergePlan is the smb.conf wrapper around the shared comparison: only
// the [global] settings the generated file carries are managed, and the
// winbind separator gets its own rule (the backslash default is expressed by
// omitting the directive, so a written operator separator that is not the
// default is a conflict, never an insertion).
func smbMergePlan(staged, current string) settingsPlan {
	generated := filterGlobal(parseSmbSettings(staged))
	existing := filterGlobal(parseSmbSettings(current))

	// The generated file expresses the backslash default by OMITTING the
	// directive; only a written non-default separator is a managed setting.
	stagedWritesSeparator := false
	for _, s := range generated {
		if s.Key == "global/winbind separator" {
			stagedWritesSeparator = true
		}
	}
	var filtered []fileSetting
	for _, s := range generated {
		if s.Key == "global/winbind separator" && !stagedWritesSeparator {
			continue
		}
		filtered = append(filtered, s)
	}
	plan := planSettings(filtered, existing, normalizeSmbValue)

	// The separator is always-present in semantic terms (omitted = samba's
	// backslash default); when the generated file omits it, only an
	// explicitly written operator line can conflict.
	if !stagedWritesSeparator {
		for _, s := range existing {
			if s.Key == "global/winbind separator" &&
				normalizeSmbValue(s.Key, s.Value) != normalizeSmbValue(s.Key, `\`) {
				plan.conflicts = append(plan.conflicts, fileConflict{
					Key:     s.Key,
					Current: s.Value,
					Want:    `\`,
					Lines:   []string{`winbind separator = \ (samba default, omitted from the generated file)`},
				})
			}
		}
	}
	return plan
}

// filterGlobal keeps the settings that live in [global]: the generated
// smb.conf is entirely [global], and the merge only reconciles that section.
func filterGlobal(list []fileSetting) []fileSetting {
	var out []fileSetting
	for _, s := range list {
		if s.Section == "global" {
			out = append(out, s)
		}
	}
	return out
}

// smbGlobalLines extracts the settable lines (no comments/blanks/section
// headers) of the generated [global] section.
func smbGlobalLines(content string) []string {
	var lines []string
	section := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(trimmed[1 : len(trimmed)-1])
			continue
		}
		if section != "global" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

// smbGlobalEndsWithBackslash reports whether the last meaningful line of the
// [global] section ends with a continuation backslash.
func smbGlobalEndsWithBackslash(content string) bool {
	section := ""
	last := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(trimmed[1 : len(trimmed)-1])
			continue
		}
		if section == "global" {
			last = raw
		}
	}
	return strings.HasSuffix(strings.TrimRight(last, " \t"), `\`)
}

// parseSmbConf flattens an smb.conf into "section/key" -> value. It applies
// the file format rules that matter for comparison: line continuation on a
// trailing backslash, comment/blank line removal, first '=' only, keys case
// insensitive, surrounding whitespace trimmed.
func parseSmbConf(content string) map[string]string {
	out := make(map[string]string)
	section := ""

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// continuation: a line ending in a backslash joins the next one
		for strings.HasSuffix(strings.TrimRight(line, " \t"), `\`) && i+1 < len(lines) {
			line = strings.TrimRight(line, " \t")
			line = line[:len(line)-1] + lines[i+1]
			i++
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(trimmed[:eq]), " "))
		value := strings.Join(strings.Fields(trimmed[eq+1:]), " ")
		out[section+"/"+key] = value
	}
	return out
}

// normalizeSmbValue makes smb.conf values comparable: case-insensitive,
// except for keytab paths where the filesystem is case sensitive.
func normalizeSmbValue(key, value string) string {
	if strings.Contains(key, "keytab") {
		return value
	}
	return strings.ToLower(value)
}

// ----------------------------------------------------------------------------
// krb5.conf normalization
// ----------------------------------------------------------------------------

// parseKrb5Settings normalizes a krb5.conf into the shared fileSetting
// representation under the MIT profile grammar: `[sections]`, `tag = value`
// relations, `#`/`;` line comments, and `tag = { ... }` subsections. The
// braced region is the krb5.conf counterpart of smb.conf's `\` continuation:
// a value that starts with `{` extends to the matching `}` (brace-aware, so
// nested subsections belong to it), and the collected text — braces, inner
// lines, indentation and EOLs included, only CRLF normalized to LF — becomes
// the setting's Value. `[realms]` blocks therefore normalize as one setting
// per realm, keyed `realms/<realm>`, exactly like an INI entry whose value
// has a strange quoting.
func parseKrb5Settings(content string) ([]fileSetting, error) {
	var out []fileSetting
	section := ""
	depth := 0

	type block struct {
		realm, realmText string
		header           string
		interior         []string
		close            string
	}
	var captured *block

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)

		if captured != nil {
			// Inside a `REALM = {` block: collect everything verbatim and
			// only track nested brace depth, so the block ends at its own
			// closing brace, never at an inner one.
			if trimmed == "}" {
				depth--
				if depth == 0 {
					captured.close = raw
					collected := "{\n" + strings.Join(captured.interior, "\n")
					if len(captured.interior) > 0 {
						collected += "\n"
					}
					collected += "}"
					out = append(out, fileSetting{
						// The realm name keeps its spelling: it is the block
						// identity and must be upper case (AD convention).
						Key:     "realms/" + captured.realmText,
						Value:   collected,
						Section: "realms",
						Lines:   append(append([]string{captured.header}, captured.interior...), raw),
					})
					captured = nil
					continue
				}
				captured.interior = append(captured.interior, raw)
				continue
			}
			if strings.HasSuffix(trimmed, "{") {
				depth++
			}
			captured.interior = append(captured.interior, raw)
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			depth = 0
			continue
		}
		if trimmed == "}" {
			if depth > 0 {
				depth--
			}
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq <= 0 {
			continue
		}
		tag := strings.TrimSpace(trimmed[:eq])
		value := strings.TrimSpace(trimmed[eq+1:])

		if strings.HasSuffix(value, "{") {
			if section == "realms" && depth == 0 {
				// `REALM = { ... }`: the block name is the tag.
				name := strings.TrimSpace(tag)
				if name == "" {
					return nil, fmt.Errorf("krb5.conf has a realm block without a name")
				}
				captured = &block{realm: strings.ToLower(name), realmText: name, header: raw}
				depth = 1
				continue
			}
			depth++
			continue
		}

		// Only direct relations of non-realms sections are managed; nested
		// subsections (appdefaults/capaths style trees) stay untouched.
		if section == "" || section == "realms" || depth != 0 {
			continue
		}
		out = append(out, fileSetting{
			Key:     section + "/" + strings.ToLower(tag),
			Value:   value,
			Lines:   []string{tag + " = " + value},
			Section: section,
		})
	}
	if captured != nil {
		return nil, fmt.Errorf("krb5.conf realm block %q is not closed", captured.realmText)
	}
	if unbalancedKrb5Braces(content) {
		return nil, fmt.Errorf("krb5.conf braces are unbalanced")
	}
	return out, nil
}

// krb5MergePlan is the krb5.conf wrapper around the shared comparison. The
// error reports a structure too broken to find safe insertion points.
//
// Realm blocks are matched by their lower-cased name to avoid ever appending
// a duplicate block, but the spelling is compared too: realm names must be
// upper case, so a name that only differs in case is drift (strict
// explosion / relaxed warning), not an equal or a new setting.
func krb5MergePlan(staged, current string) (settingsPlan, error) {
	generated, err := parseKrb5Settings(staged)
	if err != nil {
		return settingsPlan{}, fmt.Errorf("generated krb5.conf: %w", err)
	}
	existing, err := parseKrb5Settings(current)
	if err != nil {
		return settingsPlan{}, err
	}

	var genOther, existOther []fileSetting
	genRealms := map[string]fileSetting{}
	existRealms := map[string]fileSetting{}
	for _, s := range generated {
		if s.Section == "realms" {
			genRealms[strings.ToLower(krb5RealmName(s.Key))] = s
			continue
		}
		genOther = append(genOther, s)
	}
	for _, s := range existing {
		if s.Section == "realms" {
			existRealms[strings.ToLower(krb5RealmName(s.Key))] = s
			continue
		}
		existOther = append(existOther, s)
	}

	plan := planSettings(genOther, existOther, normalizeKrb5Value)

	for _, realm := range sortedKeys(genRealms) {
		want := genRealms[realm]
		have, present := existRealms[realm]
		if !present {
			plan.missing = append(plan.missing, want)
			continue
		}
		wantName, currentName := krb5RealmName(want.Key), krb5RealmName(have.Key)
		if wantName != currentName {
			plan.conflicts = append(plan.conflicts, fileConflict{
				Key:     want.Key,
				Current: fmt.Sprintf("%s (realm names must be upper case)", currentName),
				Want:    wantName,
				Lines:   want.Lines,
			})
			continue
		}
		if normalizeKrb5Value(want.Key, want.Value) != normalizeKrb5Value(have.Key, have.Value) {
			plan.conflicts = append(plan.conflicts, fileConflict{
				Key:     want.Key,
				Current: have.Value,
				Want:    want.Value,
				Lines:   want.Lines,
			})
		}
	}
	return plan, nil
}

// normalizeKrb5Value compares the collected text verbatim, exactly like an
// INI value with strange quoting: only EOL normalization happened during
// parsing. Identifiers (section/realm/tag names) are normalized at parse
// time; the value text itself is the operator's.
func normalizeKrb5Value(key, value string) string {
	return value
}

// unbalancedKrb5Braces reports whether the file's `{ ... }` structure cannot
// be trusted for merging: braces must open with a relation value ending in
// `{` and close on their own line, and the file must end balanced.
func unbalancedKrb5Braces(content string) bool {
	depth := 0
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if line == "}" {
			depth--
			continue
		}
		if eq := strings.Index(line, "="); eq > 0 && strings.HasSuffix(strings.TrimSpace(line[eq+1:]), "{") {
			depth++
		}
	}
	return depth != 0
}

// ----------------------------------------------------------------------------
// insertion drivers
// ----------------------------------------------------------------------------

// insertKrb5Settings returns the operator's content with the missing
// settings inserted at the right places:
//
//   - plain relations go at the end of their [section];
//   - a whole realm block (`REALM = { ... }`, normalized as one setting) is
//     appended at the end of [realms]; its collected text is inserted
//     byte-exact from the staged file — the "strange quoting" value is
//     written as it was read, indentation and EOLs included;
//   - a missing [section] is created at the end of the file.
//
// A block with the same realm name that already exists is an invariant
// violation (the plan would have reported it as drift), so the merge fails
// instead of appending a second block that the profile parser would silently
// override. The inserted Lines come straight from the normalized settings,
// so the merge never re-derives text.
func insertKrb5Settings(content string, missing []fileSetting) (string, error) {
	newContent := content
	for _, item := range missing {
		var err error
		if item.Section == "realms" {
			newContent, err = insertKrb5RealmBlock(newContent, item)
		} else {
			newContent, err = insertKrb5SectionRelation(newContent, item.Section, item.Lines)
		}
		if err != nil {
			return "", err
		}
	}
	return newContent, nil
}

// krb5SectionBounds reports the line-index window of a [section]: from the
// header line to the next top-level section header (exclusive) or EOF.
func krb5SectionBounds(lines []string, section string) (start, end int, ok bool) {
	for i, raw := range lines {
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			name := strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			if !ok && name == section {
				start, ok = i, true
				continue
			}
			if ok {
				return start, i, true
			}
		}
	}
	if ok {
		return start, len(lines), true
	}
	return 0, 0, false
}

// ensureLineBreakBefore makes sure the element preceding insertion index i ends
// with a newline. Files that do not end with a newline would otherwise have
// the first inserted setting concatenated onto their last line (e.g.
// "default_realm = EX.FIdns_lookup_kdc = true"). The element list comes from
// strings.SplitAfter(content, "\n"), so only its last element can lack one.
func ensureLineBreakBefore(lines []string, i int) {
	if i <= 0 || i > len(lines) {
		return
	}
	last := i - 1
	if !strings.HasSuffix(lines[last], "\n") {
		lines[last] += "\n"
	}
}

// insertKrb5LinesAt returns lines with text inserted before index i. Each
// inserted element must already carry its own newline.
func insertKrb5LinesAt(lines []string, i int, text []string) []string {
	out := make([]string, 0, len(lines)+len(text))
	out = append(out, lines[:i]...)
	out = append(out, text...)
	out = append(out, lines[i:]...)
	return out
}

// insertKrb5SectionRelation appends the given relation line at the end of
// the [section]; a missing section is created at the end of the file.
func insertKrb5SectionRelation(content, section string, relation []string) (string, error) {
	lines := strings.SplitAfter(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	var text []string
	var at int
	_, end, ok := krb5SectionBounds(lines, section)
	if !ok {
		// Missing section: append it at the end of the file, making sure
		// the previous content is newline-terminated first.
		if content != "" && !strings.HasSuffix(content, "\n") {
			lines[len(lines)-1] += "\n"
		}
		text = []string{"[" + section + "]\n"}
		for _, rel := range relation {
			text = append(text, "    "+rel+"\n")
		}
		at = len(lines)
		if content == "" {
			at = 0
		}
	} else {
		text = make([]string, 0, len(relation))
		for _, rel := range relation {
			text = append(text, "    "+rel+"\n")
		}
		at = end
		ensureLineBreakBefore(lines, at)
	}

	next := insertKrb5LinesAt(lines, at, text)
	if unbalancedKrb5Braces(strings.Join(next, "")) {
		return "", fmt.Errorf("the krb5.conf brace structure cannot be reconciled by inserting this way")
	}
	return strings.Join(next, ""), nil
}

// insertKrb5RealmBlock appends the collected `REALM = { ... }` block text at
// the end of [realms] (or creates the section at the end of the file). The
// block Lines are byte-exact from the staged file — the value is written as
// it was read. Anything that prevents the append (a same-named block that
// should not exist anymore, an unrepresentable structure) is an error; the
// caller turns it into an explosion or, with --relaxed, a warning and keeps
// going.
func insertKrb5RealmBlock(content string, item fileSetting) (string, error) {
	lines := strings.SplitAfter(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	realmName := krb5RealmName(item.Key)

	blockText := make([]string, 0, len(item.Lines))
	for _, l := range item.Lines {
		blockText = append(blockText, strings.TrimSuffix(l, "\n")+"\n")
	}

	start, end, ok := krb5SectionBounds(lines, "realms")
	if !ok {
		// No [realms] section at all: create section + block at EOF.
		if content != "" && !strings.HasSuffix(content, "\n") {
			lines[len(lines)-1] += "\n"
		}
		text := []string{"[realms]\n"}
		text = append(text, blockText...)
		at := len(lines)
		if content == "" {
			at = 0
		}
		next := insertKrb5LinesAt(lines, at, text)
		if unbalancedKrb5Braces(strings.Join(next, "")) {
			return "", fmt.Errorf("the krb5.conf brace structure cannot be reconciled by appending the %q block", realmName)
		}
		return strings.Join(next, ""), nil
	}

	if krb5RealmBlockExists(lines, start, end, realmName) {
		return "", fmt.Errorf(
			"a %q realm block already exists, so the generated block cannot be appended without a duplicate",
			realmName)
	}

	ensureLineBreakBefore(lines, end)
	next := insertKrb5LinesAt(lines, end, blockText)
	if unbalancedKrb5Braces(strings.Join(next, "")) {
		return "", fmt.Errorf("the krb5.conf brace structure cannot be reconciled by appending the %q block", realmName)
	}
	return strings.Join(next, ""), nil
}

// krb5RealmName extracts the realm identity from a realm-block key.
func krb5RealmName(key string) string {
	return strings.TrimPrefix(key, "realms/")
}

// krb5RealmBlockExists reports whether the [realms] section already has a
// `REALM = {` block with the given (lower-cased) name. Header detection is
// depth-aware so an opening brace inside a nested subsection is not mistaken
// for a realm header.
func krb5RealmBlockExists(lines []string, start, end int, realm string) bool {
	depth := 0
	for i := start + 1; i < end; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		eq := strings.Index(t, "=")
		if depth == 0 && eq > 0 {
			name := strings.TrimSpace(t[:eq])
			v := strings.TrimSpace(t[eq+1:])
			if strings.HasSuffix(v, "{") && name != "" &&
				strings.EqualFold(strings.ToLower(name), realm) {
				return true
			}
		}
		if t == "}" {
			if depth > 0 {
				depth--
			}
			continue
		}
		if strings.HasSuffix(t, "{") && eq > 0 {
			depth++
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// shared formatting helpers
// ----------------------------------------------------------------------------

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
