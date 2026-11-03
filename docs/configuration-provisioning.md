# Configuration provisioning (`rdpgw-auth`)

`rdpgw-auth` prepares the system files a winbind-capable deployment needs
before it joins the domain or serves authentication. This document describes
what is written, and how the merge of the two configuration files works:
`smb.conf` and `krb5.conf` share one comparison and one policy - only their
format normalization differs.

Related documents:

- [docs/advanced-auth-configuration.md](advanced-auth-configuration.md) - the
  configuration reference (`AuthProtocols`, `Winbind`, profiles).
- [docs/ntlm-authentication.md](ntlm-authentication.md) and
  [docs/kerberos-authentication.md](kerberos-authentication.md) - protocol
  setup.
- [docs/pam-authentication.md](pam-authentication.md) - hand-written vs
  generated PAM stacks.

## 1. What is provisioned

Provisioning runs when the configuration has *winbind capability* (a
Kerberos keytab share, or the winbind NTLM/Basic backend). Without it,
neither `smb.conf` nor `krb5.conf` is touched at all.

| Artifact | When | Behavior |
|---|---|---|
| `/tmp/rdpgw/smb.conf`, `/tmp/rdpgw/krb5.conf` | always with winbind capability | rendered from embedded templates; this is the **reference** the operator file is compared against |
| `/etc/samba/smb.conf` | always with winbind capability | installed when missing, merged otherwise |
| `/etc/krb5.conf` | always with winbind capability | installed when missing, merged otherwise |
| `AuthProtocols.Kerberos.Krb5ConfPath` | only with a Kerberos keytab share | atomic copy of the reconciled `krb5.conf` for the gateway; defaults to `dir(KeytabPath)/krb5.conf` (`/var/lib/samba/krb5.conf` with the default keytab) |
| `/etc/pam.d/<service>` + `/tmp/rdpgw/users.pwd`, referenced LDAP profiles, `session_manager.sh` | only with `AuthProtocols.Basic.Enabled` | generated; a writable PAM file is overwritten, a read-only differing one is kept with a warning. `users.pwd` only when the stack uses the `users` backend, LDAP profiles only for referenced `Ldap` entries; see [pam-authentication.md](pam-authentication.md) |
| Samba runtime dirs and `secrets.ldb` | only when the daemon supervises `winbindd` | created before the join; the host owns them in external-winbind mode |

The merge policy below applies only to `/etc/samba/smb.conf` and
`/etc/krb5.conf`. The generated PAM files and the Samba runtime state have
their own behavior and are not part of this merge.

## 2. Merge policy for `smb.conf` and `krb5.conf` (strict vs `--relaxed`)

`smb.conf` and `krb5.conf` follow the same policy. Existing operator values
are **never replaced** in any mode: the merge only appends missing settings
and reports differences.

| Situation | strict (default) | `--relaxed` |
|---|---|---|
| File missing | installed | installed |
| Missing generated settings, writable file | appended | appended |
| Operator value/text differs | daemon exits, error names every conflict | warning, keeps running |
| Settings cannot be appended (read-only target, `smb.conf` continuation hazard, unbalanced krb5 braces) | daemon exits | warning, keeps running |
| Missing file that cannot be created | daemon exits | daemon exits |

A read-only file that already carries
every generated setting is accepted without writing; a read-only file with
missing or differing settings is drift - strict mode stops, and `--relaxed`
warns and keeps running. `--relaxed` exists for long-lived systemd
deployments, where the operator fully owns the files and an outage over a
value difference is worse than a warning; containers keep the default so
drift surfaces at deploy time. In both modes the staged files under
`/tmp/rdpgw/` are the reconciliation reference named in the drift warnings.

## 3. The shared merge model

The merge is three stages, identical for `smb.conf` and `krb5.conf`:

```
parse/normalize (per format)  →  compare (one method)  →  insert (per format anchors)
```

Each parser produces a flat list of `fileSetting` values
(`cmd/auth/provisioning/semantic.go`):

```go
type fileSetting struct {
	Key     string   // global/<tag>, <section>/<tag>, or realms/<REALM>
	Value   string   // raw value as written; the per-format normalizer makes
	                 // it comparable (for a realm block: the whole collected
	                 // { ... } text)
	Lines   []string // ready-to-write text in the native format
	Section string   // [global] | [libdefaults] | [domain_realm] | [realms]
}
```

`planSettings` is the shared comparison:

- `Key` present only in the generated file → **missing**: `Lines` are
  inserted;
- `Key` present in both with different `Value` → **conflict**: reported with
  the operator text next to the generated one; never replaced;
- extra operator settings, comments and unrelated sections are accepted and
  never touched.

Realm blocks add one rule on top: they are matched by lower-cased name (so a
spelling difference can never append a duplicate block) while the exact
upper-case spelling is compared as part of the identity (see §5).

Only the per-format normalization and the insertion anchor differ. The
comparison never re-derives text: insertion writes the `Lines` that were
captured from the staged file.

## 4. `smb.conf` normalization {#smbconf}

Derived from Samba's own parser (`lib/util/tini.c`, `lib/param/loadparm.c`,
`lib/util/util_strlist_v3.c`); the rules that matter here:

- `[sections]` headers; `#`/`;` comment lines; blank lines ignored.
- `name = value`: the **first** `=` separates; names are case-insensitive;
  runs of inner whitespace collapse to one space.
- A line ending in `\` (or `\ `) **continues** onto the next line; the
  backslash is removed and the next line appended. There is **no**
  backslash-escape processing - `\s`, `\\`, `\"` are literal. A value cannot
  *end* with a lone backslash (it would continue the line).
- String values keep quotes literally; only list-typed values
  (`sync machine password to keytab` is a `cmdlist`) strip surrounding
  quotes during list tokenization. That is why the template quotes that one
  value and nothing else.
- Values compare case-insensitively, **except keytab paths** (the filesystem
  is case-sensitive). The managed keys are the `[global]` parameters of the
  generated template.

Normalization result: one `global/<tag>` setting per parameter, with the
logical line (continuation resolved) as its `Lines`. A generated file
without the `winbind separator` directive is not a gap: omitting it
expresses Samba's backslash default, and the comparison treats it as such.
Any other operator separator is a conflict (never replaced).

**Insertion anchor**: the end of `[global]` - before the next section header
or EOF - because Samba rejects global parameters found in a service section.
If the last `[global]` line ends in a continuation backslash, appending
would be swallowed: that is a strict startup failure / relaxed warning.

## 5. `krb5.conf` normalization {#krb5conf}

Derived from the MIT Kerberos `krb5.conf` documentation: an INI file with a
strange quoting after the `=`. Sections are `[name]`; lines starting with
`#` or `;` are comments; relations are `key = value` or `key = { ... }`;
there is no line continuation and no quoting. Repeated relations are legal
lists (krb5's way of listing KDCs), but every key managed outside a realm
block is a single relation.

The braces are part of the **value**, exactly as a `\` continuation is part
of an smb.conf value:

| smb.conf marker | krb5.conf marker | Normalized setting |
|---|---|---|
| `key = value` | `key = value` | `<section>/<key>` → value |
| trailing `\` continues the value | `REALM = {` … `}` is one value | `realms/<REALM>` → collected text from `{` to `}` |

A `[realms]` block is therefore **one setting**:

```ini
[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.corp.example.com:88
        kdc = dc2.corp.example.com:88
    }
```

becomes `realms/CORP.EXAMPLE.COM` with the value

```
{
        kdc = dc1.corp.example.com:88
        kdc = dc2.corp.example.com:88
    }
```

The interior is kept verbatim: leading spaces, blank lines, comments, nested
subsections (e.g. `auth_to_local_names = { ... }`) and EOL characters
included; only CRLF is normalized to LF. Section and tag names (other than
the realm identity below) are case-insensitive; **values compare verbatim**.
No individual `kdc` line inside an existing block is ever compared or
merged.

**Realm names are an identity and must be upper case** (the AD convention
for realms). They are matched case-insensitively so a spelling difference
can never append a duplicate block, but the spelling itself is compared:
`corp.example.com = { … }` against the generated `CORP.EXAMPLE.COM = { … }`
is drift (strict startup failure / `--relaxed` warning), never an equal or a new
setting. The same applies to values that are realms: `default_realm` and the
right-hand side of `[domain_realm]` mappings compare against the generated
upper-case spelling.

Single-line settings are managed for `[libdefaults]` and `[domain_realm]`
(the relations of the generated template: `default_realm`,
`dns_lookup_realm`, `dns_lookup_kdc` and the domain mappings).

**Value safety**: a configured value that contains `{`, `}`, a newline or a
control character is rejected before rendering - it would open/close a
subsection or swallow relations. (The smb.conf hazard is a trailing `\`
instead.)

**Insertion anchor**: single relations go at the end of their section;
a missing realm block is appended at the end of `[realms]` (or the section
is created at EOF) using the staged block byte for byte. An existing block
with the same realm name (in any case) is never duplicated: it is either
equal or reported as drift above; the insertion layer additionally refuses
to append if such a block is still present. After every insertion the brace
structure is re-verified; source files with unbalanced braces are never
merged.

## 6. Merge outcomes at a glance

| Generated | Operator file | Result |
|---|---|---|
| `[global] realm = CORP.EXAMPLE.COM` | `realm = OTHER.EXAMPLE.COM` | conflict (strict startup failure / relaxed warning), operator value kept |
| `[global] dedicated keytab file = …` | absent | appended inside `[global]` |
| `[libdefaults] dns_lookup_kdc = true` | absent | appended at the end of `[libdefaults]` |
| `[domain_realm] .corp.example.com = CORP.EXAMPLE.COM` | absent | appended at the end of `[domain_realm]` |
| `[realms] CORP.EXAMPLE.COM = { … }` | absent | whole block appended verbatim |
| `[realms] CORP.EXAMPLE.COM = { … }` | same name, different text (extra KDC, other indentation, extra subsection) | conflict; block never merged into or replaced |
| `[realms] CORP.EXAMPLE.COM = { … }` | block named `corp.example.com`, identical interior | conflict: realm names must be upper case; no case-wise duplicate is appended |
| - | extra comments, settings and unrelated sections | untouched |

## 7. Operator guidance

- **Let the daemon generate the files.** They are deterministic from the
  configuration; mounting is only needed to pin operator-specific settings.
- **Writable mount**: missing generated settings are appended in place;
  existing values stay.
- **Read-only mount** (ConfigMap subPath): the file must already carry the
  generated settings, or strict mode stops the daemon and `--relaxed` warns;
  reconcile against `/tmp/rdpgw/smb.conf` and `/tmp/rdpgw/krb5.conf`.
- **systemd hosts**: combine `RDPGW_AUTH_EXTERNAL_WINBIND=1` (host owns
  winbindd) with `--relaxed` (host owns the files); see the unit example in
  [docs/ntlm-authentication.md](ntlm-authentication.md#systemd-service).
- **Troubleshooting**: the generated reference files are listed in every
  warning or startup failure; diff them against the mounted target to see exactly
  what differs.

## 8. Sources of truth

| Format | Sources |
|---|---|
| smb.conf | Samba source: `lib/util/params.c` (`pm_process`), `lib/util/tini.c` (`tini_parse`, `get_line`), `lib/param/loadparm.c`, `lib/util/util_strlist_v3.c` (`str_list_make_v3`), `docs-xml/smbdotconf/**`. Snapshot: `lib/util/params.c` @ `f6fddd2232c9f94b591d52b5689d3ee03cc19be6`. |
| krb5.conf | MIT Kerberos documentation, `krb5.conf`: <https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html> |

Known parser details we deliberately reproduce (not "fix"):

- smb.conf: a trailing `\` is always a continuation; `\\` does not escape it.
  Hence the default winbind separator is rendered by omitting the directive.
- smb.conf: only list-typed values have quotes stripped
  (`sync machine password to keytab`); string values keep them literally.
- smb.conf: `winbind use default domain = no` in the generated template is
  intentional and independent of `Winbind.StripDomain` (which normalizes the
  name outside winbindd).
- krb5.conf: a `}` line ends the enclosing block, so nested subsections are
  tracked by brace depth when collecting a realm block's text.

## 9. Conformance examples

| Input | Expected normalization |
|---|---|
| smb: `x = C:\path\` + newline + `y` | value `x = C:\pathy` (continuation joins without adding a space) |
| smb: `winbind separator = \` | not representable; the parser swallows the next line - the template omits it instead |
| smb: `sync machine password to keytab = "/k:…"` | quotes removed by list tokenization; stored value without quotes |
| smb: `realm = CORP.EXAMPLE.COM` vs `corp.example.com` | equal (case-insensitive value) |
| smb: `dedicated keytab file = /A.keytab` vs `/a.keytab` | **different** (keytab paths are case-sensitive) |
| krb5: `[realms]` block with nested `auth_to_local_names = { … }` | one `realms/<REALM>` value; nested braces kept inside the collected text; the block ends at its own `}` |
| krb5: realm block without the generated `kdc` lines | different collected text → conflict (never merged into) |
| krb5: realm block spelled `corp.example.com`, identical interior | drift to `CORP.EXAMPLE.COM`: realm names must be upper case (strict startup failure / relaxed warning) |
| krb5: `default_realm = EX.FI` vs `CORP.EXAMPLE.COM` | different value → conflict |
| krb5: unbalanced `{` | never merged; strict startup failure / relaxed warning |
| smb/krb5: operator file without a trailing newline | the merge inserts a newline before the first appended setting, so it stays on its own line |

## 10. Troubleshooting

- **The daemon exits with `operator action required`** - strict mode found
  drift. The message names every conflicting setting, shows the operator value
  next to the generated one, and points at the staged reference file under
  `/tmp/rdpgw/`. Update the mounted file to match, fix the rdpgw-auth
  configuration, or run with `--relaxed`.
- **The daemon exits with `cannot add the required settings`** - the target is
  read-only (ConfigMap `subPath`, immutable image layer) or the `[global]`
  section ends in a continuation backslash. Make the file writable, remove the
  continuation, or use `--relaxed` (the daemon keeps running but the operator
  file wins).
- **`krb5.conf braces are unbalanced`** - the file cannot be merged safely.
  Fix the missing/extra `}`; no insertion is attempted.
- **A realm block is never merged** - this is intentional: a realm block is one
  verbatim value. A differing block (extra KDC, other indentation, extra
  subsection, lower-case realm name) is drift, not something the daemon
  rewrites.
- **`winbind separator` conflicts** - the generated file expresses the default
  backslash by omitting the directive. Any explicitly written separator other
  than the backslash default is drift; the directive cannot be written with a
  backslash because smb.conf would treat it as a line continuation.
- **Which files does it touch?** - only with winbind capability:
  `/etc/samba/smb.conf`, `/etc/krb5.conf`, and the staging copies under
  `/tmp/rdpgw/`. Without winbind capability provisioning is a no-op. The PAM
  file is only generated when `AuthProtocols.Basic` is enabled.
- **Compare by hand** - diff the operator target against the staged reference:

  ```bash
  diff -u /etc/samba/smb.conf /tmp/rdpgw/smb.conf
  diff -u /etc/krb5.conf /tmp/rdpgw/krb5.conf
  ```
