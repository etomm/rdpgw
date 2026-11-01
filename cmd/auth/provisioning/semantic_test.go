package provisioning

import "testing"

func TestSmbConfSemanticallyEqual(t *testing.T) {
	staged := `[global]
    security = ads
    realm = CORP.EXAMPLE.COM
    workgroup = CORP
    winbind use default domain = no
    dedicated keytab file = /var/lib/samba/rdpgw.keytab
`

	cases := []struct {
		name    string
		current string
		equal   bool
	}{
		{
			name: "identical content",
			current: `[global]
    security = ads
    realm = CORP.EXAMPLE.COM
    workgroup = CORP
    winbind use default domain = no
    dedicated keytab file = /var/lib/samba/rdpgw.keytab
`,
			equal: true,
		},
		{
			name: "formatting comments order and case differences are ignored",
			current: `# operator header
[global]
    dedicated keytab file = /var/lib/samba/rdpgw.keytab
    realm = corp.example.com
    workgroup   =   CORP

    winbind use default domain = no
    security = ads
[homes]
    path = /home
`,
			equal: true,
		},
		{
			name: "realm differs",
			current: `[global]
    security = ads
    realm = OTHER.EXAMPLE.COM
    workgroup = CORP
    winbind use default domain = no
    dedicated keytab file = /var/lib/samba/rdpgw.keytab
`,
			equal: false,
		},
		{
			name: "keytab path differs",
			current: `[global]
    security = ads
    realm = CORP.EXAMPLE.COM
    workgroup = CORP
    winbind use default domain = no
    dedicated keytab file = /etc/samba/other.keytab
`,
			equal: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			equal, _ := smbConfSemanticallyEqual(staged, tc.current)
			if equal != tc.equal {
				t.Errorf("equal = %v, want %v", equal, tc.equal)
			}
		})
	}
}

func TestSmbConfSeparatorMismatchWithoutContinuation(t *testing.T) {
	// A plain wrong separator is drift without the continuation hint.
	staged := "[global]\n    winbind use default domain = no\n"
	current := "[global]\n    winbind separator = +\n    winbind use default domain = no\n"
	equal, key := smbConfSemanticallyEqual(staged, current)
	if equal {
		t.Fatal("a non-default separator must be drift")
	}
	if key != "global/winbind separator" {
		t.Errorf("drift key = %q, want global/winbind separator", key)
	}
}

func TestSmbMergePlanSeparatorHandling(t *testing.T) {
	staged := "[global]\n    winbind use default domain = no\n" // default separator, omitted
	for _, tc := range []struct {
		name     string
		current  string
		conflict string
	}{
		{"omitted is not a conflict", "[global]\n    winbind use default domain = no\n", ""},
		{"explicit non-default conflicts", "[global]\n    winbind separator = +\n", "winbind separator"},
		{"continuation conflicts", "[global]\n    winbind separator = \\\\\n    winbind use default domain = no\n", "winbind separator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, conflicts := smbMergePlan(staged, tc.current)
			var got string
			if len(conflicts) > 0 {
				got = conflicts[0].Key
			}
			if got != tc.conflict {
				t.Errorf("conflict = %q, want %q", got, tc.conflict)
			}
		})
	}
}

func TestSmbMergePlanReportsEveryConflict(t *testing.T) {
	staged := "[global]\n    realm = CORP.EXAMPLE.COM\n    workgroup = CORP\n"
	current := "[global]\n    realm = OTHER.EXAMPLE.COM\n    workgroup = OTHER\n"
	_, conflicts := smbMergePlan(staged, current)
	if len(conflicts) != 2 {
		t.Fatalf("conflicts = %#v, want 2", conflicts)
	}
	if conflicts[0].Key != "realm" || conflicts[1].Key != "workgroup" {
		t.Errorf("conflict keys = %q, %q; want realm, workgroup", conflicts[0].Key, conflicts[1].Key)
	}
	if conflicts[0].Want != "CORP.EXAMPLE.COM" || conflicts[0].Current != "OTHER.EXAMPLE.COM" {
		t.Errorf("conflict values = %#v", conflicts[0])
	}
}

func TestSmbConfSeparatorDefaultAccepted(t *testing.T) {
	// Omitting the directive and writing one explicit backslash value are
	// both... the explicit form cannot exist (continuation), so only the
	// omission must equal the default.
	staged := "[global]\n    winbind use default domain = no\n"
	current := "[global]\n    winbind use default domain = yes\n"
	// Different value on another managed key: drift, but the separator itself
	// must compare equal (both default to backslash).
	equal, key := smbConfSemanticallyEqual(staged, current)
	if equal || key != "global/winbind use default domain" {
		t.Fatalf("equal=%v key=%q, want drift on winbind use default domain", equal, key)
	}
}

func TestKrb5ConfSemanticallyEqual(t *testing.T) {
	staged := `[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    dns_lookup_kdc = true

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.example.com:88
        kdc = dc2.example.com:88
        admin_server = dc1.example.com:749
    }

[domain_realm]
    .example.com = CORP.EXAMPLE.COM
`

	cases := []struct {
		name    string
		current string
		equal   bool
	}{
		{
			name: "same settings different formatting and order",
			current: `# operator krb5
[libdefaults]
    dns_lookup_kdc = true
    default_realm = CORP.EXAMPLE.COM

[realms]
    corp.example.com = {
        admin_server = dc1.example.com:749
        kdc = dc2.example.com:88
        kdc = dc1.example.com:88
    }

[domain_realm]
    .example.com = CORP.EXAMPLE.COM
`,
			equal: true,
		},
		{
			name: "extra operator settings are ignored",
			current: `[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    dns_lookup_kdc = true
    dns_lookup_realm = true
    forwardable = true

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.example.com:88
        kdc = dc2.example.com:88
        admin_server = dc1.example.com:749
    }

[domain_realm]
    .example.com = CORP.EXAMPLE.COM
`,
			equal: true,
		},
		{
			name: "missing kdc is drift",
			current: `[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    dns_lookup_kdc = true

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc1.example.com:88
        admin_server = dc1.example.com:749
    }

[domain_realm]
    .example.com = CORP.EXAMPLE.COM
`,
			equal: false,
		},
		{
			name: "different realm is drift",
			current: `[libdefaults]
    default_realm = OTHER.EXAMPLE.COM
    dns_lookup_kdc = true

[realms]
    OTHER.EXAMPLE.COM = {
        kdc = dc1.example.com:88
        kdc = dc2.example.com:88
        admin_server = dc1.example.com:749
    }

[domain_realm]
    .example.com = OTHER.EXAMPLE.COM
`,
			equal: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			equal, _ := krb5ConfSemanticallyEqual(staged, tc.current)
			if equal != tc.equal {
				t.Errorf("equal = %v, want %v", equal, tc.equal)
			}
		})
	}
}
