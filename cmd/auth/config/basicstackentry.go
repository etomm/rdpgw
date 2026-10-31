package config

import (
	"encoding/json"
)

// BasicStackEntry is one block of the generated PAM stack.
type BasicStackEntry struct {
	// Backend is one of "winbind", "ldap", "unix" or "users".
	Backend string `json:"backend" yaml:"backend"`
	// Name references an Ldap profile (ldap backend only).
	Name string `json:"name" yaml:"name"`
	// Oath references an Oath policy attached to this backend.
	Oath string `json:"oath" yaml:"oath"`
}

// UnmarshalJSON accepts either the object form
//
//	{backend: ldap, name: corp, oath: totp}
//
// or a bare string, which is a shorthand for entries without options:
//
//   - corp    (an Ldap profile name -> ldap/corp)
//   - users   (a reserved backend name -> users)
//
// A bare string cannot carry an oath policy; use the object form for that.
// load() resolves reserved backend names and Ldap profile names.
//
// sigs.k8s.io/yaml converts YAML to JSON before decoding, so the hook must be
// UnmarshalJSON (an UnmarshalYAML method would never run).
func (e *BasicStackEntry) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		*e = BasicStackEntry{Name: name}
		return nil
	}

	type plain BasicStackEntry
	var v plain
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*e = BasicStackEntry(v)
	return nil
}
