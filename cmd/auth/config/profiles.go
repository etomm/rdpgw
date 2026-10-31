package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// NamedProfile is implemented by a configuration profile that carries its
// name. WithProfileName returns a copy with the name set, which lets Profiles
// keep the value's name and the map key in sync.
type NamedProfile[T any] interface {
	ProfileName() string
	WithProfileName(string) T
}

// Profiles is a set of profiles addressed by name. Keys are the trimmed,
// lowercased profile names, and every value carries the same name with the
// spelling used in the configuration.
//
// Two YAML shapes are accepted. The mapping form uses the name as the key:
//
//	Ldap:
//	  corp-ldap:
//	    host: ldap.example.com
//
// The list form used by existing configurations is still decoded and indexed
// by the entry's name:
//
//	Ldap:
//	  - name: corp-ldap
//	    host: ldap.example.com
type Profiles[T NamedProfile[T]] map[string]T

// UnmarshalJSON accepts both the mapping form and the legacy list form. In
// both cases duplicate names (case-insensitively) are rejected and the value's
// Name is set from the key. Exact duplicate mapping keys are collapsed by the
// YAML-to-JSON conversion before this method runs; case variants are caught
// here.
func (p *Profiles[T]) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	out := make(Profiles[T])
	add := func(name string, profile T) error {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if key == "" {
			return errors.New("profile name must be set")
		}
		if _, exists := out[key]; exists {
			return fmt.Errorf("duplicate profile name %q", name)
		}
		out[key] = profile.WithProfileName(name)
		return nil
	}

	switch data[0] {
	case '[':
		var profiles []T
		if err := json.Unmarshal(data, &profiles); err != nil {
			return err
		}
		for i, profile := range profiles {
			if err := add(profile.ProfileName(), profile); err != nil {
				return fmt.Errorf("profile %d: %w", i+1, err)
			}
		}
	case '{':
		var profiles map[string]T
		if err := json.Unmarshal(data, &profiles); err != nil {
			return err
		}
		for name, profile := range profiles {
			if inner := strings.TrimSpace(profile.ProfileName()); inner != "" && !strings.EqualFold(inner, name) {
				return fmt.Errorf("profile name %q does not match its key %q", inner, name)
			}
			if err := add(name, profile); err != nil {
				return err
			}
		}
	default:
		return errors.New("profiles must be a mapping or a list")
	}

	*p = out
	return nil
}
