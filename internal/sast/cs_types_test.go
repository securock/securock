package sast

import (
	"sort"
	"strings"
	"testing"
)

// A spec key such as System.Security.Cryptography.HMACSHA256 only matches code that writes the
// bare type name when simpleTypes maps that name back to the same namespace.
func TestCSharpSpecKeysResolve(t *testing.T) {
	var missing []string
	// Two namespaces may share a type name (SqlCommand); the bare name resolves to one of them,
	// which is enough when the spec treats both alike.
	check := func(key string) {
		parts := strings.Split(key, ".")
		if !csSpec.pkgRoots[parts[0]] || len(parts) < 2 {
			return
		}
		for i := 1; i < len(parts); i++ {
			if q, ok := csSpec.simpleTypes[parts[i]]; ok {
				if q == strings.Join(parts[:i+1], ".") {
					return
				}
				if _, twin := csSpec.sinks[q+strings.TrimPrefix(key, strings.Join(parts[:i+1], "."))]; twin {
					return
				}
			}
		}
		missing = append(missing, key)
	}
	for k := range csSpec.sinks {
		check(k)
	}
	for k := range csSpec.misuse {
		check(k)
	}
	for k := range csSpec.sanitizers {
		check(k)
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("%s cannot be reached from a bare type name", k)
	}
}
