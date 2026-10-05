package network

import (
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

// Provenance returns a registry origin when the configured sources agree.
// Mixed public and private sources, no sources, or any source that cannot be
// read as a remote registry (a local path, a malformed URL) are unknown ("").
func Provenance(ecosystem string, sources []string) string {
	var origins []string
	seen := map[string]struct{}{}
	for _, source := range sources {
		if strings.TrimSpace(source) == "" {
			continue
		}
		origin := Origin(source)
		if origin == "" {
			return ""
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	if len(origins) == 0 {
		return ""
	}

	allPublic := true
	for _, origin := range origins {
		if !Public(ecosystem, origin) {
			allPublic = false
			break
		}
	}
	if allPublic {
		if defs := DefaultRegistries()[ecosystem]; len(defs) > 0 {
			if canonical := Origin(defs[0]); canonical != "" {
				return canonical
			}
		}
		return origins[0]
	}
	if len(origins) == 1 {
		return origins[0]
	}
	return ""
}

func Public(ecosystem, registry string) bool {
	return public(nil, core.Dependency{Ecosystem: ecosystem, Registry: registry})
}
