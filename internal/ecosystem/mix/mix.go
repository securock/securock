package mix

import (
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "mix.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "mix" }

func (Ecosystem) OSVEcosystem() string { return "Hex" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var deps []core.Dependency
	rest := string(raw)
	for {
		name, kind, payload, next, ok := nextEntry(rest)
		if !ok {
			break
		}
		rest = next
		if name == "" {
			continue
		}
		switch kind {
		case "hex":
			version, digest := hexFields(payload)
			if version == "" {
				continue
			}
			deps = append(deps, core.Dependency{
				Ecosystem:  "hex",
				Resolver:   "mix",
				Registry:   "https://repo.hex.pm",
				SourceKind: core.SourceRegistry,
				Name:       name,
				Version:    version,
				Digest:     core.NormalizeDigest(digest),
			})
		case "git":
			version := firstQuoted(payload)
			if version == "" {
				version = "git"
			}
			deps = append(deps, core.Dependency{
				Ecosystem:  "hex",
				Resolver:   "mix",
				SourceKind: core.SourceGit,
				Name:       name,
				Version:    version,
			})
		case "path":
			version := firstQuoted(payload)
			if version == "" {
				version = "path"
			}
			deps = append(deps, core.Dependency{
				Ecosystem:  "hex",
				Resolver:   "mix",
				SourceKind: core.SourceFile,
				Name:       name,
				Version:    version,
			})
		}
	}
	return deps, nil
}

func nextEntry(raw string) (name, kind, payload, rest string, ok bool) {
	marker := `": {:`
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return "", "", "", "", false
	}
	nameStart := strings.LastIndex(raw[:idx], `"`)
	if nameStart < 0 {
		return "", "", "", raw[idx+len(marker):], true
	}
	name = raw[nameStart+1 : idx]
	after := raw[idx+len(marker):]
	kindEnd := strings.IndexAny(after, ",}")
	if kindEnd < 0 {
		return name, "", "", "", true
	}
	kind = strings.TrimSpace(strings.TrimPrefix(after[:kindEnd], ":"))
	return name, kind, after[kindEnd:], after[kindEnd:], true
}

func hexFields(payload string) (version, digest string) {
	quoted := quotedStrings(payload)
	if len(quoted) == 0 {
		return "", ""
	}
	version = quoted[0]
	for i := len(quoted) - 1; i >= 1; i-- {
		if len(quoted[i]) == 64 && isHex(quoted[i]) {
			return version, quoted[i]
		}
	}
	if len(quoted) >= 2 {
		return version, quoted[len(quoted)-1]
	}
	return version, ""
}

func firstQuoted(payload string) string {
	quoted := quotedStrings(payload)
	if len(quoted) == 0 {
		return ""
	}
	return quoted[0]
}

func quotedStrings(s string) []string {
	var out []string
	for {
		start := strings.Index(s, `"`)
		if start < 0 {
			return out
		}
		s = s[start+1:]
		end := strings.Index(s, `"`)
		if end < 0 {
			return out
		}
		out = append(out, s[:end])
		s = s[end+1:]
	}
}

func isHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
