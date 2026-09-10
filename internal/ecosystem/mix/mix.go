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
			version, digest, repo := hexFields(payload)
			if version == "" {
				continue
			}
			registry := ""
			if repo == "hexpm" {
				registry = "https://repo.hex.pm"
			}
			deps = append(deps, core.Dependency{
				Ecosystem:  "hex",
				Resolver:   "mix",
				Registry:   registry,
				SourceKind: core.SourceRegistry,
				Name:       name,
				Version:    version,
				Digest:     core.NormalizeDigest(digest),
			})
		case "git":
			quoted := quotedStrings(payload)
			repo, rev := "", ""
			if len(quoted) > 0 {
				repo = quoted[0]
			}
			if len(quoted) > 1 {
				rev = quoted[1]
			}
			version := rev
			if version == "" {
				version = "git"
			}
			deps = append(deps, core.Dependency{
				Ecosystem:  "hex",
				Resolver:   "mix",
				SourceKind: core.SourceGit,
				Name:       name,
				Version:    version,
				Artifact:   core.RemoteLocation(repo),
				Resolved:   rev,
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
	end := closeTuple(after)
	if end < 0 {
		return name, kind, after[kindEnd:], "", true
	}
	return name, kind, after[kindEnd:end], after[end+1:], true
}

func closeTuple(s string) int {
	depth := 1
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func hexFields(payload string) (version, digest, repo string) {
	quoted := quotedStrings(payload)
	if len(quoted) == 0 {
		return "", "", ""
	}
	version = quoted[0]
	for i := len(quoted) - 1; i >= 1; i-- {
		if len(quoted[i]) == 64 && isHex(quoted[i]) {
			if digest == "" {
				digest = quoted[i]
			}
			continue
		}
		if quoted[i] != "" {
			repo = quoted[i]
			break
		}
	}
	return version, digest, repo
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
