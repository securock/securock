package mix

import (
	"os"
	"path/filepath"
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
	raw, err := core.ReadFile(core.Join(path, lockfileName))
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
			if repo == "hexpm" && !hexRedirected() {
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

// hexFields reads the positional hex tuple:
// :hex, :name, "version", "inner checksum", [managers], [deps], "repo", "outer checksum".
// The repo is only trusted at its position; older locks that omit it, or
// requirement strings inside the dependency list, never count as a repo.
func hexFields(payload string) (version, digest, repo string) {
	// payload starts at the comma after the :hex tag, so elems[0] is empty.
	elems := topLevel(payload)
	if len(elems) < 4 {
		return "", "", ""
	}
	version = unquote(elems[2])
	if version == "" {
		return "", "", ""
	}
	if len(elems) >= 8 {
		if outer := unquote(elems[7]); len(outer) == 64 && isHex(outer) {
			digest = outer
		}
	}
	if digest == "" {
		if inner := unquote(elems[3]); len(inner) == 64 && isHex(inner) {
			digest = inner
		}
	}
	if len(elems) >= 7 {
		repo = unquote(elems[6])
	}
	return version, digest, repo
}

func topLevel(s string) []string {
	var out []string
	depth := 0
	inString := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			if c == '\\' && i+1 < len(s) {
				i++
			} else if c == '"' {
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
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return ""
}

// hexRedirected reports whether hex is configured to fetch from somewhere other
// than repo.hex.pm, so a "hexpm" lock entry no longer proves a public origin.
func hexRedirected() bool {
	for _, env := range []string{"HEX_MIRROR", "HEX_REPO_URL", "HEX_API_URL"} {
		if strings.TrimSpace(os.Getenv(env)) != "" {
			return true
		}
	}
	for _, path := range hexConfigFiles() {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(raw)
		if strings.Contains(text, "mirror_url") || strings.Contains(text, "repo_url") || strings.Contains(text, "repos_key") {
			return true
		}
	}
	return false
}

func hexConfigFiles() []string {
	var paths []string
	if v := os.Getenv("HEX_HOME"); v != "" {
		paths = append(paths, filepath.Join(v, "hex.config"))
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		paths = append(paths, filepath.Join(v, "hex", "hex.config"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".hex", "hex.config"),
			filepath.Join(home, ".config", "hex", "hex.config"),
		)
	}
	return paths
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
