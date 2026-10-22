package sbom

import (
	"net/url"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

// PURL returns the Package URL for an artifact, or "" when its ecosystem has no
// registered purl type (jsr and plain URL imports).
func PURL(a lockfile.Artifact) string {
	name := a.Subject.Name
	var typ string
	var path []string
	switch a.Subject.Ecosystem {
	case "npm":
		typ = "npm"
		path = strings.SplitN(name, "/", 2)
	case "pypi":
		typ = "pypi"
		path = []string{strings.ToLower(strings.ReplaceAll(name, "_", "-"))}
	case "cargo":
		typ, path = "cargo", []string{name}
	case "go":
		typ = "golang"
		path = strings.Split(strings.ToLower(name), "/")
	case "packagist":
		typ = "composer"
		path = strings.Split(strings.ToLower(name), "/")
	case "rubygems":
		typ, path = "gem", []string{name}
	case "nuget":
		typ, path = "nuget", []string{name}
	case "pub":
		typ, path = "pub", []string{name}
	case "hex":
		typ, path = "hex", []string{name}
	case "maven":
		typ = "maven"
		path = strings.SplitN(name, ":", 2)
	case "swift":
		typ = "swift"
		path = swiftPath(a)
	default:
		return ""
	}
	if len(path) == 0 || path[0] == "" {
		return ""
	}

	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	for _, seg := range path {
		b.WriteByte('/')
		b.WriteString(escape(seg))
	}
	if a.Version != "" {
		b.WriteByte('@')
		b.WriteString(escape(a.Version))
	}
	return b.String()
}

// swiftPath turns the repository location into purl path segments, dropping the
// transport and a trailing ".git".
func swiftPath(a lockfile.Artifact) []string {
	loc := a.Source.Registry
	if loc == "" {
		return strings.Split(a.Subject.Name, "/")
	}
	u, err := url.Parse(loc)
	if err != nil || u.Hostname() == "" {
		return strings.Split(a.Subject.Name, "/")
	}
	rest := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	segs := []string{u.Hostname()}
	if rest != "" {
		segs = append(segs, strings.Split(rest, "/")...)
	}
	return segs
}

// escape percent-encodes everything outside the RFC 3986 unreserved set, so "@" in an
// npm scope becomes %40 and "+" in a version becomes %2B, as the purl spec requires.
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}
