package yarn

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
	"github.com/securock/securock/internal/yarnrc"
	"gopkg.in/yaml.v3"
)

const lockfileName = "yarn.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "yarn" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}
	if berry(raw) {
		return berryDeps(path, raw)
	}
	return classicDeps(path, raw)
}

func berry(raw []byte) bool {
	return bytes.Contains(raw, []byte("__metadata:")) || bytes.Contains(raw, []byte("\n  resolution:"))
}

type berryLock map[string]berryPkg

type berryPkg struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
	Checksum   string `yaml:"checksum"`
}

func berryDeps(project string, raw []byte) ([]core.Dependency, error) {
	var lock berryLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for key, pkg := range lock {
		if key == "__metadata" || pkg.Version == "" {
			continue
		}
		locator := pkg.Resolution
		if locator == "" {
			locator = key
		}
		name, protocol := parseLocator(locator)
		if name == "" {
			continue
		}
		id := name + "@" + pkg.Version
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		kind, tarball := classifyProtocol(protocol, locator)
		registry := ""
		if kind == core.SourceRegistry {
			registry = yarnrc.Registry(project, name, tarball)
			if registry == "" {
				registry = npmrc.Registry(project, name, tarball)
			}
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "yarn",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(checksum(pkg.Checksum)),
		})
	}
	return deps, nil
}

func classicDeps(project string, raw []byte) ([]core.Dependency, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		deps      []core.Dependency
		name      string
		version   string
		resolved  string
		integrity string
	)
	flush := func() {
		if name == "" || version == "" {
			name, version, resolved, integrity = "", "", "", ""
			return
		}
		kind, tarball := classifyResolved(resolved)
		registry := ""
		if kind == core.SourceRegistry {
			registry = npmrc.Registry(project, name, tarball)
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "yarn",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(integrity),
		})
		name, version, resolved, integrity = "", "", "", ""
	}

	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if indent(line) == 0 && strings.HasSuffix(trim, ":") {
			flush()
			name, _ = parseLocator(strings.TrimSuffix(trim, ":"))
			continue
		}
		if indent(line) != 2 {
			continue
		}
		key, value, ok := strings.Cut(trim, " ")
		if !ok {
			continue
		}
		value = unquote(value)
		switch key {
		case "version":
			version = value
		case "resolved":
			resolved = value
		case "integrity":
			integrity = value
		}
	}
	flush()
	return deps, sc.Err()
}

func indent(line string) int {
	n := 0
	for _, c := range line {
		if c == ' ' {
			n++
			continue
		}
		if c == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func parseLocator(raw string) (name, protocol string) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, ","); i >= 0 {
		raw = raw[:i]
	}
	raw = unquote(strings.TrimSuffix(raw, ":"))
	if i := strings.Index(raw, "::"); i >= 0 {
		raw = raw[:i]
	}
	at := strings.LastIndex(raw, "@")
	if at <= 0 {
		return raw, ""
	}
	name = raw[:at]
	rest := raw[at+1:]
	protocol, _, _ = strings.Cut(rest, ":")
	if protocol == rest {
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			return name, "https"
		}
		return name, "npm"
	}
	return name, protocol
}

func classifyProtocol(protocol, locator string) (kind, tarball string) {
	switch protocol {
	case "workspace":
		return core.SourceWorkspace, ""
	case "file", "link", "portal", "patch":
		return core.SourceFile, "file:local"
	case "git", "github", "gitlab", "git+ssh", "git+http", "git+https":
		return core.SourceGit, ""
	case "http", "https":
		if tarball = tarballURL(locator); tarball != "" {
			return core.SourceRegistry, tarball
		}
		return core.SourceURL, ""
	default:
		if tarball = tarballURL(locator); tarball != "" {
			return core.SourceRegistry, tarball
		}
		return core.SourceRegistry, ""
	}
}

func classifyResolved(resolved string) (kind, tarball string) {
	resolved = strings.TrimSpace(resolved)
	if i := strings.Index(resolved, "#"); i >= 0 && !strings.Contains(resolved, "://") {
		resolved = resolved[:i]
	}
	switch {
	case resolved == "":
		return core.SourceRegistry, ""
	case strings.HasPrefix(resolved, "file:") || strings.HasPrefix(resolved, "link:"):
		return core.SourceFile, resolved
	case strings.HasPrefix(resolved, "git+") || strings.HasPrefix(resolved, "git://") || strings.HasPrefix(resolved, "github:"):
		return core.SourceGit, ""
	case strings.HasPrefix(resolved, "https://") || strings.HasPrefix(resolved, "http://"):
		return core.SourceRegistry, resolved
	default:
		return core.SourceURL, ""
	}
}

func tarballURL(locator string) string {
	for _, prefix := range []string{"https://", "http://"} {
		i := strings.Index(locator, prefix)
		if i >= 0 {
			return locator[i:]
		}
	}
	return ""
}

func checksum(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.LastIndex(raw, "/"); i >= 0 {
		raw = raw[i+1:]
	}
	return raw
}
