package yarn

import (
	"bufio"
	"bytes"
	"net/url"
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
	raw, err := core.ReadFile(core.Join(path, lockfileName))
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
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Checksum     string            `yaml:"checksum"`
	Dependencies map[string]string `yaml:"dependencies"`
}

func berryDeps(project string, raw []byte) ([]core.Dependency, error) {
	var lock berryLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var entries []entry
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
		// Virtual and located copies of a package share its descriptors and dependencies.
		e := entry{descriptors: descriptors(key), deps: pkg.Dependencies, berry: true}
		if _, ok := seen[id]; ok {
			e.duplicate = id
			entries = append(entries, e)
			continue
		}
		seen[id] = struct{}{}
		kind, tarball := classifyProtocol(protocol, locator)
		registry := ""
		if kind == core.SourceRegistry {
			// Yarn berry does not read .npmrc, so an unknown registry stays unknown.
			registry = yarnrc.Registry(project, name, tarball)
		}
		e.dep = core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "yarn",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(checksum(pkg.Checksum)),
		}
		entries = append(entries, e)
	}
	return build(project, entries), nil
}

func classicDeps(project string, raw []byte) ([]core.Dependency, error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		entries   []entry
		name      string
		version   string
		resolved  string
		integrity string
		descs     []string
		deps      map[string]string
		inDeps    bool
	)
	reset := func() {
		name, version, resolved, integrity, descs, deps, inDeps = "", "", "", "", nil, nil, false
	}
	flush := func() {
		if name == "" || version == "" {
			reset()
			return
		}
		kind, tarball := classifyResolved(resolved)
		registry := ""
		if kind == core.SourceRegistry {
			registry = npmrc.Registry(project, name, tarball)
		}
		entries = append(entries, entry{
			descriptors: descs,
			deps:        deps,
			dep: core.Dependency{
				Ecosystem:  "npm",
				Resolver:   "yarn",
				Registry:   registry,
				SourceKind: kind,
				Name:       name,
				Version:    version,
				Digest:     core.NormalizeDigest(integrity),
			},
		})
		reset()
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
			descs = descriptors(trim)
			continue
		}
		if indent(line) == 4 && inDeps {
			if depName, rng, ok := strings.Cut(trim, " "); ok {
				if deps == nil {
					deps = map[string]string{}
				}
				deps[unquote(depName)] = unquote(rng)
			}
			continue
		}
		if indent(line) != 2 {
			continue
		}
		key, value, ok := strings.Cut(trim, " ")
		inDeps = !ok && (trim == "dependencies:" || trim == "optionalDependencies:")
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
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return build(project, entries), nil
}

// entry is one lockfile record before edges and scopes are worked out.
type entry struct {
	dep         core.Dependency
	descriptors []string
	deps        map[string]string
	berry       bool
	// duplicate is set for a second record of an artifact already seen: it adds descriptors
	// and edges to that artifact but is not a new dependency.
	duplicate string
}

// descriptors splits a lockfile header into the "name@range" descriptors it answers for.
func descriptors(header string) []string {
	header = strings.TrimSuffix(strings.TrimSpace(header), ":")
	if i := strings.Index(header, "::"); i >= 0 && !strings.Contains(header[:i], ", ") {
		header = header[:i]
	}
	var out []string
	for _, part := range strings.Split(header, ", ") {
		if d := unquote(part); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// build turns records into dependencies with edges and scopes. Edges follow the descriptor
// each dependency was requested with; scopes start from the direct dependencies listed in
// package.json, which yarn.lock itself does not record.
func build(project string, entries []entry) []core.Dependency {
	var deps []core.Dependency
	index := map[string]int{}
	byDescriptor := map[string]int{}
	owner := make([]int, len(entries))
	for i, e := range entries {
		at := -1
		if e.duplicate != "" {
			at = index["npm:"+e.duplicate]
		} else {
			at = len(deps)
			index[core.Identity(e.dep)] = at
			deps = append(deps, e.dep)
		}
		owner[i] = at
		for _, d := range e.descriptors {
			if _, ok := byDescriptor[d]; !ok {
				byDescriptor[d] = at
			}
		}
	}

	for i, e := range entries {
		var edges []string
		for name, rng := range e.deps {
			if j, ok := lookup(byDescriptor, name, rng); ok {
				edges = append(edges, core.Identity(deps[j]))
			}
		}
		deps[owner[i]].DependsOn = core.UnionIdentities(deps[owner[i]].DependsOn, edges)
	}

	roots := map[string]string{}
	for _, group := range projectDependencies(project) {
		for depName, rng := range group.deps {
			if j, ok := lookup(byDescriptor, depName, rng); ok {
				id := core.Identity(deps[j])
				roots[id] = core.MergeScope(roots[id], group.scope)
			}
		}
	}
	core.ApplyScopes(deps, roots)
	return deps
}

// lookup finds the artifact a dependency range was resolved to. Classic lockfiles write
// name@range; berry writes name@npm:range for registry packages.
func lookup(byDescriptor map[string]int, name, rng string) (int, bool) {
	for _, d := range []string{name + "@" + rng, name + "@npm:" + rng} {
		if j, ok := byDescriptor[d]; ok {
			return j, true
		}
	}
	return 0, false
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
	// Berry records the archive of non-default registries as ::__archiveUrl=<escaped url>.
	if _, query, ok := strings.Cut(locator, "::"); ok {
		if values, err := url.ParseQuery(query); err == nil {
			if archive := values.Get("__archiveUrl"); strings.HasPrefix(archive, "https://") || strings.HasPrefix(archive, "http://") {
				return archive
			}
		}
	}
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
