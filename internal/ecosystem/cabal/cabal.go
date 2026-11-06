package cabal

import (
	"regexp"
	"sort"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const (
	lockfileName    = "cabal.project.freeze"
	projectFileName = "cabal.project"
	hackage         = "https://hackage.haskell.org"
)

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "cabal" }

func (Ecosystem) OSVEcosystem() string { return "Hackage" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

// pinned matches a resolved package, any.aeson ==2.2.1.0. Ranges, flags, "installed"
// entries and qualified (setup.*) constraints do not name a version to record.
var pinned = regexp.MustCompile(`^any\.([A-Za-z0-9][A-Za-z0-9_-]*)\s*==\s*([0-9]+(?:\.[0-9]+)*)$`)

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}
	fields := parseFields(string(raw))

	registry := ""
	if hackageOnly(fields["active-repositories"]) && !customRepository(path) {
		registry = hackage
	}

	seen := map[string]bool{}
	var deps []core.Dependency
	for _, item := range strings.Split(fields["constraints"], ",") {
		m := pinned.FindStringSubmatch(strings.TrimSpace(item))
		if m == nil {
			continue
		}
		key := m[1] + "@" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		// index-state is a snapshot of the registry, and a freeze file carries no hashes,
		// so no digest is recorded.
		deps = append(deps, core.Dependency{
			Ecosystem:  "hackage",
			Resolver:   "cabal",
			Registry:   registry,
			SourceKind: core.SourceRegistry,
			Name:       m[1],
			Version:    m[2],
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// parseFields reads "key: value" fields. Indented lines continue the previous field, which
// is how a long constraints list is written. Comment lines are dropped.
func parseFields(text string) map[string]string {
	fields := map[string]string{}
	key := ""
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if key != "" {
				fields[key] += " " + trimmed
			}
			continue
		}
		name, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			key = ""
			continue
		}
		key = strings.ToLower(strings.TrimSpace(name))
		fields[key] = strings.TrimSpace(value)
	}
	return fields
}

// hackageOnly is true when the freeze file states its repositories and every one of them
// is hackage.haskell.org. A missing line proves nothing: cabal config can add others.
func hackageOnly(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, repo := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		name, _, _ := strings.Cut(repo, ":")
		if name != "hackage.haskell.org" {
			return false
		}
	}
	return true
}

// customRepository reports whether cabal.project declares a repository stanza, which can
// redefine where hackage.haskell.org points. An unreadable file is treated as absent only
// when it does not exist.
func customRepository(path string) bool {
	file := core.Join(path, projectFileName)
	if !core.FileExists(file) {
		return false
	}
	raw, err := core.ReadFile(file)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "repository ") {
			return true
		}
	}
	return false
}
