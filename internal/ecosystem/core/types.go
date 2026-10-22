package core

import (
	"os"
	"path/filepath"
	"sort"
)

type Dependency struct {
	Ecosystem  string
	Resolver   string
	Registry   string
	Artifact   string
	Requested  string
	Resolved   string
	SourceKind string
	Name       string
	Version    string
	Filename   string
	Digest     string

	// Scope says how the package enters the project, when the lockfile records it.
	// Empty means the lockfile does not say.
	Scope string
	// DependsOn holds the Identity of each direct dependency that is also in the lockfile.
	// Empty means the lockfile records no edges, not that the package has no dependencies.
	DependsOn []string
}

const (
	ScopeRuntime  = "runtime"
	ScopeDev      = "dev"
	ScopeOptional = "optional"
)

var scopeRank = map[string]int{ScopeRuntime: 3, ScopeOptional: 2, ScopeDev: 1}

// MergeScope combines the scopes of two entries for the same artifact. A package needed at
// runtime anywhere is a runtime package, whichever copy says so.
func MergeScope(a, b string) string {
	if scopeRank[b] > scopeRank[a] {
		return b
	}
	return a
}

// UnionIdentities returns the sorted union of two identity lists.
func UnionIdentities(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, id := range a {
		set[id] = struct{}{}
	}
	for _, id := range b {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

const (
	SourceRegistry  = "registry"
	SourceWorkspace = "workspace"
	SourceGit       = "git"
	SourceFile      = "file"
	SourceURL       = "url"
)

type Ecosystem interface {
	Name() string
	OSVEcosystem() string
	Detect(path string) bool
	Dependencies(path string) ([]Dependency, error)
}

func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func Join(root, name string) string {
	return filepath.Join(root, name)
}

func Identity(dep Dependency) string {
	id := dep.Ecosystem + ":" + dep.Name
	if dep.Version != "" {
		id += "@" + dep.Version
	}
	if dep.Filename != "" {
		id += "#" + dep.Filename
	}
	return id
}
