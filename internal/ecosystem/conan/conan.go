package conan

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "conan.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "conan" }

// OSV has no ConanCenter ecosystem; osv.QueryEcosystem skips these artifacts so they stay
// unknown rather than being reported clean.
func (Ecosystem) OSVEcosystem() string { return "" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock struct {
		Version       string   `json:"version"`
		Requires      []string `json:"requires"`
		BuildRequires []string `json:"build_requires"`
		PythonRequire []string `json:"python_requires"`
		GraphLock     any      `json:"graph_lock"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	if lock.GraphLock != nil {
		return nil, errors.New("conan 1 lockfiles (graph_lock) are not supported")
	}

	// config_requires are Conan configuration packages, not project dependencies.
	merged := map[string]core.Dependency{}
	add := func(refs []string, scope string) {
		for _, ref := range refs {
			dep, ok := parse(ref)
			if !ok {
				continue
			}
			dep.Scope = scope
			key := dep.Name + "@" + dep.Version
			if prev, ok := merged[key]; ok {
				prev.Scope = core.MergeScope(prev.Scope, scope)
				merged[key] = prev
				continue
			}
			merged[key] = dep
		}
	}
	add(lock.Requires, core.ScopeRuntime)
	add(lock.BuildRequires, core.ScopeDev)
	add(lock.PythonRequire, core.ScopeDev)

	deps := make([]core.Dependency, 0, len(merged))
	for _, dep := range merged {
		deps = append(deps, dep)
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

// parse reads name/version[@user/channel][#recipe_revision[%timestamp]]. The lockfile does
// not record which remote served the recipe, so no registry is set and the source stays
// unproven. The recipe revision identifies the recipe, not a downloadable file, so it is
// kept as Resolved and never as a digest.
func parse(ref string) (core.Dependency, bool) {
	ref = strings.TrimSpace(ref)
	revision := ""
	if i := strings.Index(ref, "#"); i >= 0 {
		revision = ref[i+1:]
		ref = ref[:i]
		if j := strings.Index(revision, "%"); j >= 0 {
			revision = revision[:j]
		}
	}
	if i := strings.Index(ref, "%"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name, version, ok := strings.Cut(ref, "/")
	if !ok || name == "" || version == "" {
		return core.Dependency{}, false
	}
	return core.Dependency{
		Ecosystem:  "conan",
		Resolver:   "conan",
		SourceKind: core.SourceRegistry,
		Name:       name,
		Version:    version,
		Resolved:   revision,
	}, true
}
