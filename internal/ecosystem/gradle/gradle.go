package gradle

import (
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "gradle.lockfile"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "gradle" }

func (Ecosystem) OSVEcosystem() string { return "Maven" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coord, configs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name, version, ok := mavenCoord(coord)
		if !ok {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		deps = append(deps, core.Dependency{
			Ecosystem:  "maven",
			Resolver:   "gradle",
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    version,
			Scope:      scopeOf(configs),
		})
	}
	return deps, nil
}

// scopeOf reads the configurations a dependency is locked for, such as
// "compileClasspath,runtimeClasspath". A dependency on a runtime classpath ships with the
// application; one that is only on test classpaths is development-only. Anything else, like
// compile-only and annotation processor dependencies, is neither shipped nor a test
// dependency, so the lockfile does not settle it.
func scopeOf(configs string) string {
	runtime, test, other := false, false, false
	for _, config := range strings.Split(configs, ",") {
		config = strings.ToLower(strings.TrimSpace(config))
		if config == "" {
			continue
		}
		switch {
		case isTest(config):
			test = true
		case strings.HasSuffix(config, "runtimeclasspath"):
			runtime = true
		default:
			other = true
		}
	}
	switch {
	case runtime:
		return core.ScopeRuntime
	case test && !other:
		return core.ScopeDev
	}
	return ""
}

func isTest(config string) bool {
	for _, prefix := range []string{"test", "androidtest", "debugandroidtest", "releaseunittest", "debugunittest"} {
		if strings.HasPrefix(config, prefix) {
			return true
		}
	}
	return false
}

func mavenCoord(coord string) (name, version string, ok bool) {
	coord = strings.TrimSpace(coord)
	if coord == "" || coord == "empty" {
		return "", "", false
	}
	parts := strings.Split(coord, ":")
	if len(parts) < 3 {
		return "", "", false
	}
	name = parts[0] + ":" + parts[1]
	version = parts[2]
	if name == ":" || version == "" {
		return "", "", false
	}
	return name, version, true
}
