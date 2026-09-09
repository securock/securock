package network

import (
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/policy"
)

func DefaultRegistries() map[string][]string {
	return map[string][]string{
		"npm": {
			"https://registry.npmjs.org",
		},
		"cargo": {
			"https://index.crates.io",
			"https://github.com/rust-lang/crates.io-index",
		},
		"go": {
			"https://proxy.golang.org",
		},
		"pypi": {
			"https://pypi.org",
			"https://pypi.org/simple",
		},
		"packagist": {
			"https://repo.packagist.org",
			"https://packagist.org",
		},
		"rubygems": {
			"https://rubygems.org",
		},
		"nuget": {
			"https://api.nuget.org",
		},
		"pub": {
			"https://pub.dev",
		},
		"jsr": {
			"https://jsr.io",
		},
	}
}

func Allow(mode policy.Mode, allowlist map[string][]string, dep core.Dependency) bool {
	if !remote(dep) {
		return false
	}
	switch mode {
	case policy.ModeOffline:
		return false
	case policy.ModeAllowAll:
		return true
	default:
		return public(allowlist, dep)
	}
}

func public(allowlist map[string][]string, dep core.Dependency) bool {
	if dep.Ecosystem == "go" && goPrivate(dep.Name) {
		return false
	}
	allowed := allowlist[dep.Ecosystem]
	if len(allowed) == 0 {
		allowed = DefaultRegistries()[dep.Ecosystem]
	}
	if dep.Registry == "" {
		return false
	}
	got := parse(dep.Registry)
	if got == nil {
		return false
	}
	for _, prefix := range allowed {
		want := parse(prefix)
		if want != nil && registryMatch(got, want) {
			return true
		}
	}
	return false
}

func registryMatch(got, prefix *url.URL) bool {
	if !strings.EqualFold(got.Scheme, prefix.Scheme) {
		return false
	}
	if !strings.EqualFold(got.Host, prefix.Host) {
		return false
	}
	gotPath := pathSegments(got.Path)
	prefixPath := pathSegments(prefix.Path)
	if len(gotPath) < len(prefixPath) {
		return false
	}
	for i := range prefixPath {
		if gotPath[i] != prefixPath[i] {
			return false
		}
	}
	return true
}

func pathSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func Origin(raw string) string {
	u := parse(raw)
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func RegistryURL(raw string) string {
	u := parse(raw)
	if u == nil {
		return ""
	}
	return strings.TrimRight(u.String(), "/")
}

func parse(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, prefix := range []string{"registry+", "sparse+"} {
		raw = strings.TrimPrefix(raw, prefix)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u
}

func goPrivate(name string) bool {
	return matchPrefixPatterns(os.Getenv("GOPRIVATE"), name)
}

// matchPrefixPatterns is the GOPRIVATE algorithm from
// golang.org/x/mod/module.MatchPrefixPatterns: each comma-separated
// glob is matched against the corresponding prefix of the module path.
func matchPrefixPatterns(globs, target string) bool {
	for globs != "" {
		var glob string
		if before, after, ok := strings.Cut(globs, ","); ok {
			glob, globs = before, after
		} else {
			glob, globs = globs, ""
		}
		glob = strings.TrimSpace(strings.TrimSuffix(glob, "/"))
		if glob == "" {
			continue
		}

		n := strings.Count(glob, "/")
		prefix := target
		for i := 0; i < len(target); i++ {
			if target[i] == '/' {
				if n == 0 {
					prefix = target[:i]
					break
				}
				n--
			}
		}
		if n > 0 {
			continue
		}
		matched, _ := path.Match(glob, prefix)
		if matched {
			return true
		}
	}
	return false
}

func remote(dep core.Dependency) bool {
	switch dep.SourceKind {
	case core.SourceWorkspace, core.SourceFile, core.SourceGit:
		return false
	}
	return true
}
