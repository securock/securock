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
	}
}

func Allow(mode policy.Mode, allowlist map[string][]string, dep core.Dependency) bool {
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
	got := strings.TrimRight(dep.Registry, "/")
	for _, prefix := range allowed {
		if registryMatch(got, prefix) {
			return true
		}
	}
	return false
}

func registryMatch(got, prefix string) bool {
	got = strings.TrimRight(got, "/")
	prefix = strings.TrimRight(prefix, "/")
	return got == prefix || strings.HasPrefix(got, prefix+"/") || strings.HasPrefix(prefix, got+"/")
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
	patterns := os.Getenv("GOPRIVATE")
	if patterns == "" {
		return false
	}
	for _, pattern := range strings.Split(patterns, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if matched, _ := path.Match(pattern, name); matched {
			return true
		}
		if strings.HasPrefix(name, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}
