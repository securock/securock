package dynamic

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/securock/securock/internal/dast"
)

//go:embed browser.cjs
var BrowserScript string

type server struct {
	URL string `json:"url"`
}

// Endpoints expands static GET operations, preserving server base paths while
// keeping every request on the origin explicitly authorized by the caller.
func Endpoints(r io.Reader, target string) ([]string, int, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 2<<20+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, 0, fmt.Errorf("cannot read OpenAPI input within 2 MiB limit")
	}
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Servers []server                              `json:"servers"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(raw, &spec) != nil || !strings.HasPrefix(spec.OpenAPI, "3.") || spec.Paths == nil {
		return nil, 0, fmt.Errorf("expected OpenAPI 3 JSON paths")
	}
	origin, err := dast.ValidateURL(target)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	skipped := 0
	for path, methods := range spec.Paths {
		operation, ok := methods["get"]
		if !ok {
			continue
		}
		ref, err := url.Parse(path)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid OpenAPI path")
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || ref.Host != "" || ref.RawQuery != "" || ref.Fragment != "" || strings.ContainsAny(ref.Path, "{}\\?#") || unsafePath(ref.Path) {
			skipped++
			continue
		}
		servers := spec.Servers
		if v, ok := methods["servers"]; ok {
			if json.Unmarshal(v, &servers) != nil {
				return nil, 0, fmt.Errorf("invalid path servers")
			}
		}
		var op struct {
			Servers *[]server `json:"servers"`
		}
		if json.Unmarshal(operation, &op) != nil {
			return nil, 0, fmt.Errorf("invalid GET operation")
		}
		if op.Servers != nil {
			servers = *op.Servers
		}
		bases := []*url.URL{origin}
		if len(servers) > 0 {
			bases = nil
			for _, s := range servers {
				u, err := url.Parse(s.URL)
				if err != nil || strings.ContainsAny(s.URL, "{}\\") {
					continue
				}
				// Resolve relative server declarations from the supplied base URL. Absolute
				// declarations cannot grant authority to contact another origin.
				u = origin.ResolveReference(u)
				if _, err := dast.ValidateURL(u.String()); err != nil || !sameOrigin(origin, u) || unsafePath(u.Path) {
					continue
				}
				bases = append(bases, u)
			}
		}
		if len(bases) == 0 {
			skipped++
			continue
		}
		for _, base := range bases {
			joined, err := url.Parse(strings.TrimRight(base.EscapedPath(), "/") + ref.EscapedPath())
			if err != nil {
				return nil, 0, fmt.Errorf("invalid expanded OpenAPI path")
			}
			next := *base
			next.Path, next.RawPath = joined.Path, joined.RawPath
			out = append(out, next.String())
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > 100 {
		return nil, 0, fmt.Errorf("OpenAPI GET endpoint limit is 100")
	}
	return out, skipped, nil
}

func unsafePath(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && a.Scheme == b.Scheme && port(a) == port(b)
}
