package dynamic

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
)

//go:embed browser.cjs
var BrowserScript string

func Endpoints(r io.Reader, target string) ([]string, int, error) {
	raw, e := io.ReadAll(io.LimitReader(r, 2<<20+1))
	if e != nil || len(raw) > 2<<20 {
		return nil, 0, fmt.Errorf("OpenAPI input exceeds limit")
	}
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(raw, &spec) != nil || !strings.HasPrefix(spec.OpenAPI, "3.") || spec.Paths == nil {
		return nil, 0, fmt.Errorf("expected OpenAPI 3 JSON paths")
	}
	base, e := url.Parse(target)
	if e != nil {
		return nil, 0, e
	}
	var out []string
	skipped := 0
	for path, methods := range spec.Paths {
		if _, ok := methods["get"]; !ok {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "{}?#") {
			skipped++
			continue
		}
		ref, e := url.Parse(path)
		if e != nil {
			return nil, 0, fmt.Errorf("invalid OpenAPI path")
		}
		next := base.ResolveReference(ref)
		if next.Host != base.Host || next.Scheme != base.Scheme {
			skipped++
			continue
		}
		out = append(out, next.String())
	}
	slices.Sort(out)
	if len(out) > 100 {
		return nil, 0, fmt.Errorf("OpenAPI GET endpoint limit is 100")
	}
	return out, skipped, nil
}
