package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/internal/license"
	"github.com/securock/securock/pkg/lockfile"
	"golang.org/x/mod/module"
)

// RegistryHealth adds release metadata without inventing provenance or signatures.
// Only public sources already admitted by scanner network policy are considered.
type RegistryHealth struct {
	HTTP                   *http.Client
	GoProxy, Crates, NuGet string
}

func NewRegistryHealth() *RegistryHealth {
	return &RegistryHealth{HTTP: &http.Client{Timeout: 20 * time.Second}, GoProxy: "https://proxy.golang.org", Crates: "https://crates.io", NuGet: "https://api.nuget.org"}
}
func (c *RegistryHealth) Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]Record, error) {
	out := map[string]Record{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan ecosystem.Dependency)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dep := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if dep.SourceKind != core.SourceRegistry || dep.Name == "" || dep.Version == "" {
					continue
				}
				var health *lockfile.HealthEvidence
				switch dep.Ecosystem {
				case "go":
					if dep.Registry == "https://proxy.golang.org" {
						health = c.goHealth(ctx, dep)
					}
				case "cargo":
					if dep.Registry == "https://index.crates.io" || dep.Registry == "https://github.com/rust-lang/crates.io-index" {
						health = c.crateHealth(ctx, dep)
					}
				case "nuget":
					if dep.Registry == "https://api.nuget.org" {
						health = c.nugetHealth(ctx, dep)
					}
				}
				if health != nil {
					mu.Lock()
					out[Key(dep)] = Record{Provenance: lockfile.EvidenceUnknown, Signature: lockfile.EvidenceUnknown, Health: health}
					mu.Unlock()
				}
			}
		}()
	}
send:
	for _, dep := range deps {
		select {
		case jobs <- dep:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	return out, ctx.Err()
}
func (c *RegistryHealth) get(ctx context.Context, endpoint string, dst any) bool {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return false
	}
	req.Header.Set("User-Agent", "securock")
	res, e := httpx.Do(ctx, c.HTTP, req)
	if e != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(res.Body).Decode(dst) == nil
}
func (c *RegistryHealth) goHealth(ctx context.Context, dep ecosystem.Dependency) *lockfile.HealthEvidence {
	name, e := module.EscapePath(dep.Name)
	if e != nil {
		return nil
	}
	version, e := module.EscapeVersion(dep.Version)
	if e != nil {
		return nil
	}
	var info struct {
		Version string
		Time    time.Time
	}
	if !c.get(ctx, strings.TrimRight(c.GoProxy, "/")+"/"+name+"/@v/"+version+".info", &info) || info.Version != dep.Version || info.Time.IsZero() {
		return nil
	}
	return &lockfile.HealthEvidence{Released: info.Time.UTC().Format("2006-01-02")}
}
func (c *RegistryHealth) crateHealth(ctx context.Context, dep ecosystem.Dependency) *lockfile.HealthEvidence {
	var data struct {
		Version struct {
			Num, License string
			CreatedAt    string `json:"created_at"`
			Yanked       bool
		}
	}
	endpoint := fmt.Sprintf("%s/api/v1/crates/%s/%s", strings.TrimRight(c.Crates, "/"), url.PathEscape(dep.Name), url.PathEscape(dep.Version))
	if !c.get(ctx, endpoint, &data) || data.Version.Num != dep.Version {
		return nil
	}
	h := &lockfile.HealthEvidence{License: license.NormalizeExpression(clip(data.Version.License)), Released: day(data.Version.CreatedAt)}
	if data.Version.Yanked {
		h.Deprecated = "yanked"
	}
	return h
}
func (c *RegistryHealth) nugetHealth(ctx context.Context, dep ecosystem.Dependency) *lockfile.HealthEvidence {
	var leaf struct {
		CatalogEntry json.RawMessage `json:"catalogEntry"`
	}
	endpoint := fmt.Sprintf("%s/v3/registration5-gz-semver2/%s/%s.json", strings.TrimRight(c.NuGet, "/"), url.PathEscape(strings.ToLower(dep.Name)), url.PathEscape(strings.ToLower(dep.Version)))
	if !c.get(ctx, endpoint, &leaf) {
		return nil
	}
	raw := leaf.CatalogEntry
	var catalog string
	if json.Unmarshal(raw, &catalog) == nil {
		// Registration metadata is not permission to send package names elsewhere.
		u, e := url.Parse(catalog)
		base, _ := url.Parse(c.NuGet)
		if e != nil || base == nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil
		}
		var entry json.RawMessage
		if !c.get(ctx, catalog, &entry) {
			return nil
		}
		raw = entry
	}
	var entry struct {
		ID          string `json:"id"`
		Version     string `json:"version"`
		License     string `json:"licenseExpression"`
		Published   string `json:"published"`
		Deprecation *struct {
			Reasons []string `json:"reasons"`
		} `json:"deprecation"`
	}
	if json.Unmarshal(raw, &entry) != nil || !strings.EqualFold(entry.ID, dep.Name) || !strings.EqualFold(entry.Version, dep.Version) {
		return nil
	}
	h := &lockfile.HealthEvidence{License: license.NormalizeExpression(clip(entry.License)), Released: day(entry.Published)}
	if entry.Deprecation != nil {
		h.Deprecated = "deprecated"
	}
	return h
}
