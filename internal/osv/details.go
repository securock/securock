package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/pkg/lockfile"
)

const defaultVulnEndpoint = "https://api.osv.dev/v1/vulns/"

// Detail is what OSV knows about one advisory beyond its ID.
type Detail struct {
	// Severity is critical, high, medium, or low; empty when OSV gives no usable rating.
	Severity string
	Affected []Affected
}

// Affected is the part of an advisory that covers one package.
type Affected struct {
	Ecosystem string
	Name      string
	Ranges    []Range
}

type Range struct {
	Type   string
	Events []Event
}

// Event is one step of a range: a version where the problem starts, or where it is fixed.
type Event struct {
	Introduced string
	Fixed      string
}

// Detailer is implemented by clients that can look up advisories. It is optional: a client
// without it still reports which advisories apply, only without severity or fixed versions.
type Detailer interface {
	Details(ctx context.Context, ids []string) (map[string]Detail, error)
}

const detailParallelism = 8

// Details fetches the advisories by ID. An advisory that cannot be fetched is left out of
// the result, so a failure costs detail for that one advisory rather than the whole scan.
func (c *HTTPClient) Details(ctx context.Context, ids []string) (map[string]Detail, error) {
	ids = slices.Clone(ids)
	slices.Sort(ids)
	ids = slices.Compact(ids)

	out := make(map[string]Detail, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, detailParallelism)
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if d, ok := c.detail(ctx, id); ok {
				mu.Lock()
				out[id] = d
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *HTTPClient) vulnBase() string {
	if base, ok := strings.CutSuffix(c.Endpoint, "querybatch"); ok && c.Endpoint != "" {
		return base + "vulns/"
	}
	return defaultVulnEndpoint
}

func (c *HTTPClient) detail(ctx context.Context, id string) (Detail, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.vulnBase()+url.PathEscape(id), nil)
	if err != nil {
		return Detail{}, false
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	res, err := httpx.Do(ctx, client, req)
	if err != nil {
		return Detail{}, false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Detail{}, false
	}
	var raw rawVuln
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return Detail{}, false
	}
	return raw.detail(), true
}

type rawVuln struct {
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (r rawVuln) detail() Detail {
	d := Detail{Severity: r.severity()}
	for _, a := range r.Affected {
		aff := Affected{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name}
		for _, rg := range a.Ranges {
			rng := Range{Type: rg.Type}
			for _, e := range rg.Events {
				rng.Events = append(rng.Events, Event{Introduced: e.Introduced, Fixed: e.Fixed})
			}
			aff.Ranges = append(aff.Ranges, rng)
		}
		d.Affected = append(d.Affected, aff)
	}
	return d
}

// severity prefers a computed CVSS v3 score, since it is the same on every advisory, and
// falls back to the rating a database such as GitHub attaches. v2 and v4 vectors are not
// computed, so an advisory that has only those and no database rating has no severity.
func (r rawVuln) severity() string {
	best := 0.0
	for _, s := range r.Severity {
		if score, ok := cvss3Score(s.Score); ok && score > best {
			best = score
		}
	}
	if sev := severityOf(best); sev != "" {
		return sev
	}
	switch strings.ToLower(r.DatabaseSpecific.Severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

// Enrich adds severity and the version that fixes the advisory for this dependency.
func Enrich(dep ecosystem.Dependency, v lockfile.Vulnerability, d Detail) lockfile.Vulnerability {
	v.Severity = lockfile.VulnSeverity(d.Severity)
	name, eco := QueryName(dep), QueryEcosystem(dep)
	var fixed []string
	for _, a := range d.Affected {
		if a.Name == name && a.Ecosystem == eco {
			fixed = append(fixed, fixedFor(dep.Version, a.Ranges)...)
		}
	}
	slices.SortFunc(fixed, func(a, b string) int {
		if c, ok := compareVersions(a, b); ok {
			return c
		}
		return strings.Compare(a, b)
	})
	v.Fixed = slices.Compact(fixed)
	return v
}

// fixedFor returns the versions that end the range containing version. Ranges that do
// not contain it describe other branches and are ignored. When versions cannot be
// compared, every fix newer than nothing is offered rather than guessing, so the caller
// sees all candidates.
func fixedFor(version string, ranges []Range) []string {
	var out []string
	for _, r := range ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		introduced := ""
		for _, e := range r.Events {
			if e.Introduced != "" {
				introduced = e.Introduced
				continue
			}
			if e.Fixed == "" {
				continue
			}
			after, ok := compareVersions(version, introduced)
			if introduced == "0" {
				after, ok = 1, true
			}
			before, ok2 := compareVersions(version, e.Fixed)
			switch {
			case !ok || !ok2:
				out = append(out, e.Fixed)
			case after >= 0 && before < 0:
				out = append(out, e.Fixed)
			}
			introduced = ""
		}
	}
	return out
}
