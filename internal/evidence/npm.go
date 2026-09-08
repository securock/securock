package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/pkg/lockfile"
)

const npmAttestationsPath = "/-/npm/v1/attestations/"

type NPM struct {
	HTTP      *http.Client
	Registry  string
	UserAgent string
	Limit     int
}

func NewNPM() *NPM {
	return &NPM{
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
		Registry:  "https://registry.npmjs.org",
		UserAgent: "securock",
		Limit:     8,
	}
}

func (c *NPM) Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]Record, error) {
	out := make(map[string]Record)
	var npmDeps []ecosystem.Dependency
	for _, dep := range deps {
		if dep.Ecosystem != "npm" {
			continue
		}
		npmDeps = append(npmDeps, dep)
	}
	if len(npmDeps) == 0 {
		return out, nil
	}

	limit := c.Limit
	if limit < 1 {
		limit = 8
	}
	sem := make(chan struct{}, limit)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, dep := range npmDeps {
		wg.Add(1)
		go func(dep ecosystem.Dependency) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			rec := c.lookup(ctx, dep)
			mu.Lock()
			out[Key(dep)] = rec
			mu.Unlock()
		}(dep)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *NPM) lookup(ctx context.Context, dep ecosystem.Dependency) Record {
	return Record{
		Provenance: c.provenance(ctx, dep),
		Signature:  c.signature(ctx, dep),
	}
}

func (c *NPM) provenance(ctx context.Context, dep ecosystem.Dependency) lockfile.EvidenceState {
	endpoint := strings.TrimRight(c.Registry, "/") + npmAttestationsPath + url.PathEscape(dep.Name) + "@" + url.PathEscape(dep.Version)
	res, err := c.get(ctx, endpoint)
	if err != nil {
		return lockfile.EvidenceUnknown
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotFound:
		return lockfile.EvidenceMissing
	case http.StatusOK:
	default:
		return lockfile.EvidenceUnknown
	}

	var parsed struct {
		Attestations []struct {
			PredicateType string `json:"predicateType"`
		} `json:"attestations"`
	}
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return lockfile.EvidenceUnknown
	}
	for _, att := range parsed.Attestations {
		if isProvenance(att.PredicateType) {
			return lockfile.EvidenceVerified
		}
	}
	return lockfile.EvidenceMissing
}

func (c *NPM) signature(ctx context.Context, dep ecosystem.Dependency) lockfile.EvidenceState {
	endpoint := strings.TrimRight(c.Registry, "/") + "/" + encodeNPMName(dep.Name) + "/" + url.PathEscape(dep.Version)
	res, err := c.get(ctx, endpoint)
	if err != nil {
		return lockfile.EvidenceUnknown
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotFound:
		return lockfile.EvidenceMissing
	case http.StatusOK:
	default:
		return lockfile.EvidenceUnknown
	}

	var parsed struct {
		Dist struct {
			Signatures []json.RawMessage `json:"signatures"`
		} `json:"dist"`
	}
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return lockfile.EvidenceUnknown
	}
	if len(parsed.Dist.Signatures) == 0 {
		return lockfile.EvidenceMissing
	}
	return lockfile.EvidenceVerified
}

func (c *NPM) get(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return httpClient.Do(req)
}

func encodeNPMName(name string) string {
	if i := strings.Index(name, "/"); i > 0 {
		return name[:i] + "%2F" + name[i+1:]
	}
	return name
}

func isProvenance(predicateType string) bool {
	return strings.Contains(strings.ToLower(predicateType), "provenance")
}
