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

func (c *NPM) Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]lockfile.EvidenceState, error) {
	out := make(map[string]lockfile.EvidenceState)
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

			state, err := c.lookup(ctx, dep)
			if err != nil {
				state = lockfile.EvidenceUnknown
			}
			mu.Lock()
			out[Key(dep)] = state
			mu.Unlock()
		}(dep)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *NPM) lookup(ctx context.Context, dep ecosystem.Dependency) (lockfile.EvidenceState, error) {
	endpoint := strings.TrimRight(c.Registry, "/") + npmAttestationsPath + url.PathEscape(dep.Name) + "@" + url.PathEscape(dep.Version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return lockfile.EvidenceUnknown, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return lockfile.EvidenceUnknown, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotFound:
		return lockfile.EvidenceMissing, nil
	case http.StatusOK:
	default:
		return lockfile.EvidenceUnknown, fmt.Errorf("npm attestations: %s", res.Status)
	}

	var parsed struct {
		Attestations []struct {
			PredicateType string `json:"predicateType"`
		} `json:"attestations"`
	}
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return lockfile.EvidenceUnknown, err
	}
	for _, att := range parsed.Attestations {
		if isProvenance(att.PredicateType) {
			return lockfile.EvidenceVerified, nil
		}
	}
	return lockfile.EvidenceMissing, nil
}

func isProvenance(predicateType string) bool {
	return strings.Contains(strings.ToLower(predicateType), "provenance")
}
