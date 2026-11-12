package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/pkg/lockfile"
)

const (
	defaultEndpoint = "https://api.osv.dev/v1/querybatch"
	batchSize       = 100
	// batchParallelism is kept small to stay well inside the OSV rate limits.
	batchParallelism = 3
)

type Client interface {
	Query(ctx context.Context, deps []ecosystem.Dependency) (map[string][]lockfile.Vulnerability, error)
}

type HTTPClient struct {
	Endpoint  string
	HTTP      *http.Client
	UserAgent string
}

func New() *HTTPClient {
	return &HTTPClient{
		Endpoint: defaultEndpoint,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
		},
		UserAgent: "securock",
	}
}

func (c *HTTPClient) Query(ctx context.Context, deps []ecosystem.Dependency) (map[string][]lockfile.Vulnerability, error) {
	out := make(map[string][]lockfile.Vulnerability, len(deps))
	if len(deps) == 0 {
		return out, nil
	}

	// Batches are independent, so a few go out together. Each fills its own map and the
	// results are merged in order, which keeps the error that is reported independent of
	// timing.
	var batches [][]ecosystem.Dependency
	for i := 0; i < len(deps); i += batchSize {
		batches = append(batches, deps[i:min(i+batchSize, len(deps))])
	}
	results := make([]map[string][]lockfile.Vulnerability, len(batches))
	errs := make([]error, len(batches))
	sem := make(chan struct{}, batchParallelism)
	var wg sync.WaitGroup
	for i, batch := range batches {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = make(map[string][]lockfile.Vulnerability, len(batch))
			errs[i] = c.queryBatch(ctx, batch, results[i])
		}()
	}
	wg.Wait()
	for i := range batches {
		if errs[i] != nil {
			return nil, errs[i]
		}
		maps.Copy(out, results[i])
	}
	return out, nil
}

type queryRequest struct {
	Queries []queryItem `json:"queries"`
}

type queryItem struct {
	Package   queryPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryResponse struct {
	Results []*queryResult `json:"results"`
}

type queryResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

func (c *HTTPClient) queryBatch(ctx context.Context, deps []ecosystem.Dependency, out map[string][]lockfile.Vulnerability) error {
	reqBody := queryRequest{Queries: make([]queryItem, 0, len(deps))}
	pending := make([]int, len(deps))
	seenTokens := make([]map[string]bool, len(deps))
	hits := make([]map[string]bool, len(deps))
	for i, dep := range deps {
		pending[i] = i
		seenTokens[i] = map[string]bool{}
		hits[i] = map[string]bool{}
		reqBody.Queries = append(reqBody.Queries, queryItem{
			Package: queryPackage{
				Name:      QueryName(dep),
				Ecosystem: QueryEcosystem(dep),
			},
			Version: dep.Version,
		})
	}

	// Each result has its own cursor. Only unfinished queries are sent again;
	// pending keeps their original identities as the batch shrinks between pages.
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("osv query: %w", err)
		}
		parsed, err := c.queryPage(ctx, reqBody)
		if err != nil {
			return err
		}
		if len(parsed.Results) != len(pending) {
			return fmt.Errorf("osv query: result count %d does not match query count %d", len(parsed.Results), len(pending))
		}
		next := queryRequest{}
		var nextPending []int
		for i, result := range parsed.Results {
			if result == nil {
				return fmt.Errorf("osv query: missing result")
			}
			index := pending[i]
			for _, v := range result.Vulns {
				if strings.TrimSpace(v.ID) == "" {
					return fmt.Errorf("osv query: missing vulnerability ID")
				}
				hits[index][v.ID] = true
			}
			if token := result.NextPageToken; token != "" {
				if seenTokens[index][token] {
					return fmt.Errorf("osv query: repeated page token")
				}
				seenTokens[index][token] = true
				q := reqBody.Queries[i]
				q.PageToken = token
				next.Queries = append(next.Queries, q)
				nextPending = append(nextPending, index)
			}
		}
		reqBody, pending = next, nextPending
	}
	for i, dep := range deps {
		ids := slices.Sorted(maps.Keys(hits[i]))
		vulns := make([]lockfile.Vulnerability, 0, len(ids))
		for _, id := range ids {
			vulns = append(vulns, lockfile.Vulnerability{ID: id})
		}
		out[identity(dep)] = vulns
	}
	return nil
}

func (c *HTTPClient) queryPage(ctx context.Context, reqBody queryRequest) (queryResponse, error) {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return queryResponse{}, err
	}

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return queryResponse{}, err
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	res, err := httpx.Do(ctx, httpClient, req)
	if err != nil {
		return queryResponse{}, fmt.Errorf("osv query: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return queryResponse{}, fmt.Errorf("osv query: unexpected status %s", res.Status)
	}

	var parsed queryResponse
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return queryResponse{}, fmt.Errorf("osv query: %w", err)
	}
	return parsed, nil
}

func identity(dep ecosystem.Dependency) string {
	return ecosystem.Identity(dep)
}

func Queryable(dep ecosystem.Dependency) bool {
	return QueryEcosystem(dep) != ""
}

func QueryName(dep ecosystem.Dependency) string {
	if dep.Ecosystem == "swift" && dep.Registry != "" {
		return swiftURLName(dep.Registry)
	}
	if dep.Ecosystem == "go" && dep.Artifact != "" {
		return dep.Artifact
	}
	return dep.Name
}

// swiftURLName maps a SwiftPM repository location to the identifier form
// OSV uses for the SwiftURL ecosystem: the transport is omitted and a
// trailing ".git" is dropped, but the host and path keep their case.
func swiftURLName(location string) string {
	u, err := url.Parse(location)
	if err != nil || u.Hostname() == "" {
		return location
	}
	path := strings.TrimSuffix(u.Path, ".git")
	return u.Hostname() + path
}

func QueryEcosystem(dep ecosystem.Dependency) string {
	if dep.Ecosystem == "cargo" && !cratesIO(dep.Registry) {
		return ""
	}
	// A cran or hackage artifact without a proven public registry may be Bioconductor, a
	// private mirror or another repository.
	if (dep.Ecosystem == "cran" || dep.Ecosystem == "hackage") && dep.Registry == "" {
		return ""
	}
	// OSV has no CocoaPods or ConanCenter ecosystem, so these stay unknown instead of looking clean.
	if dep.Ecosystem == "jsr" || dep.Ecosystem == "url" || dep.Ecosystem == "cocoapods" || dep.Ecosystem == "conan" {
		return ""
	}
	return Ecosystem(dep.Ecosystem)
}

func cratesIO(registry string) bool {
	switch registry {
	case "https://index.crates.io", "https://github.com/rust-lang/crates.io-index":
		return true
	}
	return strings.Contains(registry, "crates.io")
}

func Ecosystem(name string) string {
	switch name {
	case "npm", "pnpm", "yarn", "bun", "deno":
		return "npm"
	case "cargo":
		return "crates.io"
	case "go":
		return "Go"
	case "pypi":
		return "PyPI"
	case "packagist":
		return "Packagist"
	case "rubygems":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	case "swift":
		return "SwiftURL"
	case "pub":
		return "Pub"
	case "hex":
		return "Hex"
	case "cran":
		return "CRAN"
	case "julia":
		return "Julia"
	case "hackage":
		return "Hackage"
	case "maven":
		return "Maven"
	default:
		return name
	}
}
