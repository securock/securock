package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/pkg/lockfile"
)

const (
	defaultEndpoint = "https://api.osv.dev/v1/querybatch"
	batchSize       = 100
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

	for i := 0; i < len(deps); i += batchSize {
		end := min(i+batchSize, len(deps))
		if err := c.queryBatch(ctx, deps[i:end], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type queryRequest struct {
	Queries []queryItem `json:"queries"`
}

type queryItem struct {
	Package queryPackage `json:"package"`
	Version string       `json:"version"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

func (c *HTTPClient) queryBatch(ctx context.Context, deps []ecosystem.Dependency, out map[string][]lockfile.Vulnerability) error {
	reqBody := queryRequest{Queries: make([]queryItem, 0, len(deps))}
	for _, dep := range deps {
		reqBody.Queries = append(reqBody.Queries, queryItem{
			Package: queryPackage{
				Name:      dep.Name,
				Ecosystem: Ecosystem(dep.Ecosystem),
			},
			Version: dep.Version,
		})
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("osv query: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("osv query: unexpected status %s", res.Status)
	}

	var parsed queryResponse
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("osv query: %w", err)
	}
	if len(parsed.Results) != len(deps) {
		return fmt.Errorf("osv query: result count %d does not match query count %d", len(parsed.Results), len(deps))
	}

	for i, dep := range deps {
		key := identity(dep)
		vulns := make([]lockfile.Vulnerability, 0, len(parsed.Results[i].Vulns))
		for _, v := range parsed.Results[i].Vulns {
			if v.ID == "" {
				continue
			}
			vulns = append(vulns, lockfile.Vulnerability{
				ID:       v.ID,
				Modified: v.Modified,
			})
		}
		out[key] = vulns
	}
	return nil
}

func identity(dep ecosystem.Dependency) string {
	return dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
}

func Ecosystem(name string) string {
	switch name {
	case "npm", "pnpm":
		return "npm"
	case "cargo":
		return "crates.io"
	case "go":
		return "Go"
	case "pypi":
		return "PyPI"
	default:
		return name
	}
}
