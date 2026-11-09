// Package scorecard reads the OpenSSF Scorecard of a package's source repository through
// deps.dev, which maps a package version to its repository and publishes the score.
//
// The repository comes from the package's own metadata, which anyone can fill in, so a
// score says something about the repository the package claims, not about the package.
// It is used to warn about weak projects and never to vouch for one.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/internal/network"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

const (
	DefaultBase = "https://api.deps.dev"

	parallelism = 8
	maxBody     = 2 << 20
)

// Systems maps a securock ecosystem to the name deps.dev uses for it. Ecosystems that
// deps.dev does not cover are not looked up.
var Systems = map[string]string{
	"npm":      "npm",
	"pypi":     "pypi",
	"cargo":    "cargo",
	"go":       "go",
	"nuget":    "nuget",
	"rubygems": "rubygems",
}

// Target is one package version to look up.
type Target struct {
	Ecosystem string
	Name      string
	Version   string
}

// Result is the Scorecard of the repository a package version points at.
type Result struct {
	// Repository is the project, such as github.com/lodash/lodash.
	Repository string
	// Score is the overall score from 0 to 10.
	Score float64
	// Verified is true only when deps.dev confirmed the package belongs to the repository.
	// Otherwise the link is the package's own claim.
	Verified bool
	// Checks holds the score of each individual check, such as Dangerous-Workflow. A check
	// that does not apply to the repository, which Scorecard marks -1, is left out.
	Checks map[string]float64
}

type Client struct {
	Base      string
	HTTP      *http.Client
	UserAgent string
}

func New() *Client {
	return &Client{Base: DefaultBase, HTTP: &http.Client{Timeout: 30 * time.Second}, UserAgent: "securock"}
}

// Lookup returns the Scorecard of each target that has one, and the targets that could not
// be answered: a request that failed, as opposed to a package with no repository or no
// score, which is a normal answer and leaves the target out of the result.
func (c *Client) Lookup(ctx context.Context, targets []Target) (found map[Target]Result, failed []Target) {
	targets = slices.Clone(targets)
	slices.SortFunc(targets, func(a, b Target) int {
		return strings.Compare(a.Ecosystem+"\x00"+a.Name+"\x00"+a.Version, b.Ecosystem+"\x00"+b.Name+"\x00"+b.Version)
	})
	targets = slices.Compact(targets)

	found = map[Target]Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallelism)
	for _, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				failed = append(failed, t)
				mu.Unlock()
				return
			}
			defer func() { <-sem }()
			res, ok, err := c.one(ctx, t)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failed = append(failed, t)
			case ok:
				found[t] = res
			}
		}()
	}
	wg.Wait()
	return found, failed
}

func (c *Client) one(ctx context.Context, t Target) (Result, bool, error) {
	system, ok := Systems[t.Ecosystem]
	if !ok || t.Name == "" || t.Version == "" {
		return Result{}, false, nil
	}
	var version struct {
		RelatedProjects []struct {
			ProjectKey struct {
				ID string `json:"id"`
			} `json:"projectKey"`
			Provenance string `json:"relationProvenance"`
			Type       string `json:"relationType"`
		} `json:"relatedProjects"`
	}
	endpoint := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s", c.base(), system, url.PathEscape(t.Name), url.PathEscape(t.Version))
	if found, err := c.getJSON(ctx, endpoint, &version); err != nil || !found {
		return Result{}, false, err
	}
	var repo string
	var verified bool
	for _, p := range version.RelatedProjects {
		if p.Type == "SOURCE_REPO" && p.ProjectKey.ID != "" {
			repo, verified = p.ProjectKey.ID, p.Provenance == "VERIFIED_METADATA"
			break
		}
	}
	if repo == "" {
		return Result{}, false, nil
	}

	var project struct {
		Scorecard *struct {
			Overall *float64 `json:"overallScore"`
			Checks  []struct {
				Name  string   `json:"name"`
				Score *float64 `json:"score"`
			} `json:"checks"`
		} `json:"scorecard"`
	}
	endpoint = fmt.Sprintf("%s/v3/projects/%s", c.base(), url.PathEscape(repo))
	if found, err := c.getJSON(ctx, endpoint, &project); err != nil || !found {
		return Result{}, false, err
	}
	if project.Scorecard == nil || project.Scorecard.Overall == nil {
		return Result{}, false, nil
	}
	score := *project.Scorecard.Overall
	if score < 0 || score > 10 {
		return Result{}, false, nil
	}
	res := Result{Repository: repo, Score: score, Verified: verified, Checks: map[string]float64{}}
	for _, check := range project.Scorecard.Checks {
		if check.Score != nil && *check.Score >= 0 && *check.Score <= 10 {
			res.Checks[check.Name] = *check.Score
		}
	}
	return res, true, nil
}

func (c *Client) base() string {
	if c.Base == "" {
		return DefaultBase
	}
	return strings.TrimRight(c.Base, "/")
}

// getJSON reports found=false for a 404, which deps.dev uses for a package or project it
// does not know. Any other failure is an error.
func (c *Client) getJSON(ctx context.Context, endpoint string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
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
		return false, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("status %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(into); err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}
	return true, nil
}

// Collect looks up the Scorecard of each package in the lockfile document that the network
// settings allow to leave the machine, by artifact ID. The note says how many packages have
// no Scorecard, or why none could be looked up, so a missing score is not read as a good one.
func (c *Client) Collect(ctx context.Context, net policy.Network, doc lockfile.Document) (map[string]Result, string) {
	if net.Mode == policy.ModeOffline {
		return nil, "the lookup needs the network, and the network mode is offline"
	}
	var targets []Target
	byTarget := map[Target][]string{}
	for _, art := range doc.Artifacts {
		if _, ok := Systems[art.Subject.Ecosystem]; !ok || art.Version == "" {
			continue
		}
		// The same rule the scan used to decide what may leave the machine.
		if !network.Allow(net.Mode, net.Registries, core.Dependency{
			Ecosystem:  art.Subject.Ecosystem,
			Registry:   art.Source.Registry,
			Artifact:   art.Source.Artifact,
			SourceKind: art.Source.Kind,
			Name:       art.Subject.Name,
			Version:    art.Version,
		}) {
			continue
		}
		t := Target{Ecosystem: art.Subject.Ecosystem, Name: art.Subject.Name, Version: art.Version}
		targets = append(targets, t)
		byTarget[t] = append(byTarget[t], art.ArtifactID())
	}
	found, failed := c.Lookup(ctx, targets)
	out := map[string]Result{}
	for t, res := range found {
		for _, id := range byTarget[t] {
			out[id] = res
		}
	}
	if missing := len(doc.Artifacts) - len(out); missing > 0 {
		note := fmt.Sprintf("%d of %d packages have no Scorecard: private, unsupported ecosystem, no known repository or no score", missing, len(doc.Artifacts))
		if len(failed) > 0 {
			note += fmt.Sprintf("; %d lookups failed", len(failed))
		}
		return out, note
	}
	return out, ""
}
