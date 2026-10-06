package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/pkg/lockfile"
)

const pypiIntegrityAccept = "application/vnd.pypi.integrity.v1+json"

// PyPI collects PEP 740 provenance objects from the PyPI Integrity API.
type PyPI struct {
	HTTP      *http.Client
	Index     string
	UserAgent string
	Limit     int
}

func NewPyPI() *PyPI {
	return &PyPI{
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
		Index:     "https://pypi.org",
		UserAgent: "securock",
		Limit:     8,
	}
}

func (c *PyPI) Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]Record, error) {
	out := make(map[string]Record)
	var pypiDeps []ecosystem.Dependency
	for _, dep := range deps {
		if dep.Ecosystem != "pypi" || dep.Filename == "" {
			continue
		}
		if !pypiPublicRegistry(dep) {
			continue
		}
		pypiDeps = append(pypiDeps, dep)
	}
	if len(pypiDeps) == 0 {
		return out, nil
	}

	limit := c.Limit
	if limit < 1 {
		limit = 8
	}
	sem := make(chan struct{}, limit)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, dep := range pypiDeps {
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

func (c *PyPI) lookup(ctx context.Context, dep ecosystem.Dependency) Record {
	rec := Record{
		Provenance: lockfile.EvidenceUnknown,
		Signature:  lockfile.EvidenceUnknown,
		Capabilities: lockfile.CapabilityEvidence{
			State: lockfile.CapUnknown,
		},
		Behavior: lockfile.BehaviorEvidence{
			State: lockfile.CapUnknown,
		},
		Ownership: lockfile.OwnershipEvidence{
			State: lockfile.CapUnknown,
		},
		Chain: lockfile.ChainEvidence{
			State: lockfile.EvidenceUnknown,
		},
	}

	raw, status, err := c.fetchProvenance(ctx, dep)
	if err != nil {
		return rec
	}
	switch status {
	case http.StatusNotFound:
		rec.Provenance = lockfile.EvidenceMissing
		rec.Signature = lockfile.EvidenceMissing
		rec.Chain.State = lockfile.EvidenceMissing
		return rec
	case http.StatusOK:
	default:
		return rec
	}

	prov, sig, chain := parsePyPIProvenance(raw, dep.Digest, dep.Filename)
	rec.Provenance = prov
	rec.Signature = sig
	rec.Chain = chain
	return rec
}

func (c *PyPI) fetchProvenance(ctx context.Context, dep ecosystem.Dependency) ([]byte, int, error) {
	index := strings.TrimRight(c.Index, "/")
	if index == "" {
		index = "https://pypi.org"
	}
	project := pypiProjectName(dep.Name)
	u := fmt.Sprintf("%s/integrity/%s/%s/%s/provenance",
		index,
		url.PathEscape(project),
		url.PathEscape(dep.Version),
		url.PathEscape(dep.Filename),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", pypiIntegrityAccept)
	ua := c.UserAgent
	if ua == "" {
		ua = "securock"
	}
	req.Header.Set("User-Agent", ua)

	res, err := httpx.Do(ctx, c.HTTP, req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func parsePyPIProvenance(raw []byte, digest, filename string) (lockfile.EvidenceState, lockfile.EvidenceState, lockfile.ChainEvidence) {
	var parsed struct {
		AttestationBundles []struct {
			Attestations []json.RawMessage `json:"attestations"`
			Publisher    struct {
				Kind             string `json:"kind"`
				Repository       string `json:"repository"`
				Workflow         string `json:"workflow"`
				WorkflowFilepath string `json:"workflow_filepath"`
			} `json:"publisher"`
		} `json:"attestation_bundles"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return lockfile.EvidenceUnknown, lockfile.EvidenceUnknown, lockfile.ChainEvidence{State: lockfile.EvidenceUnknown}
	}
	if len(parsed.AttestationBundles) == 0 {
		return lockfile.EvidenceMissing, lockfile.EvidenceMissing, lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	}

	chain := lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	foundAttestation := false
	digest = core.NormalizeDigest(digest)

	for _, bundle := range parsed.AttestationBundles {
		kind := strings.TrimSpace(bundle.Publisher.Kind)
		if repo := strings.TrimSpace(bundle.Publisher.Repository); repo != "" {
			chain.Source = normalizePublisherSource(kind, repo)
		}
		workflow := strings.TrimSpace(bundle.Publisher.Workflow)
		if workflow == "" {
			workflow = strings.TrimSpace(bundle.Publisher.WorkflowFilepath)
		}
		if workflow != "" {
			setWorkflow(&chain, workflow)
			if chain.Workflow == "" {
				chain.Workflow = workflowBase(workflow)
			}
		}
		for _, att := range bundle.Attestations {
			foundAttestation = true
			predType, _ := pypiAttestationMeta(att, digest, filename)
			if predType != "" && chain.PredicateType == "" {
				chain.PredicateType = predType
			}
			if res, ok := verifyPyPIAttestation(att, digest, filename); ok {
				return lockfile.EvidenceVerified, lockfile.EvidenceVerified, chainFromPyPIVerified(res, chain)
			}
		}
	}

	if !foundAttestation {
		return lockfile.EvidenceMissing, lockfile.EvidenceMissing, lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	}

	// Attestations are present but local Sigstore re-verification did not
	// succeed (missing digest, incomplete envelope, or crypto failure).
	chain.State = lockfile.EvidencePresent
	return lockfile.EvidencePresent, lockfile.EvidencePresent, chain
}

func pypiAttestationMeta(att json.RawMessage, digest, filename string) (predicateType string, subjectMatches bool) {
	var obj struct {
		Envelope struct {
			Statement string `json:"statement"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(att, &obj); err != nil {
		return "", false
	}
	if obj.Envelope.Statement == "" {
		return "", false
	}
	raw, err := decodeBase64(obj.Envelope.Statement)
	if err != nil {
		return "", false
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return "", false
	}
	predicateType = stmt.PredicateType
	if digest == "" {
		return predicateType, false
	}
	wantAlg, wantHex, ok := strings.Cut(digest, ":")
	if !ok {
		return predicateType, false
	}
	wantAlg = strings.ToLower(wantAlg)
	filename = strings.TrimSpace(filename)
	for _, sub := range stmt.Subject {
		if filename != "" && sub.Name != filename {
			continue
		}
		for alg, hexDigest := range sub.Digest {
			if strings.EqualFold(alg, wantAlg) && strings.EqualFold(hexDigest, wantHex) {
				return predicateType, true
			}
		}
	}
	return predicateType, false
}

func pypiProjectName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "_", "-")
	return strings.ToLower(name)
}

func workflowBase(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func pypiPublicRegistry(dep ecosystem.Dependency) bool {
	if dep.SourceKind != "" && dep.SourceKind != core.SourceRegistry {
		return false
	}
	reg := strings.TrimRight(strings.ToLower(strings.TrimSpace(dep.Registry)), "/")
	switch reg {
	case "https://pypi.org", "http://pypi.org", "https://pypi.org/simple", "http://pypi.org/simple":
		return true
	default:
		return false
	}
}

func normalizePublisherSource(kind, repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	if strings.Contains(repo, "://") || strings.HasPrefix(repo, "github.com/") || strings.HasPrefix(repo, "gitlab.com/") {
		return normalizeSource(repo)
	}
	host := "github.com"
	if strings.EqualFold(strings.TrimSpace(kind), "GitLab") {
		host = "gitlab.com"
	}
	return normalizeSource(host + "/" + strings.TrimPrefix(repo, "/"))
}
