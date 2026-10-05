package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/capability"
	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/pkg/lockfile"
)

const (
	npmAttestationsPath = "/-/npm/v1/attestations/"
	maxTarballBytes     = 32 << 20
)

type NPM struct {
	HTTP      *http.Client
	Registry  string
	UserAgent string
	Limit     int
	// SkipTarball disables package source capability scanning.
	SkipTarball bool
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
	rec := Record{
		Provenance: c.provenance(ctx, dep),
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
	}

	meta, ok := c.versionMeta(ctx, dep)
	if !ok {
		return rec
	}
	rec.Signature = meta.Signature
	rec.Ownership = meta.Ownership

	findings := capability.FromMetadata(meta.Capability)
	if !c.SkipTarball && meta.Tarball != "" {
		_ = c.scanTarball(ctx, c.registryFor(dep), meta.Tarball, &findings)
	}
	// Install scripts imply shell at install time even without a source scan.
	if findings.InstallScripts {
		findings.Shell = true
	}
	rec.Capabilities = capability.Evidence(findings)
	rec.Behavior = capability.Behavior(findings)
	return rec
}

type versionMeta struct {
	Signature  lockfile.EvidenceState
	Ownership  lockfile.OwnershipEvidence
	Capability capability.Metadata
	Tarball    string
}

func (c *NPM) versionMeta(ctx context.Context, dep ecosystem.Dependency) (versionMeta, bool) {
	endpoint := strings.TrimRight(c.registryFor(dep), "/") + "/" + encodeNPMName(dep.Name) + "/" + url.PathEscape(dep.Version)
	res, err := c.get(ctx, endpoint)
	if err != nil {
		return versionMeta{}, false
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotFound:
		return versionMeta{
			Signature: lockfile.EvidenceMissing,
			Ownership: lockfile.OwnershipEvidence{State: lockfile.CapChecked},
		}, true
	case http.StatusOK:
	default:
		return versionMeta{}, false
	}

	var parsed npmVersionDoc
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		return versionMeta{}, false
	}

	sig := lockfile.EvidenceMissing
	if len(parsed.Dist.Signatures) > 0 {
		sig = lockfile.EvidencePresent
	}

	owner := lockfile.OwnershipEvidence{State: lockfile.CapChecked}
	if parsed.NPMUser != nil {
		owner.Publisher = identityName(parsed.NPMUser.Name, parsed.NPMUser.Email)
	}
	if owner.Publisher == "" && parsed.Author.Person != nil {
		owner.Publisher = identityName(parsed.Author.Person.Name, parsed.Author.Person.Email)
	}
	for _, m := range parsed.Maintainers {
		if id := identityName(m.Name, m.Email); id != "" {
			owner.Maintainers = append(owner.Maintainers, id)
		}
	}

	capMeta := capability.Metadata{
		HasInstallScript: parsed.HasInstallScript,
		Scripts:          parsed.Scripts,
		Gypfile:          parsed.Gypfile,
		Binary:           parsed.Binary != nil,
		Dependencies:     parsed.Dependencies,
		OptionalDeps:     parsed.OptionalDependencies,
		BundledDeps:      parsed.BundleDependencies,
		Files:            parsed.Files,
	}

	return versionMeta{
		Signature:  sig,
		Ownership:  owner,
		Capability: capMeta,
		Tarball:    parsed.Dist.Tarball,
	}, true
}

func (c *NPM) scanTarball(ctx context.Context, registry, tarball string, findings *capability.Findings) error {
	u, err := url.Parse(tarball)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("unsupported tarball scheme %q", u.Scheme)
	}
	reg, err := url.Parse(registry)
	if err != nil {
		return err
	}
	if !sameRegistryHost(reg.Host, u.Host) {
		return fmt.Errorf("tarball host %q outside registry %q", u.Host, reg.Host)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarball, nil)
	if err != nil {
		return err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := *httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL == nil || !sameRegistryHost(reg.Host, req.URL.Host) {
			return fmt.Errorf("refusing cross-registry tarball redirect")
		}
		return nil
	}
	// Tarballs exceed the httpx body cache limit; fetch directly.
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return io.ErrUnexpectedEOF
	}
	return capability.ScanSource(io.LimitReader(res.Body, maxTarballBytes), findings)
}

func sameRegistryHost(registryHost, targetHost string) bool {
	registryHost = strings.ToLower(registryHost)
	targetHost = strings.ToLower(targetHost)
	if registryHost == targetHost {
		return true
	}
	// Allow CDN hosts under the same organizational domain suffix when present.
	if strings.HasSuffix(targetHost, "."+registryHost) {
		return true
	}
	return false
}

func (c *NPM) provenance(ctx context.Context, dep ecosystem.Dependency) lockfile.EvidenceState {
	endpoint := strings.TrimRight(c.registryFor(dep), "/") + npmAttestationsPath + url.PathEscape(dep.Name) + "@" + url.PathEscape(dep.Version)
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
			return lockfile.EvidencePresent
		}
	}
	return lockfile.EvidenceMissing
}

func (c *NPM) registryFor(dep ecosystem.Dependency) string {
	if dep.Registry != "" {
		return dep.Registry
	}
	if c.Registry != "" {
		return c.Registry
	}
	return "https://registry.npmjs.org"
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
	return httpx.Do(ctx, httpClient, req)
}

type npmVersionDoc struct {
	HasInstallScript     bool              `json:"hasInstallScript"`
	Scripts              map[string]string `json:"scripts"`
	Gypfile              bool              `json:"gypfile"`
	Binary               json.RawMessage   `json:"binary"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundleDependencies   softStringList    `json:"bundleDependencies"`
	Files                []string          `json:"files"`
	Maintainers          []npmPerson       `json:"maintainers"`
	Author               softPerson        `json:"author"`
	NPMUser              *npmPerson        `json:"_npmUser"`
	Dist                 struct {
		Signatures []json.RawMessage `json:"signatures"`
		Tarball    string            `json:"tarball"`
	} `json:"dist"`
}

type npmPerson struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type softPerson struct {
	Person *npmPerson
}

func (p *softPerson) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		name, email := splitPerson(s)
		p.Person = &npmPerson{Name: name, Email: email}
		return nil
	}
	var person npmPerson
	if err := json.Unmarshal(raw, &person); err != nil {
		return err
	}
	p.Person = &person
	return nil
}

type softStringList []string

func (s *softStringList) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '[' {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		*s = list
		return nil
	}
	// npm may set bundleDependencies to true/false.
	return nil
}

func splitPerson(s string) (name, email string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.Index(s, "<"); i >= 0 {
		j := strings.Index(s[i:], ">")
		if j > 1 {
			email = strings.TrimSpace(s[i+1 : i+j])
			name = strings.TrimSpace(s[:i])
			return name, email
		}
	}
	if strings.Contains(s, "@") && !strings.Contains(s, " ") {
		return "", s
	}
	return s, ""
}


func identityName(name, email string) string {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	switch {
	case name != "" && email != "":
		return name + " <" + email + ">"
	case name != "":
		return name
	case email != "":
		return email
	default:
		return ""
	}
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
