package scanner

import (
	"cmp"
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/osv"
	"github.com/securock/securock/internal/provenance"
	"github.com/securock/securock/internal/trust"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

type Options struct {
	Path    string
	Offline bool
	Policy  policy.Document
	Client  osv.Client
	Now     time.Time
}

type Result struct {
	Document lockfile.Document
}

func Scan(ctx context.Context, opts Options) (*Result, error) {
	path := opts.Path
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	deps, names, err := ecosystem.Collect(path)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(deps, func(a, b ecosystem.Dependency) int {
		if n := cmp.Compare(a.Ecosystem, b.Ecosystem); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return cmp.Compare(a.Version, b.Version)
	})

	var vulns map[string][]lockfile.Vulnerability
	if !opts.Offline {
		client := opts.Client
		if client == nil {
			client = osv.New()
		}
		vulns, err = client.Query(ctx, deps)
		if err != nil {
			return nil, err
		}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}

	doc := lockfile.Document{
		Version:     lockfile.SchemaVersion,
		GeneratedAt: now,
		Source: lockfile.Source{
			Path:       abs,
			Ecosystems: names,
		},
		Artifacts: make([]lockfile.Artifact, 0, len(deps)),
	}

	for _, dep := range deps {
		art := lockfile.Artifact{
			Ecosystem: dep.Ecosystem,
			Name:      dep.Name,
			Version:   dep.Version,
			Digest:    dep.Digest,
			Evidence: lockfile.Evidence{
				Provenance: provenance.State(),
				Signature:  lockfile.EvidenceUnknown,
			},
		}
		if vulns != nil {
			art.Evidence.Vulnerabilities = vulns[dep.Ecosystem+":"+dep.Name+"@"+dep.Version]
		}
		trust.Evaluate(&art, opts.Policy)
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return &Result{Document: doc}, nil
}

func Summary(doc lockfile.Document) (trusted, untrusted, unknown int) {
	for _, art := range doc.Artifacts {
		switch art.Trust.Status {
		case lockfile.StatusTrusted:
			trusted++
		case lockfile.StatusUntrusted:
			untrusted++
		default:
			unknown++
		}
	}
	return trusted, untrusted, unknown
}
