package scanner

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/internal/network"
	"github.com/securock/securock/internal/osv"
	"github.com/securock/securock/internal/provenance"
	"github.com/securock/securock/internal/reachability"
	"github.com/securock/securock/internal/trust"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

type Options struct {
	Path     string
	Offline  bool
	Network  policy.Network
	Policy   policy.Document
	Client   osv.Client
	Evidence evidence.Collector

	// Reachability records each package's scope and dependencies and marks every
	// vulnerability reachable, unreachable, or unknown. Off by default so the lockfile
	// stays small.
	Reachability bool
}

type Result struct {
	Document lockfile.Document
}

func Scan(ctx context.Context, opts Options) (*Result, error) {
	path := opts.Path
	if path == "" {
		path = "."
	}
	if opts.Policy.Version == 0 {
		opts.Policy = policy.Default()
	}

	deps, err := ecosystem.Collect(path)
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
		if n := cmp.Compare(a.Version, b.Version); n != 0 {
			return n
		}
		return cmp.Compare(a.Filename, b.Filename)
	})

	mode := opts.Network.ResolvedMode()
	if opts.Offline {
		mode = policy.ModeOffline
	}
	allowlist := opts.Network.Registries
	if len(allowlist) == 0 {
		allowlist = opts.Policy.Network.Registries
	}

	var query []ecosystem.Dependency
	allowed := make(map[string]bool, len(deps))
	for _, dep := range deps {
		key := ecosystem.Identity(dep)
		if network.Allow(mode, allowlist, dep) && osv.Queryable(dep) {
			query = append(query, dep)
			allowed[key] = true
		}
	}

	var (
		vulns   map[string][]lockfile.Vulnerability
		details map[string]osv.Detail
		ev      map[string]evidence.Record
	)
	if len(query) > 0 {
		client := opts.Client
		if client == nil {
			client = osv.New()
		}
		collector := opts.Evidence
		if collector == nil {
			collector = evidence.NewDefault()
		}

		// Evidence collection does not depend on the OSV results, so the two run
		// together. Either failure cancels the other. An independent OSV error wins
		// when both fail, but cancellation must not hide the evidence failure that caused it.
		ctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		var (
			wg    sync.WaitGroup
			evErr error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev, evErr = collector.Collect(ctx, query)
			if evErr != nil {
				cancel(evErr)
			}
		}()
		vulns, err = client.Query(ctx, query)
		if err == nil {
			details = advisoryDetails(ctx, client, vulns)
		} else {
			cancel(err)
		}
		wg.Wait()
		if err != nil {
			if errors.Is(err, context.Canceled) && evErr != nil && errors.Is(context.Cause(ctx), evErr) {
				return nil, evErr
			}
			return nil, err
		}
		if evErr != nil {
			return nil, evErr
		}
	}

	fp, err := policy.Fingerprint(opts.Policy)
	if err != nil {
		return nil, err
	}

	doc := lockfile.Document{
		Version:   lockfile.SchemaVersion,
		Policy:    lockfile.PolicyRef{Digest: fp},
		Artifacts: make([]lockfile.Artifact, 0, len(deps)),
	}

	for _, dep := range deps {
		art := lockfile.Artifact{
			Subject: lockfile.Subject{
				Ecosystem: dep.Ecosystem,
				Name:      dep.Name,
			},
			Version:  dep.Version,
			Filename: dep.Filename,
			Digest:   dep.Digest,
			Source: lockfile.ArtifactSource{
				Resolver:  dep.Resolver,
				Kind:      dep.SourceKind,
				Registry:  dep.Registry,
				Artifact:  dep.Artifact,
				Requested: dep.Requested,
				Resolved:  dep.Resolved,
			},
			Evidence: lockfile.Evidence{
				Provenance: provenance.State(),
				Signature:  lockfile.EvidenceUnknown,
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnUnknown,
				},
				Malicious: lockfile.MaliciousEvidence{
					State: lockfile.VulnUnknown,
				},
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
			},
		}
		key := ecosystem.Identity(dep)
		if rec, ok := ev[evidence.Key(dep)]; ok {
			art.Evidence.Provenance = rec.Provenance
			art.Evidence.Signature = rec.Signature
			if rec.Capabilities.State != "" {
				art.Evidence.Capabilities = rec.Capabilities
			}
			if rec.Behavior.State != "" {
				art.Evidence.Behavior = rec.Behavior
			}
			if rec.Ownership.State != "" {
				art.Evidence.Ownership = rec.Ownership
			}
			if rec.Chain.State != "" {
				art.Evidence.Chain = rec.Chain
			}
			art.Evidence.Health = rec.Health
		}
		if allowed[key] {
			art.Evidence.Vulnerabilities.State = lockfile.VulnChecked
			art.Evidence.Malicious.State = lockfile.VulnChecked
			if vulns != nil {
				cves, malware := osv.Partition(vulns[key])
				for i, v := range cves {
					if d, ok := details[v.ID]; ok {
						cves[i] = osv.Enrich(dep, v, d)
					}
				}
				art.Evidence.Vulnerabilities.Items = cves
				art.Evidence.Malicious.Reports = malware
			}
		}
		if opts.Reachability {
			art.Scope = lockfile.Scope(dep.Scope)
			art.Dependencies = dep.DependsOn
		}
		trust.Evaluate(&art, opts.Policy)
		doc.Artifacts = append(doc.Artifacts, art)
		doc.Source.Ecosystems = append(doc.Source.Ecosystems, dep.Ecosystem)
		if dep.Resolver != "" {
			doc.Source.Resolvers = append(doc.Source.Resolvers, dep.Resolver)
		}
	}

	lockfile.Canonicalize(&doc)
	if opts.Reachability {
		reachability.Annotate(&doc)
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

// advisoryDetails looks up severity and fix information for the advisories that were hit.
// It is best effort: a client that cannot look advisories up, or a lookup that fails, only
// means the findings carry no severity or fixed version.
func advisoryDetails(ctx context.Context, client osv.Client, hits map[string][]lockfile.Vulnerability) map[string]osv.Detail {
	detailer, ok := client.(osv.Detailer)
	if !ok {
		return nil
	}
	var ids []string
	for _, vulns := range hits {
		for _, v := range vulns {
			if !osv.IsMaliciousID(v.ID) {
				ids = append(ids, v.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	details, err := detailer.Details(ctx, ids)
	if err != nil {
		return nil
	}
	return details
}
