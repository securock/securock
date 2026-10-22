// Package sbom exports securock.lock as CycloneDX or SPDX and checks an SBOM against the lock.
//
// The export is a pure function of the lockfile, so it is deterministic: no timestamps
// unless SOURCE_DATE_EPOCH is set, and identifiers derived from the content.
package sbom

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/securock/securock/pkg/lockfile"
)

// PropertyPrefix namespaces the trust evidence securock adds to an SBOM.
const PropertyPrefix = "securock:"

// Property keys that verification reads back.
const (
	PropArtifact    = PropertyPrefix + "artifact"
	PropDigest      = PropertyPrefix + "digest"
	PropTrustStatus = PropertyPrefix + "trust.status"
	PropPolicy      = PropertyPrefix + "policy.digest"
)

type Options struct {
	ToolVersion string
	// Created stamps the document. The zero value omits the CycloneDX timestamp and
	// uses the Unix epoch for SPDX, which requires a creation date.
	Created time.Time
}

// CreatedFromEnv reads SOURCE_DATE_EPOCH, the reproducible-builds convention.
func CreatedFromEnv(getenv func(string) string) time.Time {
	secs, err := strconv.ParseInt(strings.TrimSpace(getenv("SOURCE_DATE_EPOCH")), 10, 64)
	if err != nil || secs < 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

type property struct{ Name, Value string }

type hash struct{ Alg, Hex string }

type component struct {
	ID         string
	Name       string
	Version    string
	PURL       string
	License    string
	Hashes     []hash
	Properties []property
}

func components(doc lockfile.Document) []component {
	out := make([]component, 0, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		out = append(out, component{
			ID:         a.ArtifactID(),
			Name:       a.Subject.Name,
			Version:    a.Version,
			PURL:       PURL(a),
			License:    declaredLicense(a),
			Hashes:     hashes(a.Digest),
			Properties: properties(a),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func declaredLicense(a lockfile.Artifact) string {
	if a.Evidence.Health == nil {
		return ""
	}
	return a.Evidence.Health.License
}

// hashes maps a lock digest to standard algorithms. It accepts "alg:hex" and the SRI form
// "alg-base64" that npm lockfiles use. Digests in other forms, such as Go's h1, stay
// available through the securock:digest property.
func hashes(digest string) []hash {
	if alg, payload, ok := strings.Cut(digest, "-"); ok && knownAlg(alg) {
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil || len(raw) != algSize[alg] {
			return nil
		}
		return []hash{{Alg: alg, Hex: hex.EncodeToString(raw)}}
	}
	alg, hexValue, ok := strings.Cut(digest, ":")
	if !ok || !knownAlg(alg) {
		return nil
	}
	if raw, err := hex.DecodeString(hexValue); err != nil || len(raw) != algSize[alg] {
		return nil
	}
	return []hash{{Alg: alg, Hex: strings.ToLower(hexValue)}}
}

var algSize = map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

func knownAlg(alg string) bool {
	_, ok := algSize[alg]
	return ok
}

// properties records the trust decision and evidence for one artifact.
func properties(a lockfile.Artifact) []property {
	var out []property
	add := func(name, value string) {
		if value != "" {
			out = append(out, property{PropertyPrefix + name, value})
		}
	}
	addBool := func(name string, v *bool) {
		if v != nil {
			add(name, strconv.FormatBool(*v))
		}
	}

	add("artifact", a.ArtifactID())
	add("digest", a.Digest)
	add("filename", a.Filename)
	add("license", declaredLicense(a))
	add("source.resolver", a.Source.Resolver)
	add("source.kind", a.Source.Kind)
	add("source.registry", a.Source.Registry)
	add("source.artifact", a.Source.Artifact)
	add("source.requested", a.Source.Requested)
	add("source.resolved", a.Source.Resolved)

	add("trust.status", string(a.Trust.Status))
	for _, r := range a.Trust.Reasons {
		add("trust.reason", r)
	}

	ev := a.Evidence
	add("evidence.provenance", string(ev.Provenance))
	add("evidence.signature", string(ev.Signature))
	add("evidence.vulnerabilities", string(ev.Vulnerabilities.State))
	add("evidence.malicious", string(ev.Malicious.State))
	add("evidence.capabilities", string(ev.Capabilities.State))
	add("evidence.behavior", string(ev.Behavior.State))
	add("evidence.ownership", string(ev.Ownership.State))
	add("evidence.chain", string(ev.Chain.State))

	if ev.Capabilities.State == lockfile.CapChecked {
		addBool("capability.network", ev.Capabilities.Network)
		add("capability.filesystem", string(ev.Capabilities.Filesystem))
		addBool("capability.environment", ev.Capabilities.Environment)
		addBool("capability.shell", ev.Capabilities.Shell)
		addBool("capability.native-code", ev.Capabilities.NativeCode)
		addBool("capability.install-scripts", ev.Capabilities.InstallScripts)
	}
	add("ownership.publisher", ev.Ownership.Publisher)
	for _, m := range ev.Ownership.Maintainers {
		add("ownership.maintainer", m)
	}
	add("chain.source", ev.Chain.Source)
	add("chain.commit", ev.Chain.Commit)
	add("chain.ref", ev.Chain.Ref)
	add("chain.builder", ev.Chain.Builder)
	add("chain.workflow", ev.Chain.Workflow)
	return out
}

// vulnerabilities groups advisory and malware IDs with the components they affect.
func vulnerabilities(doc lockfile.Document) map[string][]string {
	out := map[string][]string{}
	for _, a := range doc.Artifacts {
		if a.Evidence.Vulnerabilities.State == lockfile.VulnChecked {
			for _, v := range a.Evidence.Vulnerabilities.Items {
				out[v.ID] = append(out[v.ID], a.ArtifactID())
			}
		}
		if a.Evidence.Malicious.State == lockfile.VulnChecked {
			for _, r := range a.Evidence.Malicious.Reports {
				out[r.ID] = append(out[r.ID], a.ArtifactID())
			}
		}
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// contentID hashes the parts of an SBOM that identify it, so re-exporting the same lock
// yields the same serial number or namespace.
func contentID(parts ...string) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s\n", len(p), p)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// uuid formats a content hash as a version 5 style UUID.
func uuid(sum [32]byte) string {
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
