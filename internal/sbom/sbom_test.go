package sbom_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/sbom"
	"github.com/securock/securock/pkg/lockfile"
)

func art(eco, name, version, digest string) lockfile.Artifact {
	return lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: eco, Name: name},
		Version: version,
		Digest:  digest,
		Source:  lockfile.ArtifactSource{Resolver: eco, Kind: "registry", Registry: "https://registry.example"},
		Evidence: lockfile.Evidence{
			Provenance:      lockfile.EvidenceVerified,
			Signature:       lockfile.EvidenceMissing,
			Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
			Capabilities:    lockfile.CapabilityEvidence{State: lockfile.CapChecked, Network: lockfile.Bool(true), Filesystem: lockfile.FilesystemRead},
			Ownership:       lockfile.OwnershipEvidence{State: lockfile.CapChecked, Publisher: "alice", Maintainers: []string{"alice", "bob"}},
			Chain:           lockfile.ChainEvidence{State: lockfile.EvidenceVerified, Source: "github.com/o/r", Commit: "abc"},
		},
		Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
	}
}

func srisha512(t *testing.T, seed string) (sri, hexed string) {
	t.Helper()
	sum := sha512.Sum512([]byte(seed))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:]), hex.EncodeToString(sum[:])
}

func fixture(t *testing.T) lockfile.Document {
	t.Helper()
	sri, _ := srisha512(t, "react")
	vulnerable := art("npm", "lodash", "4.17.20", "sha256:"+strings.Repeat("ab", 32))
	vulnerable.Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{{ID: "GHSA-aaaa"}}
	vulnerable.Trust = lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerability"}}
	return lockfile.Document{
		Version: 2,
		Policy:  lockfile.PolicyRef{Digest: "sha256:policy"},
		Artifacts: []lockfile.Artifact{
			art("npm", "react", "19.1.0", sri),
			vulnerable,
			art("go", "github.com/Gorilla/mux", "v1.8.0", "goh1:abc="),
			art("url", "https://esm.sh/preact", "", ""),
		},
	}
}

func export(t *testing.T, write func(w *bytes.Buffer) error) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cdx(t *testing.T, doc lockfile.Document, o sbom.Options) []byte {
	return export(t, func(w *bytes.Buffer) error { return sbom.WriteCycloneDX(w, doc, o) })
}

func spdx(t *testing.T, doc lockfile.Document, o sbom.Options) []byte {
	return export(t, func(w *bytes.Buffer) error { return sbom.WriteSPDX(w, doc, o) })
}

func TestPURL(t *testing.T) {
	tests := []struct {
		eco, name, version, registry, want string
	}{
		{"npm", "react", "19.1.0", "", "pkg:npm/react@19.1.0"},
		{"npm", "@babel/core", "7.0.0", "", "pkg:npm/%40babel/core@7.0.0"},
		{"pypi", "Foo_Bar", "1.0", "", "pkg:pypi/foo-bar@1.0"},
		{"cargo", "serde", "1.0.200", "", "pkg:cargo/serde@1.0.200"},
		{"go", "github.com/Gorilla/mux", "v1.8.0", "", "pkg:golang/github.com/gorilla/mux@v1.8.0"},
		{"packagist", "Symfony/Console", "6.4.0", "", "pkg:composer/symfony/console@6.4.0"},
		{"rubygems", "rails", "7.1.0", "", "pkg:gem/rails@7.1.0"},
		{"nuget", "Newtonsoft.Json", "13.0.3", "", "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{"pub", "http", "1.2.0", "", "pkg:pub/http@1.2.0"},
		{"hex", "phoenix", "1.7.0", "", "pkg:hex/phoenix@1.7.0"},
		{"maven", "org.slf4j:slf4j-api", "2.0.9", "", "pkg:maven/org.slf4j/slf4j-api@2.0.9"},
		{"swift", "swift-log", "1.5.3", "https://github.com/apple/swift-log.git", "pkg:swift/github.com/apple/swift-log@1.5.3"},
		{"swift", "swift-log", "1.5.3", "", "pkg:swift/swift-log@1.5.3"},
		{"npm", "weird", "1.0.0+build", "", "pkg:npm/weird@1.0.0%2Bbuild"},
		{"url", "https://esm.sh/preact", "", "", ""},
		{"jsr", "@std/path", "1.0.0", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.eco+"/"+tt.name, func(t *testing.T) {
			a := art(tt.eco, tt.name, tt.version, "")
			a.Source.Registry = tt.registry
			if got := sbom.PURL(a); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCycloneDXContent(t *testing.T) {
	doc := fixture(t)
	raw := cdx(t, doc, sbom.Options{ToolVersion: "1.2.3"})

	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
		Components []struct {
			BOMRef     string `json:"bom-ref"`
			PURL       string `json:"purl"`
			Hashes     []struct{ Alg, Content string }
			Properties []struct{ Name, Value string }
		} `json:"components"`
		Vulnerabilities []struct {
			ID      string
			Affects []struct{ Ref string }
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Fatalf("header: %s", raw)
	}
	if bom.Metadata.Timestamp != "" {
		t.Fatal("timestamp must be omitted without SOURCE_DATE_EPOCH")
	}
	if len(bom.Components) != 4 {
		t.Fatalf("components: %d", len(bom.Components))
	}
	refs := make([]string, 0, 4)
	for _, c := range bom.Components {
		refs = append(refs, c.BOMRef)
	}
	if strings.Join(refs, ",") != "go:github.com/Gorilla/mux@v1.8.0,npm:lodash@4.17.20,npm:react@19.1.0,url:https://esm.sh/preact" {
		t.Fatalf("components should be sorted by artifact id: %v", refs)
	}

	_, wantHex := srisha512(t, "react")
	for _, c := range bom.Components {
		switch c.BOMRef {
		case "npm:react@19.1.0":
			if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-512" || c.Hashes[0].Content != wantHex {
				t.Fatalf("sri digest should become a SHA-512 hash: %+v", c.Hashes)
			}
		case "npm:lodash@4.17.20":
			if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" {
				t.Fatalf("hashes: %+v", c.Hashes)
			}
		case "go:github.com/Gorilla/mux@v1.8.0":
			if len(c.Hashes) != 0 {
				t.Fatalf("go h1 digests have no standard algorithm: %+v", c.Hashes)
			}
			if !hasProp(c.Properties, "securock:digest", "goh1:abc=") {
				t.Fatalf("raw digest should be kept as a property: %+v", c.Properties)
			}
		case "url:https://esm.sh/preact":
			if c.PURL != "" {
				t.Fatalf("url imports have no purl: %q", c.PURL)
			}
		}
	}
	for _, c := range bom.Components {
		if c.BOMRef != "npm:lodash@4.17.20" {
			continue
		}
		for _, want := range [][2]string{
			{"securock:trust.status", "untrusted"},
			{"securock:trust.reason", "known vulnerability"},
			{"securock:evidence.provenance", "verified"},
			{"securock:evidence.signature", "missing"},
			{"securock:capability.network", "true"},
			{"securock:ownership.maintainer", "bob"},
			{"securock:chain.commit", "abc"},
		} {
			if !hasProp(c.Properties, want[0], want[1]) {
				t.Fatalf("missing %v in %+v", want, c.Properties)
			}
		}
	}
	if len(bom.Vulnerabilities) != 1 || bom.Vulnerabilities[0].ID != "GHSA-aaaa" || bom.Vulnerabilities[0].Affects[0].Ref != "npm:lodash@4.17.20" {
		t.Fatalf("vulnerabilities: %+v", bom.Vulnerabilities)
	}
}

func hasProp(props []struct{ Name, Value string }, name, value string) bool {
	for _, p := range props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}

func TestSPDXContent(t *testing.T) {
	raw := spdx(t, fixture(t), sbom.Options{ToolVersion: "1.2.3", Created: time.Unix(1700000000, 0)})
	var doc struct {
		SPDXVersion  string `json:"spdxVersion"`
		SPDXID       string
		CreationInfo struct {
			Created  string
			Creators []string
		} `json:"creationInfo"`
		Packages []struct {
			SPDXID       string
			Checksums    []struct{ Algorithm, ChecksumValue string }
			ExternalRefs []struct{ ReferenceType, ReferenceLocator string }
			Annotations  []struct{ Comment string }
		} `json:"packages"`
		Relationships []struct{ RelationshipType, RelatedSpdxElement string }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Fatalf("header: %s", raw)
	}
	if doc.CreationInfo.Created != "2023-11-14T22:13:20Z" || doc.CreationInfo.Creators[0] != "Tool: securock-1.2.3" {
		t.Fatalf("creation info: %+v", doc.CreationInfo)
	}
	if len(doc.Packages) != 4 || len(doc.Relationships) != 4 {
		t.Fatalf("packages %d, relationships %d", len(doc.Packages), len(doc.Relationships))
	}
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		if !strings.HasPrefix(p.SPDXID, "SPDXRef-Package-") || strings.ContainsAny(p.SPDXID, ":/@_ ") {
			t.Fatalf("invalid SPDXID %q", p.SPDXID)
		}
		if ids[p.SPDXID] {
			t.Fatalf("duplicate SPDXID %q", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
	for _, rel := range doc.Relationships {
		if rel.RelationshipType != "DESCRIBES" || !ids[rel.RelatedSpdxElement] {
			t.Fatalf("relationship: %+v", rel)
		}
	}
}

func TestExportIsDeterministic(t *testing.T) {
	doc := fixture(t)
	reversed := fixture(t)
	for i, j := 0, len(reversed.Artifacts)-1; i < j; i, j = i+1, j-1 {
		reversed.Artifacts[i], reversed.Artifacts[j] = reversed.Artifacts[j], reversed.Artifacts[i]
	}
	if !bytes.Equal(cdx(t, doc, sbom.Options{}), cdx(t, reversed, sbom.Options{})) {
		t.Fatal("cyclonedx depends on artifact order")
	}
	if !bytes.Equal(spdx(t, doc, sbom.Options{}), spdx(t, reversed, sbom.Options{})) {
		t.Fatal("spdx depends on artifact order")
	}

	changed := fixture(t)
	changed.Artifacts[0].Version = "19.2.0"
	if bytes.Equal(cdx(t, doc, sbom.Options{}), cdx(t, changed, sbom.Options{})) {
		t.Fatal("different locks must not export identically")
	}
}

func TestCreatedFromEnv(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if got := sbom.CreatedFromEnv(env("1700000000")); got.Unix() != 1700000000 {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"", "soon", "-5"} {
		if got := sbom.CreatedFromEnv(env(bad)); !got.IsZero() {
			t.Fatalf("%q should be ignored, got %v", bad, got)
		}
	}
	raw := cdx(t, fixture(t), sbom.Options{Created: time.Unix(1700000000, 0)})
	if !bytes.Contains(raw, []byte(`"timestamp": "2023-11-14T22:13:20Z"`)) {
		t.Fatalf("missing timestamp:\n%s", raw)
	}
}

func verify(t *testing.T, lock lockfile.Document, raw []byte) []string {
	t.Helper()
	parsed, err := sbom.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range sbom.Verify(lock, parsed).Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestVerifyRoundTrip(t *testing.T) {
	doc := fixture(t)
	for name, raw := range map[string][]byte{
		"cyclonedx": cdx(t, doc, sbom.Options{}),
		"spdx":      spdx(t, doc, sbom.Options{}),
	} {
		t.Run(name, func(t *testing.T) {
			if got := verify(t, doc, raw); len(got) != 0 {
				t.Fatalf("unexpected findings: %v", got)
			}
		})
	}
}

func TestVerifyDetectsDrift(t *testing.T) {
	exported := fixture(t)
	tests := []struct {
		name   string
		mutate func(*lockfile.Document)
		want   []string
	}{
		{"package added to lock", func(d *lockfile.Document) {
			d.Artifacts = append(d.Artifacts, art("npm", "new", "1.0.0", ""))
		}, []string{"sbom-component-missing"}},
		{"package removed from lock", func(d *lockfile.Document) {
			d.Artifacts = d.Artifacts[:len(d.Artifacts)-1]
		}, []string{"sbom-component-unexpected"}},
		{"version bumped", func(d *lockfile.Document) {
			d.Artifacts[1].Version = "4.17.21"
		}, []string{"sbom-component-missing", "sbom-component-unexpected"}},
		{"digest changed", func(d *lockfile.Document) {
			d.Artifacts[1].Digest = "sha256:" + strings.Repeat("cd", 32)
		}, []string{"sbom-digest-mismatch"}},
		{"trust changed", func(d *lockfile.Document) {
			d.Artifacts[0].Trust.Status = lockfile.StatusUntrusted
		}, []string{"sbom-trust-mismatch"}},
		{"policy changed", func(d *lockfile.Document) {
			d.Policy.Digest = "sha256:other"
		}, []string{"sbom-policy-mismatch"}},
	}
	for _, spec := range []string{"cyclonedx", "spdx"} {
		for _, tt := range tests {
			t.Run(spec+"/"+tt.name, func(t *testing.T) {
				raw := cdx(t, exported, sbom.Options{})
				if spec == "spdx" {
					raw = spdx(t, exported, sbom.Options{})
				}
				lock := fixture(t)
				tt.mutate(&lock)
				got := verify(t, lock, raw)
				if spec == "spdx" && tt.name == "policy changed" {
					if len(got) != 0 {
						t.Fatalf("spdx carries no policy digest, got %v", got)
					}
					return
				}
				if strings.Join(sorted(got), ",") != strings.Join(sorted(tt.want), ",") {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			})
		}
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestVerifyForeignSBOMMatchesByPURL(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"name":"react","version":"19.1.0","purl":"pkg:npm/react@19.1.0"},
		{"name":"mystery","version":"1","purl":"pkg:npm/mystery@1"}]}`)
	lock := lockfile.Document{Artifacts: []lockfile.Artifact{art("npm", "react", "19.1.0", "")}}
	got := verify(t, lock, raw)
	if strings.Join(got, ",") != "sbom-component-unexpected" {
		t.Fatalf("got %v", got)
	}
}

func TestParseRejectsOtherDocuments(t *testing.T) {
	for _, raw := range []string{`not json`, `{}`, `{"bomFormat":"Other"}`, `[]`} {
		if _, err := sbom.Parse([]byte(raw)); err == nil {
			t.Fatalf("%q should be rejected", raw)
		}
	}
}

func TestLicenseExport(t *testing.T) {
	doc := fixture(t)
	doc.Artifacts[0].Evidence.Health = &lockfile.HealthEvidence{License: "MIT OR Apache-2.0"} // react
	doc.Artifacts[1].Evidence.Health = &lockfile.HealthEvidence{License: "Custom Terms 1.0"}  // lodash
	// the Go and url artifacts have no health evidence

	var bom struct {
		Components []struct {
			BOMRef   string `json:"bom-ref"`
			Licenses []struct {
				Expression string `json:"expression"`
				License    *struct {
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdx(t, doc, sbom.Options{}), &bom); err != nil {
		t.Fatal(err)
	}
	for _, c := range bom.Components {
		switch c.BOMRef {
		case "npm:react@19.1.0":
			if len(c.Licenses) != 1 || c.Licenses[0].Expression != "MIT OR Apache-2.0" {
				t.Fatalf("react licenses = %+v", c.Licenses)
			}
		case "npm:lodash@4.17.20":
			if len(c.Licenses) != 1 || c.Licenses[0].License == nil || c.Licenses[0].License.Name != "Custom Terms 1.0" {
				t.Fatalf("a license that is not SPDX is exported as a name: %+v", c.Licenses)
			}
		default:
			if len(c.Licenses) != 0 {
				t.Fatalf("%s: nothing to say without evidence: %+v", c.BOMRef, c.Licenses)
			}
		}
	}

	var spdxDoc struct {
		Packages []struct {
			Name            string `json:"name"`
			LicenseDeclared string `json:"licenseDeclared"`
			Annotations     []struct{ Comment string }
		} `json:"packages"`
	}
	if err := json.Unmarshal(spdx(t, doc, sbom.Options{}), &spdxDoc); err != nil {
		t.Fatal(err)
	}
	declared := map[string]string{}
	for _, p := range spdxDoc.Packages {
		declared[p.Name] = p.LicenseDeclared
		if p.Name == "lodash" {
			found := false
			for _, a := range p.Annotations {
				found = found || a.Comment == "securock:license=Custom Terms 1.0"
			}
			if !found {
				t.Fatalf("the raw license must stay available as an annotation: %+v", p.Annotations)
			}
		}
	}
	if declared["react"] != "MIT OR Apache-2.0" || declared["lodash"] != "NOASSERTION" || declared["github.com/Gorilla/mux"] != "NOASSERTION" {
		t.Fatalf("licenseDeclared = %v", declared)
	}
}

func TestCycloneDXVulnerabilityRatings(t *testing.T) {
	doc := fixture(t)
	doc.Artifacts[1].Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{{ID: "GHSA-aaaa", Severity: lockfile.SeverityCritical}}
	extra := art("npm", "other", "1.0.0", "")
	extra.Evidence.Vulnerabilities = lockfile.VulnEvidence{State: lockfile.VulnChecked, Items: []lockfile.Vulnerability{
		{ID: "GHSA-aaaa", Severity: lockfile.SeverityMedium}, {ID: "GHSA-bare"},
	}}
	doc.Artifacts = append(doc.Artifacts, extra)

	var bom struct {
		Vulnerabilities []struct {
			ID      string
			Ratings []struct{ Severity string }
		}
	}
	if err := json.Unmarshal(cdx(t, doc, sbom.Options{}), &bom); err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, v := range bom.Vulnerabilities {
		for _, r := range v.Ratings {
			got[v.ID] = append(got[v.ID], r.Severity)
		}
		if _, seen := got[v.ID]; !seen {
			got[v.ID] = nil
		}
	}
	if len(got["GHSA-aaaa"]) != 1 || got["GHSA-aaaa"][0] != "critical" {
		t.Fatalf("the highest severity wins: %v", got)
	}
	if len(got["GHSA-bare"]) != 0 {
		t.Fatalf("an unrated advisory has no rating: %v", got)
	}
}
