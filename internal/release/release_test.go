package release_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/securock/securock/internal/inventory"
	"github.com/securock/securock/internal/release"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedDeliveriesImpactAndDrift(t *testing.T) {
	seed := bytes.Repeat([]byte{1}, 32)
	key := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	bom := []byte("{\n \"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\"lib\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/lib@1.0.0\"}]}\n")
	s := release.Statement{Product: "api", Release: "1.0", Artifact: "sha256:" + strings.Repeat("a", 64), Repository: "repo:.", Revision: strings.Repeat("b", 40)}
	env, e := release.Sign(s, bom, seed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := release.Verify(env, append(bom, ' '), key); e == nil {
		t.Fatal("changed SBOM accepted")
	}
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	shipment := release.Shipment{Customer: "customer-one", Attestation: env, SBOM: bom}
	if e := release.Register(catalog, shipment, key); e != nil {
		t.Fatal(e)
	}
	if e := release.Register(catalog, shipment, key); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(catalog)
	var c release.Catalog
	if e := json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	if len(c.Shipments) != 1 {
		t.Fatal("duplicate shipment")
	}
	imp, e := release.Impacts(c, []release.Advisory{{ID: "CVE-fixture", PURL: "pkg:npm/lib@1.0.0"}}, key)
	if e != nil || len(imp.Affected) != 1 || imp.Affected[0].Customer != "customer-one" {
		t.Fatal(imp, e)
	}
	graph := inventory.Report{Version: 1, Nodes: []inventory.Node{{ID: "repo:.", Kind: "repository", Revision: s.Revision}, {ID: "image:" + s.Artifact, Kind: "image", Digest: s.Artifact}}, Edges: []inventory.Edge{}, Gaps: []string{}}
	linked, findings, e := release.Link(c, graph, key)
	if e != nil || len(findings.Findings) != 0 || len(linked.Edges) != 1 {
		t.Fatal(linked, findings, e)
	}
	graph.Nodes = graph.Nodes[:1]
	_, findings, e = release.Link(c, graph, key)
	if e != nil || len(findings.Findings) == 0 {
		t.Fatal("signed image mistaken for observed deployment")
	}
	env.Signature = "forged"
	if _, e = release.Verify(env, bom, key); e == nil {
		t.Fatal("forged signer")
	}
}
