package evidence_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/pkg/lockfile"
)

func TestExtractChainFromPredicate(t *testing.T) {
	raw := []byte(`{
		"attestations": [{
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {
				"buildDefinition": {
					"externalParameters": {
						"workflow": {
							"repository": "https://github.com/facebook/react",
							"path": ".github/workflows/release.yml",
							"ref": "refs/heads/main"
						}
					},
					"resolvedDependencies": [{
						"uri": "git+https://github.com/facebook/react@refs/heads/main",
						"digest": {"sha1": "abc123def4567890abc123def4567890abc123de"}
					}]
				},
				"runDetails": {
					"builder": {
						"id": "https://github.com/actions/runner"
					}
				}
			}
		}]
	}`)
	state, chain := evidence.ExtractChainForTest(raw)
	if state != lockfile.EvidencePresent {
		t.Fatalf("state = %s", state)
	}
	if chain.Source != "github.com/facebook/react" {
		t.Fatalf("source = %q", chain.Source)
	}
	if chain.Commit != "abc123def4567890abc123def4567890abc123de" {
		t.Fatalf("commit = %q", chain.Commit)
	}
	if chain.Workflow != "release.yml" {
		t.Fatalf("workflow = %q", chain.Workflow)
	}
	if chain.Builder == "" {
		t.Fatal("expected builder")
	}
}

func TestExtractChainFromDSSEPayload(t *testing.T) {
	stmt, err := json.Marshal(map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"externalParameters": map[string]any{
					"source": "https://github.com/acme/pkg.git",
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{
					"id": "https://github.com/acme/pkg/.github/workflows/publish.yml@refs/heads/main",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString(stmt)
	raw, err := json.Marshal(map[string]any{
		"attestations": []any{
			map[string]any{
				"bundle": map[string]any{
					"dsseEnvelope": map[string]any{
						"payload": payload,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, chain := evidence.ExtractChainForTest(raw)
	if state != lockfile.EvidencePresent {
		t.Fatalf("state = %s", state)
	}
	if chain.Source != "github.com/acme/pkg" {
		t.Fatalf("source = %q", chain.Source)
	}
	if chain.Workflow != "publish.yml" {
		t.Fatalf("workflow = %q want publish.yml from builder", chain.Workflow)
	}
}

func TestExtractChainMissing(t *testing.T) {
	state, chain := evidence.ExtractChainForTest([]byte(`{"attestations":[]}`))
	if state != lockfile.EvidenceMissing || chain.State != lockfile.EvidenceMissing {
		t.Fatalf("got state=%s chain=%+v", state, chain)
	}
}
