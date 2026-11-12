package coverage_test

import (
	"github.com/securock/securock/internal/coverage"
	"github.com/securock/securock/internal/finding"
	"testing"
)

func TestUnknownEvidenceAndAccounts(t *testing.T) {
	r := coverage.Build(finding.New("security", []finding.Finding{{ID: "cspm:check-unavailable", Subject: "AWS::S3::Bucket/123/us-east-1/x"}}), nil, nil, "")
	if len(r.Gaps) != 1 || len(r.Scopes) != 2 {
		t.Fatal(r)
	}
}

func TestUnsupportedResourcesRemainCoverageGaps(t *testing.T) {
	r := coverage.Build(finding.New("security", []finding.Finding{{ID: "cspm:unsupported-resource", Subject: "AWS::Lambda::Function/123/us-east-1/f"}}), nil, []string{"inventory.json"}, "")
	if len(r.Gaps) != 1 || r.Gaps[0].ID != "cspm:unsupported-resource" {
		t.Fatalf("missing unsupported resource: %+v", r)
	}
}

func TestIncompleteSourceAndExactTargetScope(t *testing.T) {
	r := coverage.Build(finding.New("security", []finding.Finding{
		{ID: "sast:analysis-incomplete", Subject: "main.kt"},
		{ID: "dast:analysis-incomplete", Subject: "https://app.test/api-other"},
	}), []string{"https://app.test/api"}, nil, "")
	for _, scope := range r.Scopes {
		if scope.Kind == "source" && scope.State != "incomplete" {
			t.Fatal(scope)
		}
		if scope.Kind == "dast" && scope.State != "attempted" {
			t.Fatal(scope)
		}
	}
}

func TestUncheckedSecretFilesMakeSourceIncomplete(t *testing.T) {
	r := coverage.Build(finding.New("security", []finding.Finding{{ID: "sast:secrets-unchecked", Subject: "dump.sh"}}), nil, nil, "")
	if len(r.Gaps) != 1 || r.Gaps[0].ID != "sast:secrets-unchecked" {
		t.Fatalf("unchecked file missing from gaps: %+v", r)
	}
	for _, scope := range r.Scopes {
		if scope.Kind == "source" && scope.State != "incomplete" {
			t.Fatalf("source scope must be incomplete: %+v", scope)
		}
	}
}
