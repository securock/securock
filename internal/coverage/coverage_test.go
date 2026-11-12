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
