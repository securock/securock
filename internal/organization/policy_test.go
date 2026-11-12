package organization_test

import (
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/organization"
	"strings"
	"testing"
)

func TestApprovalLimitsAndSLA(t *testing.T) {
	p, e := organization.Read(strings.NewReader(`{"version":1,"services":{"api":{"owner":"security","criticality":5,"fail_on":"high","sla_days":{"high":7},"require_approver":true,"reviewers":["alice"],"max_exception_days":30}}}`))
	if e != nil {
		t.Fatal(e)
	}
	r := finding.New("security", []finding.Finding{{ID: "risk", Title: "risk", Severity: finding.SeverityHigh, Suppressed: &finding.Suppression{Approver: "bob", Expires: "2030-01-10", Reason: "review"}}})
	out, e := organization.Evaluate(r, p, "api", "2030-01-01")
	if e != nil || out.Report.AtLeast(finding.SeverityHigh) != 2 || len(out.Tasks) != 1 || out.Tasks[0].Due != "2030-01-08" {
		t.Fatal(out, e)
	}
	if r.Findings[0].Suppressed == nil {
		t.Fatal("input mutated")
	}
}

func TestEmptyApproverCannotBypassReview(t *testing.T) {
	for _, raw := range []string{`{"version":1,"services":{"api":{"owner":"team","criticality":5,"fail_on":"high","max_exception_days":30,"require_approver":true,"reviewers":[""]}}}`, `{"version":1,"services":{"api":{"owner":"team","criticality":5,"fail_on":"high","max_exception_days":30,"require_approver":null}}}`} {
		if _, e := organization.Read(strings.NewReader(raw)); e == nil {
			t.Fatal("unsafe policy accepted")
		}
	}
}
