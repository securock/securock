package prioritization_test

import (
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/prioritization"
	"strings"
	"testing"
)

func TestContextRaisesPriorityWithoutChangingSeverity(t *testing.T) {
	c, e := prioritization.Read(strings.NewReader(`{"version":1,"assets":[{"match":"app/","criticality":5,"internet_exposed":true,"evidence":["inventory:edge"]}]}`))
	if e != nil {
		t.Fatal(e)
	}
	r := prioritization.Rank(finding.New("security", []finding.Finding{{ID: "a", Subject: "app/x", Severity: finding.SeverityMedium}, {ID: "b", Subject: "other", Severity: finding.SeverityMedium}}), c)
	if r.Items[0].Finding.ID != "a" || r.Items[0].Finding.Severity != finding.SeverityMedium {
		t.Fatal(r)
	}
	if _, e := prioritization.Read(strings.NewReader(`{"version":1,"assets":[{"match":"x","criticality":5}]}`)); e == nil {
		t.Fatal("context without evidence accepted")
	}
}
