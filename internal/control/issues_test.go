package control_test

import (
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/runrecord"
	"strings"
	"testing"
)

func TestSharedIssuesRequireComparableCompletionEvidence(t *testing.T) {
	s, token, _ := fixture(t)
	admin, robot := token("alice"), token("robot")
	if w := request(s, admin, "POST", "/api/v1/projects", `{"id":"repo","name":"Repo","owner":"platform","sla_days":{"high":7}}`); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	complete := func(id string, report finding.Report) {
		t.Helper()
		request(s, admin, "POST", "/api/v1/jobs", `{"id":"`+id+`","project":"repo"}`)
		claimed := request(s, robot, "POST", "/api/v1/runner/claim", `{"projects":["repo"]}`)
		var v struct {
			Data control.Job `json:"data"`
		}
		_ = json.Unmarshal(claimed.Body.Bytes(), &v)
		record := runrecord.New("sha256:"+strings.Repeat("a", 64), strings.Repeat("b", 40), "configuration", "repo", false, []string{"main.go"}, report, true)
		body, _ := json.Marshal(map[string]any{"id": id, "lease": v.Data.Lease, "report": report, "record": record, "failed": false})
		if w := request(s, robot, "POST", "/api/v1/runner/complete", string(body)); w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	complete("scan-one", finding.New("security", []finding.Finding{{ID: "sast:tls", Title: "TLS issue", Severity: finding.SeverityHigh, Location: &finding.Location{File: "main.go", Line: 1}}}))
	registry := s.Store.Read().Tenants["a"].Registries["repo"]
	if len(registry.Entries) != 1 || registry.Entries[0].Owner != "platform" || registry.Entries[0].Due == "" {
		t.Fatal(registry)
	}
	if strings.Contains(request(s, token("bob"), "GET", "/api/v1/issues", "").Body.String(), "TLS issue") {
		t.Fatal("queue tenant leak")
	}
	complete("scan-two", finding.New("security", nil))
	registry = s.Store.Read().Tenants["a"].Registries["repo"]
	if registry.Entries[0].State != "resolved" {
		t.Fatal(registry.Entries)
	}
}
