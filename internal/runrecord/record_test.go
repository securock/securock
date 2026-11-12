package runrecord_test

import (
	"encoding/json"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/runrecord"
	"strings"
	"testing"
)

func TestIntegrityAndSourceCompleteness(t *testing.T) {
	r := runrecord.New("v1", "abc", "config", "app", false, []string{"a.go"}, finding.New("security", nil), true)
	raw, _ := json.Marshal(r)
	if _, e := runrecord.Read(strings.NewReader(string(raw))); e != nil {
		t.Fatal(e)
	}
	r.Report.Findings = append(r.Report.Findings, finding.Finding{ID: "x"})
	raw, _ = json.Marshal(r)
	if _, e := runrecord.Read(strings.NewReader(string(raw))); e == nil {
		t.Fatal("altered report accepted")
	}
	r = runrecord.New("v1", "abc", "config", "", false, nil, finding.New("security", nil), true)
	if r.Scopes[0].Complete {
		t.Fatal("anonymous scope certified")
	}
}
