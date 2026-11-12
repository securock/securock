package dashboard_test

import (
	"bytes"
	"github.com/securock/securock/internal/dashboard"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/lifecycle"
	"strings"
	"testing"
)

func TestOfflineEscapingAndStates(t *testing.T) {
	r := lifecycle.Registry{Version: 1, Entries: []lifecycle.Entry{{Key: "k", State: "new", Finding: finding.Finding{ID: "risk", Title: "</td><script>alert(1)</script>", Subject: "<img src=x>", Severity: finding.SeverityHigh}}}}
	var b bytes.Buffer
	if e := dashboard.Render(&b, r, nil, ""); e != nil {
		t.Fatal(e)
	}
	html := b.String()
	if strings.Contains(html, "<script>alert(1)</script>") || !strings.Contains(html, "&lt;img src=x&gt;") || !strings.Contains(html, "connect-src") {
		t.Fatal("unsafe or incomplete HTML")
	}
	if e := dashboard.Render(&b, lifecycle.Registry{}, nil, ""); e == nil {
		t.Fatal("invalid state accepted")
	}
}
