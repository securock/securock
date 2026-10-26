package chain_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/chain"
	"github.com/securock/securock/internal/finding"
)

func taint(id, subject string, sev finding.Severity, src, sink string) finding.Finding {
	f := finding.Finding{
		ID:       id,
		Severity: sev,
		Title:    "title (CWE-89)",
		Subject:  subject,
		Location: &finding.Location{File: fileOf(subject), Line: 9},
	}
	for _, s := range []string{src, sink} {
		f.Trace = append(f.Trace, finding.Step{Location: finding.Location{File: fileOf(subject), Line: 9}, Message: s})
	}
	return f
}

// fileOf mirrors the subject format "file#fn/sink" the sast engine writes.
func fileOf(subject string) string {
	for i := 0; i < len(subject); i++ {
		if subject[i] == '#' {
			return subject[:i]
		}
	}
	return subject
}

func chainByNode(chains []chain.Chain) map[string]chain.Chain {
	out := map[string]chain.Chain{}
	for _, c := range chains {
		out[c.Nodes[0].FindingID+"/"+string(c.Nodes[0].Stage)+"+"+c.Nodes[1].FindingID+"/"+string(c.Nodes[1].Stage)] = c
	}
	return out
}

func TestSingleFindingChain(t *testing.T) {
	f := taint("sast:go/command-injection", "main.go#h/exec.Command", finding.SeverityHigh,
		"untrusted data: request body", "reaches exec.Command (CWE-78)")
	got := chain.Analyze([]finding.Finding{f})
	if len(got) != 1 {
		t.Fatalf("chains = %+v", got)
	}
	c := got[0]
	if c.Status != chain.Confirmed || c.Severity != finding.SeverityHigh {
		t.Fatalf("chain = %+v", c)
	}
	if c.Nodes[0].Stage != chain.StageEntry || c.Nodes[0].Detail != "request body" {
		t.Fatalf("entry node = %+v", c.Nodes[0])
	}
	if c.Nodes[1].Stage != chain.StageImpact {
		t.Fatalf("sink node = %+v", c.Nodes[1])
	}
	if c.Links[0].Status != chain.Confirmed {
		t.Fatalf("link = %+v", c.Links[0])
	}
}

func TestParameterSourceIsNotAChainAlone(t *testing.T) {
	// A parameter source has no proven attacker reach, so the finding alone is not a
	// chain; it only composes with another finding's sink.
	f := taint("sast:go/command-injection", "main.go#run/exec.Command", finding.SeverityHigh,
		"untrusted data: parameter cmd of run", "reaches exec.Command (CWE-78)")
	if got := chain.Analyze([]finding.Finding{f}); len(got) != 0 {
		t.Fatalf("chains = %+v", got)
	}
}

func TestCompositionLink(t *testing.T) {
	entry := taint("sast:go/sql-injection", "main.go#h/sql.DB.Query", finding.SeverityHigh,
		"untrusted data: parameter id of load", "reaches (*sql.DB).Query (CWE-89)")
	sink := taint("sast:go/command-injection", "main.go#run/exec.Command", finding.SeverityHigh,
		"untrusted data: request body", "reaches exec.Command (CWE-78)")
	got := chainByNode(chain.Analyze([]finding.Finding{entry, sink}))
	c, ok := got["sast:go/sql-injection/entry+sast:go/command-injection/impact"]
	if !ok {
		t.Fatalf("chains = %+v", got)
	}
	// Different functions in the same file: the link is possible, not confirmed.
	if c.Status != chain.Possible {
		t.Fatalf("status = %s", c.Status)
	}
	if c.Severity != finding.SeverityHigh {
		t.Fatalf("severity = %s", c.Severity)
	}

	// The same function label makes the link confirmed.
	entry.Subject = "main.go#run/sql.DB.Query"
	got = chainByNode(chain.Analyze([]finding.Finding{entry, sink}))
	c, ok = got["sast:go/sql-injection/entry+sast:go/command-injection/impact"]
	if !ok || c.Status != chain.Confirmed {
		t.Fatalf("chain = %+v", c)
	}
	if !strings.Contains(c.Links[0].Reason, "and the same function") {
		t.Fatalf("reason = %s", c.Links[0].Reason)
	}
}

func TestEnablerLink(t *testing.T) {
	enabler := finding.Finding{
		ID:       "sast:go/csrf-disabled",
		Severity: finding.SeverityMedium,
		Title:    "CSRF protection disabled (CWE-352)",
		Subject:  "main.go#h",
		Location: &finding.Location{File: "main.go", Line: 5},
	}
	sink := taint("sast:go/sql-injection", "main.go#h/sql.DB.Query", finding.SeverityHigh,
		"untrusted data: request body", "reaches (*sql.DB).Query (CWE-89)")
	got := chainByNode(chain.Analyze([]finding.Finding{enabler, sink}))
	c, ok := got["sast:go/csrf-disabled/entry+sast:go/sql-injection/pivot"]
	if !ok {
		t.Fatalf("chains = %+v", got)
	}
	if c.Status != chain.Confirmed || c.Severity != finding.SeverityHigh {
		t.Fatalf("chain = %+v", c)
	}
	if want := "untrusted input can reach sql-injection in main.go past CSRF protection disabled"; c.Summary != want {
		t.Fatalf("summary = %s", c.Summary)
	}
}

func TestCredentialExfilLink(t *testing.T) {
	sink := taint("sast:go/path-traversal", "main.go#h/os.ReadFile", finding.SeverityHigh,
		"untrusted data: request path", "reaches os.ReadFile (CWE-22)")
	secret := finding.Finding{
		ID:       "sast:secrets/aws-access-key",
		Severity: finding.SeverityHigh,
		Title:    "Credential committed to the repository (CWE-798)",
		Subject:  "main.go#aws-access-key",
		Location: &finding.Location{File: "main.go", Line: 3},
	}
	got := chainByNode(chain.Analyze([]finding.Finding{sink, secret}))
	c, ok := got["sast:go/path-traversal/pivot+sast:secrets/aws-access-key/impact"]
	if !ok {
		t.Fatalf("chains = %+v", got)
	}
	if c.Status != chain.Possible {
		t.Fatalf("status = %s", c.Status)
	}
	if want := "an attacker who reaches path-traversal in main.go can read the credential committed there"; c.Summary != want {
		t.Fatalf("summary = %s", c.Summary)
	}

	// A non-egress sink does not pair with the credential.
	read := taint("sast:go/sql-injection", "main.go#h/sql.DB.Query", finding.SeverityHigh,
		"untrusted data: request body", "reaches (*sql.DB).Query (CWE-89)")
	got = chainByNode(chain.Analyze([]finding.Finding{read, secret}))
	if c, ok := got["sast:go/sql-injection/pivot+sast:secrets/aws-access-key/impact"]; ok {
		t.Fatalf("unexpected chain = %+v", c)
	}
}

func TestOrderingAndStableIDs(t *testing.T) {
	critical := taint("sast:go/code-injection", "a.go#h/eval", finding.SeverityCritical,
		"untrusted data: request body", "reaches eval (CWE-95)")
	low := taint("sast:go/xss", "b.go#h/html", finding.SeverityLow,
		"untrusted data: request body", "reaches html (CWE-79)")
	enabler := finding.Finding{
		ID:       "sast:go/debug-enabled", // stage entry
		Severity: finding.SeverityMedium,
		Title:    "Debug mode enabled (CWE-489)",
		Subject:  "b.go#h",
		Location: &finding.Location{File: "b.go", Line: 4},
	}
	got := chain.Analyze([]finding.Finding{low, enabler, critical})
	if len(got) != 3 {
		t.Fatalf("chains = %+v", got)
	}
	if got[0].Severity != finding.SeverityCritical || got[0].ID != "chain:1" {
		t.Fatalf("first = %+v", got[0])
	}
	// Both remaining chains are high? No: one is medium (enabler + low sink), one low.
	if got[1].ID != "chain:2" || got[2].ID != "chain:3" {
		t.Fatalf("ids = %s, %s", got[1].ID, got[2].ID)
	}
	if !(got[1].Severity.Rank() >= got[2].Severity.Rank()) {
		t.Fatalf("order = %+v", got)
	}
	// Deterministic: the same input gives the same IDs.
	again := chain.Analyze([]finding.Finding{low, enabler, critical})
	for i := range got {
		if chainKeyForTest(got[i]) != chainKeyForTest(again[i]) {
			t.Fatalf("not deterministic at %d", i)
		}
	}
}

func chainKeyForTest(c chain.Chain) string {
	s := ""
	for _, n := range c.Nodes {
		s += n.FindingID + "/" + string(n.Stage) + "+"
	}
	return s + c.ID
}

func TestSuppressedAndUnstagedAreSkipped(t *testing.T) {
	now := "2030-01-01"
	f := taint("sast:go/command-injection", "main.go#h/exec.Command", finding.SeverityHigh,
		"untrusted data: request body", "reaches exec.Command (CWE-78)")
	f.Suppressed = &finding.Suppression{Reason: "accepted", Expires: now}
	incomplete := finding.Finding{ID: "sast:analysis-incomplete", Severity: finding.SeverityInfo}
	unstaged := finding.Finding{
		ID:       "sast:go/weak-crypto", // no chain role
		Severity: finding.SeverityMedium,
		Subject:  "main.go#h",
		Location: &finding.Location{File: "main.go", Line: 2},
	}
	if got := chain.Analyze([]finding.Finding{f, incomplete, unstaged}); len(got) != 0 {
		t.Fatalf("chains = %+v", got)
	}
}

func TestCountAndFailThreshold(t *testing.T) {
	confirmed := taint("sast:go/command-injection", "main.go#h/exec.Command", finding.SeverityHigh,
		"untrusted data: request body", "reaches exec.Command (CWE-78)")
	enabler := finding.Finding{
		ID:       "sast:go/debug-enabled",
		Severity: finding.SeverityMedium,
		Title:    "Debug mode enabled (CWE-489)",
		Subject:  "other.go#h",
		Location: &finding.Location{File: "other.go", Line: 4},
	}
	low := taint("sast:go/xss", "other.go#h/html", finding.SeverityLow,
		"untrusted data: request body", "reaches html (CWE-79)")
	report := chain.Report{Tool: "chain", Chains: chain.Analyze([]finding.Finding{confirmed, enabler, low})}
	counts := report.Count()
	if counts[finding.SeverityHigh] != 1 || counts[finding.SeverityLow] != 1 || counts[finding.SeverityMedium] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
	// Only confirmed chains count toward the threshold.
	if n := report.AtLeast(finding.SeverityHigh); n != 1 {
		t.Fatalf("AtLeast(high) = %d", n)
	}
	if n := report.AtLeast(finding.SeverityCritical); n != 0 {
		t.Fatalf("AtLeast(critical) = %d", n)
	}
}
