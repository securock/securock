package exceptions_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	pkg "github.com/securock/securock/pkg/exceptions"
)

var now = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func ex(id, subject, expires string) pkg.Exception {
	return pkg.Exception{ID: id, Subject: subject, Reason: "tracked in ENG-1", Approver: "alice", Expires: expires}
}

func report(findings ...finding.Finding) finding.Report {
	return finding.New("audit", findings)
}

func vuln(subject string) finding.Finding {
	return finding.Finding{ID: "known-vulnerability:GHSA-1", Severity: finding.SeverityHigh, Title: "Known vulnerability", Subject: subject}
}

func TestPath(t *testing.T) {
	root := filepath.Join("a", "b")
	if got, want := exceptions.Path(root, ""), filepath.Join(root, ".securock", "exceptions.yaml"); got != want {
		t.Fatalf("default: got %s, want %s", got, want)
	}
	if got, want := exceptions.Path(root, "x.yaml"), filepath.Join(root, "x.yaml"); got != want {
		t.Fatalf("relative: got %s, want %s", got, want)
	}
	abs := filepath.Join(t.TempDir(), "x.yaml")
	if got := exceptions.Path(root, abs); got != abs {
		t.Fatalf("absolute: got %s", got)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	doc, err := exceptions.Load(filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != pkg.SchemaVersion || len(doc.Exceptions) != 0 {
		t.Fatalf("doc: %+v", doc)
	}
}

func TestSaveLoadRoundTripIsCanonical(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".securock", "exceptions.yaml")
	doc := pkg.Document{Version: 1, Exceptions: []pkg.Exception{ex("b", "", "2026-12-31"), ex("a", "npm:x", "2026-12-31")}}
	if err := exceptions.Save(path, doc); err != nil {
		t.Fatal(err)
	}
	got, err := exceptions.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Exceptions) != 2 || got.Exceptions[0].ID != "a" || got.Exceptions[1].ID != "b" {
		t.Fatalf("saved order: %+v", got.Exceptions)
	}
	first, _ := os.ReadFile(path)
	if err := exceptions.Save(path, got); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatalf("save is not stable:\n%s\n---\n%s", first, second)
	}
	if !strings.HasPrefix(string(first), "# ") {
		t.Fatalf("expected a header comment:\n%s", first)
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	tests := map[string]string{
		"unknown field": "version: 1\nexceptions:\n  - id: a\n    reason: r\n    expires: 2026-12-31\n    owner: me\n",
		"no expiry":     "version: 1\nexceptions:\n  - id: a\n    reason: r\n",
		"wrong version": "version: 9\nexceptions: []\n",
		"not yaml":      "version: [\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "e.yaml")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := exceptions.Load(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSaveRefusesInvalidDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.yaml")
	bad := pkg.Document{Version: 1, Exceptions: []pkg.Exception{{ID: "a", Expires: "2026-12-31"}}}
	if err := exceptions.Save(path, bad); err == nil {
		t.Fatal("a reason is required")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing should be written for an invalid document")
	}
}

func TestUpsertRenewsAndRemove(t *testing.T) {
	doc := pkg.Document{Version: 1}
	doc, renewed := exceptions.Upsert(doc, ex("a", "", "2026-07-01"))
	if renewed || len(doc.Exceptions) != 1 {
		t.Fatalf("first add: renewed=%v doc=%+v", renewed, doc)
	}
	doc, renewed = exceptions.Upsert(doc, ex("a", "npm:x", "2026-07-01"))
	if renewed || len(doc.Exceptions) != 2 {
		t.Fatalf("a different subject is a different exception: %+v", doc)
	}
	doc, renewed = exceptions.Upsert(doc, ex("a", "", "2027-01-01"))
	if !renewed || len(doc.Exceptions) != 2 {
		t.Fatalf("renew: renewed=%v doc=%+v", renewed, doc)
	}
	for _, e := range doc.Exceptions {
		if e.Subject == "" && e.Expires != "2027-01-01" {
			t.Fatalf("expiry not renewed: %+v", e)
		}
	}

	doc, removed := exceptions.Remove(doc, "a", "npm:x")
	if !removed || len(doc.Exceptions) != 1 {
		t.Fatalf("remove: %v %+v", removed, doc)
	}
	if _, removed := exceptions.Remove(doc, "nope", ""); removed {
		t.Fatal("removing a missing exception must report false")
	}
}

func TestApplySuppressesActiveExceptions(t *testing.T) {
	r := report(vuln("npm:lodash@4.17.20"), vuln("npm:other@1.0.0"))
	doc := pkg.Document{Version: 1, Exceptions: []pkg.Exception{ex("known-vulnerability:GHSA-1", "npm:lodash", "2026-06-15")}}

	got := exceptions.Apply(r, doc, now)
	if len(got.Findings) != 2 {
		t.Fatalf("suppressed findings must stay in the report: %+v", got.Findings)
	}
	var suppressed, active int
	for _, f := range got.Findings {
		if f.Suppressed != nil {
			suppressed++
			if f.Subject != "npm:lodash@4.17.20" || f.Suppressed.Reason == "" || f.Suppressed.Approver != "alice" || f.Suppressed.Expires != "2026-06-15" {
				t.Fatalf("suppression: %+v", f)
			}
		} else {
			active++
		}
	}
	if suppressed != 1 || active != 1 {
		t.Fatalf("suppressed %d, active %d", suppressed, active)
	}
	if got.AtLeast(finding.SeverityHigh) != 1 {
		t.Fatalf("only the unaccepted finding should count: %d", got.AtLeast(finding.SeverityHigh))
	}
	if r.Findings[0].Suppressed != nil || r.Findings[1].Suppressed != nil {
		t.Fatal("Apply must not modify its input")
	}
}

func TestApplyExpiredExceptionReturnsTheFinding(t *testing.T) {
	r := report(vuln("npm:lodash@4.17.20"))
	doc := pkg.Document{Version: 1, Exceptions: []pkg.Exception{ex("known-vulnerability:GHSA-1", "", "2026-06-14")}}

	got := exceptions.Apply(r, doc, now)
	if got.AtLeast(finding.SeverityHigh) != 1 {
		t.Fatalf("an expired exception must not suppress: %+v", got.Findings)
	}
	var expired []finding.Finding
	for _, f := range got.Findings {
		if f.ID == "exception-expired" {
			expired = append(expired, f)
		}
	}
	if len(expired) != 1 || expired[0].Severity != finding.SeverityMedium || !strings.Contains(expired[0].Detail, "2026-06-14") {
		t.Fatalf("expired findings: %+v", expired)
	}
}

func TestApplyStaysQuietAboutExpiredExceptionsThatMatchNothing(t *testing.T) {
	r := report(vuln("npm:lodash@4.17.20"))
	doc := pkg.Document{Version: 1, Exceptions: []pkg.Exception{ex("known-vulnerability:GHSA-9", "", "2020-01-01")}}
	if got := exceptions.Apply(r, doc, now); len(got.Findings) != 1 {
		t.Fatalf("unexpected findings: %+v", got.Findings)
	}
}

func TestApplyPrefersAnActiveExceptionOverAnExpiredOne(t *testing.T) {
	r := report(vuln("npm:lodash@4.17.20"))
	doc := pkg.Document{Version: 1, Exceptions: []pkg.Exception{
		ex("known-vulnerability:GHSA-1", "npm:lodash@4.17.20", "2020-01-01"),
		ex("known-vulnerability:GHSA-1", "", "2027-01-01"),
	}}
	got := exceptions.Apply(r, doc, now)
	if len(got.Findings) != 1 || got.Findings[0].Suppressed == nil {
		t.Fatalf("the active exception should suppress and no expiry warning is needed: %+v", got.Findings)
	}
}

func TestApplyWithoutExceptionsReturnsReportUnchanged(t *testing.T) {
	r := report(vuln("npm:a@1"))
	got := exceptions.Apply(r, pkg.Document{Version: 1}, now)
	if len(got.Findings) != 1 || got.Findings[0].Suppressed != nil {
		t.Fatalf("got %+v", got.Findings)
	}
}
