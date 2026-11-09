package audit_test

import (
	"testing"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func TestDependencyConfusion(t *testing.T) {
	const (
		npmPublic  = "https://registry.npmjs.org"
		npmPrivate = "https://npm.corp.example/repo"
	)
	tests := []struct {
		name     string
		eco      string
		pkg      string
		registry string
		internal []string
		want     finding.Severity // empty: no finding
	}{
		{"scope from public registry", "npm", "@acme/ui", npmPublic, []string{"npm:@acme/*"}, finding.SeverityHigh},
		{"scope from private registry", "npm", "@acme/ui", npmPrivate, []string{"npm:@acme/*"}, ""},
		{"exact name from public registry", "npm", "acme-core", npmPublic, []string{"npm:acme-core"}, finding.SeverityHigh},
		{"exact entry is not a prefix", "npm", "acme-core-extra", npmPublic, []string{"npm:acme-core"}, ""},
		{"other package", "npm", "left-pad", npmPublic, []string{"npm:@acme/*"}, ""},
		{"other ecosystem", "pypi", "@acme/ui", "https://pypi.org/simple", []string{"npm:@acme/*"}, ""},
		{"no registry recorded is not assumed private", "npm", "@acme/ui", "", []string{"npm:@acme/*"}, finding.SeverityMedium},
		{"pypi names compare like pypi", "pypi", "Acme_Core", "https://pypi.org/simple", []string{"pypi:acme-core"}, finding.SeverityHigh},
		{"not configured", "npm", "@acme/ui", npmPublic, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Subject = lockfile.Subject{Ecosystem: tt.eco, Name: tt.pkg}
				a.Source.Registry = tt.registry
			})
			report := audit.RunWith(doc, audit.Options{Now: time.Now(), InternalNames: tt.internal})
			var got finding.Severity
			for _, f := range report.Findings {
				if f.ID == "dependency-confusion" {
					if got != "" {
						t.Fatal("reported twice")
					}
					got = f.Severity
				}
			}
			if got != tt.want {
				t.Fatalf("severity = %q, want %q: %+v", got, tt.want, report.Findings)
			}
		})
	}
}
