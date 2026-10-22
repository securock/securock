package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/typosquat"
	"github.com/securock/securock/pkg/lockfile"
)

// staleAfter is how long after its release a version is reported as stale.
const staleAfter = 2 * 365 * 24 * time.Hour

// Run turns the evidence recorded for each artifact into severity-ranked findings.
// Unchecked evidence is reported as info: absence of a check is not a defect.
func Run(doc lockfile.Document) finding.Report {
	return RunAt(doc, time.Now())
}

// RunAt is Run with an explicit clock, for the age-based findings.
func RunAt(doc lockfile.Document, now time.Time) finding.Report {
	return RunWith(doc, Options{Now: now})
}

// Options tunes the findings that depend on time.
type Options struct {
	// Now is the clock; the zero value uses time.Now.
	Now time.Time
	// MinReleaseAge reports any release published more recently than this as a high
	// finding. Zero turns the check off.
	MinReleaseAge time.Duration
}

// RunWith is Run with options.
func RunWith(doc lockfile.Document, opts Options) finding.Report {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	var out []finding.Finding
	for _, art := range doc.Artifacts {
		out = append(out, artifact(art, opts)...)
	}
	return finding.New("audit", out)
}

func artifact(art lockfile.Artifact, opts Options) []finding.Finding {
	now := opts.Now
	subject := art.ArtifactID()
	ev := art.Evidence
	var out []finding.Finding
	add := func(id string, sev finding.Severity, title, detail, fix string) {
		out = append(out, finding.Finding{ID: id, Severity: sev, Title: title, Detail: detail, Subject: subject, Remediation: fix})
	}

	switch ev.Malicious.State {
	case lockfile.VulnChecked:
		for _, r := range ev.Malicious.Reports {
			add("malicious-package:"+r.ID, finding.SeverityCritical, "Package is reported as malicious", r.ID, "Remove the dependency and rotate any secrets it could read.")
		}
	default:
		add("malicious-unchecked", finding.SeverityInfo, "Malicious package reports were not checked", "", "Run without --offline to query OSV.")
	}

	switch ev.Vulnerabilities.State {
	case lockfile.VulnChecked:
		for _, v := range ev.Vulnerabilities.Items {
			sev, title, detail := vulnerability(v)
			add("known-vulnerability:"+v.ID, sev, title, detail, "Upgrade to a fixed version.")
		}
	default:
		add("vulnerability-unchecked", finding.SeverityInfo, "Vulnerabilities were not checked", "", "Run without --offline to query OSV.")
	}

	if art.Digest == "" {
		add("missing-digest", finding.SeverityMedium, "Artifact has no digest", "", "Pin the artifact digest in the lockfile.")
	}
	if ev.Provenance == lockfile.EvidenceMissing {
		add("missing-provenance", finding.SeverityLow, "No provenance attestation", "", "Prefer releases published with provenance.")
	}
	if ev.Signature == lockfile.EvidenceMissing {
		add("missing-signature", finding.SeverityLow, "No signature", "", "Prefer signed releases.")
	}

	health(art, now, add)
	recentRelease(art, opts, add)

	if ev.Capabilities.State == lockfile.CapChecked {
		caps := ev.Capabilities
		if enabled(caps.InstallScripts) {
			add("capability:install-scripts", finding.SeverityMedium, "Runs install scripts", "", "Review the scripts or disable them at install time.")
		}
		if enabled(caps.Shell) {
			add("capability:shell", finding.SeverityMedium, "Executes shell commands", "", "")
		}
		if enabled(caps.Network) {
			add("capability:network", finding.SeverityLow, "Uses the network", "", "")
		}
		if enabled(caps.NativeCode) {
			add("capability:native-code", finding.SeverityLow, "Contains native code", "", "")
		}
		if caps.Filesystem == lockfile.FilesystemWrite {
			add("capability:filesystem-write", finding.SeverityLow, "Writes to the filesystem", fmt.Sprint(caps.Filesystem), "")
		}
	}
	return out
}

// health reports what the registry says about the release, plus a name check that
// needs no registry. Findings here are signals to look at, not proof of a problem.
func health(art lockfile.Artifact, now time.Time, add func(id string, sev finding.Severity, title, detail, fix string)) {
	if target, ok := typosquat.Check(art.Subject.Ecosystem, art.Subject.Name); ok {
		add("typosquat-suspect", finding.SeverityMedium, "Name resembles a popular package", "similar to "+target, "Check that this is the package you meant to install.")
	}
	h := art.Evidence.Health
	if h == nil {
		return
	}
	if h.Deprecated != "" {
		add("deprecated-package", finding.SeverityMedium, "Release is deprecated", h.Deprecated, "Move to a maintained version or an alternative.")
	}
	if released, err := time.Parse("2006-01-02", h.Released); err == nil && now.Sub(released) > staleAfter {
		add("stale-release", finding.SeverityLow, "Release is more than two years old", "published "+h.Released, "Check that the project is still maintained.")
	}
}

// vulnerability ranks a known vulnerability. Reachability, when it was recorded, can only
// lower the severity of one the lockfile shows to be development-only; unknown stays high.
func vulnerability(v lockfile.Vulnerability) (finding.Severity, string, string) {
	switch v.Reachable {
	case lockfile.ReachNo:
		return finding.SeverityLow, "Known vulnerability in a development-only dependency", v.ID + " (not part of the runtime dependencies)"
	case lockfile.ReachYes:
		if len(v.Via) > 1 {
			return finding.SeverityHigh, "Known vulnerability", v.ID + " (reached via " + strings.Join(v.Via, " -> ") + ")"
		}
		return finding.SeverityHigh, "Known vulnerability", v.ID + " (runtime dependency)"
	default:
		return finding.SeverityHigh, "Known vulnerability", v.ID
	}
}

// recentRelease flags releases younger than the cooldown, which is how a freshly
// published malicious version is kept out until the registry has had time to react.
// The release day is all the registry gives, so a release is dated from the start of that
// day; an unknown date is never flagged.
func recentRelease(art lockfile.Artifact, opts Options, add func(id string, sev finding.Severity, title, detail, fix string)) {
	if opts.MinReleaseAge <= 0 || art.Evidence.Health == nil {
		return
	}
	released, err := time.Parse("2006-01-02", art.Evidence.Health.Released)
	if err != nil {
		return
	}
	age := opts.Now.UTC().Sub(released)
	if age >= opts.MinReleaseAge {
		return
	}
	days := max(int(age/(24*time.Hour)), 0)
	add("recent-release", finding.SeverityHigh, "Release is newer than the minimum age",
		fmt.Sprintf("published %s (%s ago); minimum is %s", art.Evidence.Health.Released, plural(days, "day"), formatAge(opts.MinReleaseAge)),
		"Wait until the release is older, or pin the previous version.")
}

func formatAge(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return plural(int(d/(24*time.Hour)), "day")
	}
	return d.String()
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func enabled(b *bool) bool {
	return b != nil && *b
}
