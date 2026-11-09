package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/securock/securock/internal/exploit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/network"
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
	// InternalNames are the package names your organization publishes privately, in the
	// policy's "<ecosystem>:<name>" form. One that resolves from a public registry is
	// reported as a dependency-confusion risk.
	InternalNames []string
	// Signals holds exploitation data by advisory ID, from `audit --prioritize`. It can
	// only raise a vulnerability's severity: an advisory CISA lists as exploited is
	// critical, and one with an EPSS score of 50% or more is at least high.
	Signals map[string]exploit.Signal
	// SignalsUnavailable, when set, says why --prioritize could not look the signals up.
	// It is reported as an info finding so a missing lookup is not read as "not exploited".
	SignalsUnavailable string
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
	if opts.SignalsUnavailable != "" {
		out = append(out, finding.Finding{
			ID:          "exploit-signals-unavailable",
			Severity:    finding.SeverityInfo,
			Title:       "Exploitation data was not checked",
			Detail:      opts.SignalsUnavailable,
			Remediation: "Run without --offline, or retry when CISA KEV and EPSS are reachable.",
		})
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
			sev, title, detail := vulnerability(v, opts.Signals[v.ID])
			add("known-vulnerability:"+v.ID, sev, title, detail, upgradeAdvice(v))
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
	dependencyConfusion(art, opts, add)

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
		add("typosquat-suspect", finding.SeverityLow, "Name resembles a popular package", "similar to "+target, "Check that this is the package you meant to install.")
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

// vulnerability ranks a known vulnerability. The advisory's own severity sets the level, and
// high is assumed when it gave none, which is how every advisory was ranked before severity
// was recorded. Exploitation data can raise the level and reachability can lower it: a
// vulnerability the lockfile shows to be development-only is low whatever the signals say,
// though they are still shown. Unknown reachability changes nothing.
func vulnerability(v lockfile.Vulnerability, sig exploit.Signal) (finding.Severity, string, string) {
	sev := advisorySeverity(v.Severity)
	title := "Known vulnerability"
	detail := v.ID
	if v.Severity != "" {
		detail += " (" + string(v.Severity) + " severity)"
	}
	if note := signalNote(sig); note != "" {
		detail += ", " + note
	}
	switch v.Reachable {
	case lockfile.ReachNo:
		return finding.SeverityLow, "Known vulnerability in a development-only dependency", detail + ", not part of the runtime dependencies"
	case lockfile.ReachYes:
		sev = raised(sev, sig)
		if len(v.Via) > 1 {
			return sev, title, detail + ", reached via " + strings.Join(v.Via, " -> ")
		}
		return sev, title, detail + ", runtime dependency"
	}
	return raised(sev, sig), title, detail
}

// epssHigh is the EPSS score, a probability from 0 to 1, from which a vulnerability is
// treated as likely to be exploited.
const epssHigh = 0.5

// raised lifts sev to what the exploitation data warrants, and never lowers it.
func raised(sev finding.Severity, sig exploit.Signal) finding.Severity {
	floor := finding.SeverityInfo
	switch {
	case sig.KEV:
		floor = finding.SeverityCritical
	case sig.HasEPSS && sig.EPSS >= epssHigh:
		floor = finding.SeverityHigh
	}
	if floor.Rank() > sev.Rank() {
		return floor
	}
	return sev
}

func signalNote(sig exploit.Signal) string {
	var parts []string
	if sig.KEV {
		parts = append(parts, "actively exploited (CISA KEV)")
	}
	if sig.HasEPSS {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%%", sig.EPSS*100))
	}
	return strings.Join(parts, ", ")
}

func advisorySeverity(s lockfile.VulnSeverity) finding.Severity {
	switch s {
	case lockfile.SeverityCritical:
		return finding.SeverityCritical
	case lockfile.SeverityMedium:
		return finding.SeverityMedium
	case lockfile.SeverityLow:
		return finding.SeverityLow
	default:
		return finding.SeverityHigh
	}
}

// upgradeAdvice names the version that fixes the advisory when OSV says which.
func upgradeAdvice(v lockfile.Vulnerability) string {
	switch len(v.Fixed) {
	case 0:
		return "Upgrade to a fixed version."
	case 1:
		return "Upgrade to " + v.Fixed[0] + " or later."
	default:
		return "Upgrade to " + v.Fixed[0] + " or later (also fixed in " + strings.Join(v.Fixed[1:], ", ") + ")."
	}
}

// recentRelease flags releases younger than the cooldown, which is how a freshly
// published malicious version is kept out until the registry has had time to react.
// The release day is all the registry gives, so a release is dated from the start of that
// day. A release whose date could not be found cannot be judged, and is reported as such.
func recentRelease(art lockfile.Artifact, opts Options, add func(id string, sev finding.Severity, title, detail, fix string)) {
	if opts.MinReleaseAge <= 0 {
		return
	}
	var released time.Time
	var err error
	if art.Evidence.Health != nil {
		released, err = time.Parse("2006-01-02", art.Evidence.Health.Released)
	}
	if art.Evidence.Health == nil || err != nil {
		// Silence would read as "old enough". Only npm and PyPI have release dates to find.
		if eco := art.Subject.Ecosystem; eco == "npm" || eco == "pypi" {
			add("release-date-unknown", finding.SeverityInfo, "Release date is unknown, so the minimum age was not checked", "",
				"Run without --offline, or check the release date yourself.")
		}
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

// dependencyConfusion reports a package the policy names as internal that resolves from a
// public registry: an attacker who publishes that name there can win the install. When the
// lockfile records no registry the source cannot be shown to be private, so it is reported
// too, at a lower severity, rather than assumed safe.
func dependencyConfusion(art lockfile.Artifact, opts Options, add func(id string, sev finding.Severity, title, detail, fix string)) {
	if !internalName(opts.InternalNames, art.Subject.Ecosystem, art.Subject.Name) {
		return
	}
	const fix = "Pin the package to your private registry and claim the name on the public one."
	switch registry := art.Source.Registry; {
	case registry == "":
		add("dependency-confusion", finding.SeverityMedium, "Internal package has no recorded registry", "the lockfile does not show where "+art.Subject.Name+" was resolved from", fix)
	case network.Public(art.Subject.Ecosystem, registry):
		add("dependency-confusion", finding.SeverityHigh, "Internal package resolves from a public registry", art.Subject.Name+" from "+registry, fix)
	}
}

// internalName reports whether a policy entry covers the package. Python names are compared
// the way PyPI does, ignoring case and the difference between -, _ and .
func internalName(entries []string, ecosystem, name string) bool {
	norm := func(eco, s string) string {
		if eco == "pypi" {
			s = strings.NewReplacer("_", "-", ".", "-").Replace(s)
		}
		return strings.ToLower(s)
	}
	name = norm(ecosystem, name)
	for _, entry := range entries {
		eco, pattern, _ := strings.Cut(entry, ":")
		if eco != ecosystem {
			continue
		}
		pattern = norm(eco, pattern)
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == pattern {
			return true
		}
	}
	return false
}
