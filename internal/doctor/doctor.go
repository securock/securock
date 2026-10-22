package doctor

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
)

type Options struct {
	Root       string
	LockPath   string
	PolicyPath string
	Profile    string
	// ExceptionsPath overrides the accepted-findings file.
	ExceptionsPath string
	// Now is the clock for expiry checks; the zero value uses time.Now.
	Now func() time.Time
}

// expiringSoon is how far ahead doctor warns about an exception that is about to lapse.
const expiringSoon = 14 * 24 * time.Hour

// Run checks the project setup around securock rather than the dependencies themselves.
func Run(opts Options) finding.Report {
	if opts.Root == "" {
		opts.Root = "."
	}
	var out []finding.Finding
	out = append(out, checkLock(opts)...)
	out = append(out, checkPolicy(opts)...)
	out = append(out, checkExceptions(opts)...)
	out = append(out, checkRegistryConfig(opts.Root)...)
	out = append(out, checkWorkflows(opts.Root)...)
	out = append(out, checkRulesets(opts.Root)...)
	return finding.New("doctor", out)
}

func checkLock(opts Options) []finding.Finding {
	path := lock.Path(opts.Root, opts.LockPath)
	_, migrated, err := lock.Read(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return []finding.Finding{{ID: "lock-missing", Severity: finding.SeverityMedium, Title: "securock.lock does not exist", Subject: path, Remediation: "Run securock lock and commit the file."}}
	case err != nil:
		return []finding.Finding{{ID: "lock-invalid", Severity: finding.SeverityHigh, Title: "securock.lock cannot be read", Detail: err.Error(), Subject: path, Remediation: "Regenerate it with securock lock."}}
	case migrated:
		return []finding.Finding{{ID: "lock-outdated", Severity: finding.SeverityLow, Title: "securock.lock uses an older schema", Subject: path, Remediation: "Run securock lock to write the current schema."}}
	}
	return nil
}

func checkPolicy(opts Options) []finding.Finding {
	if opts.PolicyPath != "" || opts.Profile != "" {
		if _, err := policy.LoadWithProfile(opts.PolicyPath, opts.Profile); err != nil {
			return []finding.Finding{{ID: "policy-invalid", Severity: finding.SeverityHigh, Title: "Policy cannot be loaded", Detail: err.Error(), Subject: opts.PolicyPath, Remediation: "Fix the policy file or the profile name."}}
		}
	}
	if opts.PolicyPath == "" && opts.Profile != "strict" {
		return []finding.Finding{{ID: "policy-default", Severity: finding.SeverityInfo, Title: "The default profile is in use", Detail: "strict additionally requires provenance, signature and digest", Remediation: "Pass --profile strict or --policy to tighten it."}}
	}
	return nil
}

func checkExceptions(opts Options) []finding.Finding {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	at := now().UTC()

	path := exceptions.Path(opts.Root, opts.ExceptionsPath)
	doc, err := exceptions.Load(path)
	if err != nil {
		return []finding.Finding{{ID: "exceptions-invalid", Severity: finding.SeverityHigh, Title: "Accepted findings cannot be read", Detail: err.Error(), Subject: path, Remediation: "Fix the file, or remove it and accept findings again with securock accept."}}
	}

	var out []finding.Finding
	for _, e := range doc.Exceptions {
		switch end, _ := e.ExpiresAt(); {
		case e.Expired(at):
			out = append(out, exceptions.ExpiredFinding(e))
		case end.Sub(at) <= expiringSoon:
			out = append(out, finding.Finding{
				ID: "exception-expiring", Severity: finding.SeverityLow, Title: "An accepted finding expires soon",
				Detail:      e.ID + " expires on " + e.Expires,
				Subject:     e.Subject,
				Remediation: "Fix the finding, or renew it with securock accept.",
			})
		}
		if e.Approver == "" {
			out = append(out, finding.Finding{
				ID: "exception-no-approver", Severity: finding.SeverityInfo, Title: "An accepted finding has no approver",
				Detail:      e.ID,
				Subject:     e.Subject,
				Remediation: "Renew it with securock accept --approver.",
			})
		}
	}
	return out
}

var (
	httpRegistry = regexp.MustCompile(`(?i)^\s*(?:@[^:=\s]+:)?registry\s*=\s*http://`)
	literalToken = regexp.MustCompile(`(?i)_auth(?:Token)?\s*=\s*[^$\s]`)
	strictSSLOff = regexp.MustCompile(`(?i)^\s*strict-ssl\s*=\s*false`)
	httpURL      = regexp.MustCompile(`(?i)(?:npmRegistryServer|unsafeHttpWhitelist|<add[^>]+value)[^\n]*http://`)
)

func checkRegistryConfig(root string) []finding.Finding {
	var out []finding.Finding
	for _, name := range []string{".npmrc", ".yarnrc.yml", "nuget.config", "NuGet.Config"} {
		path := filepath.Join(root, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			line := scan.Text()
			switch {
			case strictSSLOff.MatchString(line):
				out = append(out, finding.Finding{ID: "registry-tls-disabled", Severity: finding.SeverityHigh, Title: "TLS verification is disabled", Subject: path, Remediation: "Remove strict-ssl=false."})
			case literalToken.MatchString(line):
				out = append(out, finding.Finding{ID: "registry-literal-credential", Severity: finding.SeverityCritical, Title: "A registry credential is written into the file", Subject: path, Remediation: "Read the token from an environment variable such as ${NPM_TOKEN}."})
			case httpRegistry.MatchString(line), httpURL.MatchString(line):
				out = append(out, finding.Finding{ID: "registry-insecure-http", Severity: finding.SeverityHigh, Title: "A registry is reached over plain http", Subject: path, Remediation: "Use an https registry."})
			}
		}
		f.Close()
	}
	return out
}

var (
	usesLine = regexp.MustCompile(`^\s*-?\s*uses:\s*([^\s#]+)`)
	fullSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func checkWorkflows(root string) []finding.Finding {
	files, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.y*ml"))
	var out []finding.Finding
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			m := usesLine.FindStringSubmatch(scan.Text())
			if m == nil {
				continue
			}
			action := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(action, "./") || strings.HasPrefix(action, "docker://") {
				continue
			}
			_, ref, _ := strings.Cut(action, "@")
			if !fullSHA.MatchString(ref) {
				out = append(out, finding.Finding{ID: "action-not-pinned:" + action, Severity: finding.SeverityMedium, Title: "A workflow action is not pinned to a commit SHA", Detail: action, Subject: path, Remediation: "Pin the action to its full commit SHA."})
			}
		}
		f.Close()
	}
	return out
}

func checkRulesets(root string) []finding.Finding {
	files, _ := filepath.Glob(filepath.Join(root, ".github", "rulesets", "*.json"))
	if len(files) > 0 {
		return nil
	}
	return []finding.Finding{{ID: "rulesets-missing", Severity: finding.SeverityLow, Title: "No repository rulesets are defined", Subject: filepath.Join(root, ".github", "rulesets"), Remediation: "Protect the default branch and tags with rulesets."}}
}
