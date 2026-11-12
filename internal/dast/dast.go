// Package dast inspects live HTTP responses without injecting payloads or crawling.
package dast

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/securock/securock/internal/finding"
)

const DefaultTimeout = 15 * time.Second
const maxRedirects = 5

type Options struct {
	URL     string
	Timeout time.Duration
	// Client permits local TLS fixtures; production callers use the default transport.
	Client      *http.Client
	BearerToken string
}

// ValidateURL rejects credentials and queries so reports and errors cannot expose them.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return nil, fmt.Errorf("DAST target must be an absolute http or https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("DAST targets must not contain credentials, query parameters, or fragments")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("DAST target has an invalid port")
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// Scan performs at most six GETs, following redirects only within the exact origin.
// It never caches responses, replays cookies, or disables certificate verification.
// Findings describe observed configuration; they do not establish exploitability.
func Scan(ctx context.Context, opts Options) (finding.Report, error) {
	u, err := ValidateURL(opts.URL)
	if err != nil {
		return finding.New("dast", nil), err
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 {
		return finding.New("dast", nil), fmt.Errorf("DAST timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{}
	if opts.Client != nil {
		*client = *opts.Client
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	origin := u
	var found []finding.Finding
	incomplete := func(reason string) (finding.Report, error) {
		found = append(found, finding.Finding{ID: "dast:analysis-incomplete", Severity: finding.SeverityHigh,
			Subject: u.String(), Title: "Live application analysis did not complete", Detail: reason,
			Remediation: "Check target availability, TLS trust, and redirect scope, then rerun DAST."})
		return finding.New("dast", deduplicate(found)), fmt.Errorf("DAST analysis incomplete: %s", reason)
	}
	for redirects := 0; ; redirects++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return incomplete("Could not construct the target request.")
		}
		req.Header.Set("User-Agent", "securock-dast")
		if opts.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+opts.BearerToken)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5")
		resp, err := client.Do(req)
		if err != nil {
			return incomplete("HTTP request failed or timed out; certificate verification remains enabled.")
		}
		// Only headers are inspected. Do not retain response bodies or cookie values.
		resp.Body.Close()
		found = append(found, inspect(u, resp)...)
		if resp.StatusCode >= 500 {
			return incomplete("The target returned a server error.")
		}
		switch resp.StatusCode {
		case 301, 302, 303, 307, 308:
			if redirects >= maxRedirects {
				return incomplete("The redirect limit was reached.")
			}
			next, err := resp.Location()
			if err != nil {
				return incomplete("The redirect location is missing or invalid.")
			}
			next, err = ValidateURL(next.String())
			if err != nil {
				return incomplete("The redirect target contains unsupported URL components.")
			}
			if !sameOrigin(origin, next) {
				return incomplete("A redirect leaves the target origin; scan its destination explicitly.")
			}
			u = next
		default:
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return incomplete("The target did not return a successful application response.")
			}
			return finding.New("dast", deduplicate(found)), nil
		}
	}
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func inspect(u *url.URL, r *http.Response) []finding.Finding {
	var out []finding.Finding
	add := func(id string, sev finding.Severity, title, detail, fix string) {
		out = append(out, finding.Finding{ID: "dast:" + id, Severity: sev, Title: title, Detail: detail, Remediation: fix, Subject: u.String()})
	}
	if u.Scheme == "http" {
		add("unencrypted-http", finding.SeverityHigh, "Response was served over unencrypted HTTP", "Transport confidentiality and integrity are not provided.", "Serve the application over HTTPS.")
	} else if !validHSTS(r.Header.Get("Strict-Transport-Security")) {
		add("hsts-missing", finding.SeverityMedium, "HSTS is absent or has no positive max-age", "", "Set Strict-Transport-Security with a positive max-age after validating HTTPS coverage.")
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.StatusCode >= 200 && r.StatusCode < 300 && (contentType == "text/html" || contentType == "application/xhtml+xml") {
		csp := r.Header.Values("Content-Security-Policy")
		if len(csp) == 0 || strings.TrimSpace(strings.Join(csp, "")) == "" {
			add("csp-missing", finding.SeverityMedium, "HTML response has no enforced Content Security Policy", "This is a missing defense, not proof of XSS.", "Deploy an application-specific Content-Security-Policy; report-only policies do not enforce restrictions.")
		}
		frame := strings.ToUpper(strings.TrimSpace(r.Header.Get("X-Frame-Options")))
		if frame != "DENY" && frame != "SAMEORIGIN" && !hasFrameAncestors(csp) {
			add("frame-protection-missing", finding.SeverityMedium, "HTML response lacks framing protection", "", "Set CSP frame-ancestors to the intended embedding origins, or X-Frame-Options to DENY or SAMEORIGIN.")
		}
		if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Content-Type-Options")), "nosniff") {
			add("nosniff-missing", finding.SeverityLow, "HTML response lacks nosniff protection", "", "Set X-Content-Type-Options: nosniff.")
		}
		if strings.TrimSpace(r.Header.Get("Referrer-Policy")) == "" {
			add("referrer-policy-missing", finding.SeverityLow, "HTML response has no explicit Referrer-Policy", "Browser defaults vary; this is a hardening recommendation.", "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.")
		}
	}
	for _, c := range r.Cookies() {
		// Names distinguish findings without copying credential values into reports.
		detail := "Cookie: " + c.Name + ". Review attributes against the cookie's intended use."
		if !c.Secure {
			add("cookie-secure-missing", finding.SeverityMedium, "Cookie lacks the Secure attribute", detail, "Use Secure cookies with HTTPS.")
		}
		if !c.HttpOnly {
			add("cookie-httponly-missing", finding.SeverityMedium, "Cookie is accessible to scripts", detail, "Use HttpOnly for session or other cookies that do not need JavaScript access.")
		}
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			add("cookie-samesite-missing", finding.SeverityLow, "Cookie has no valid explicit SameSite attribute", detail, "Choose SameSite=Lax or Strict unless cross-site use is required.")
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			add("cookie-samesite-none-insecure", finding.SeverityHigh, "SameSite=None cookie lacks Secure", detail, "Set Secure when using SameSite=None.")
		}
	}
	return out
}

func validHSTS(value string) bool {
	for _, part := range strings.Split(value, ";") {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, "max-age") {
			age, err := strconv.ParseUint(val, 10, 64)
			return err == nil && age > 0
		}
	}
	return false
}

func hasFrameAncestors(policies []string) bool {
	for _, policy := range policies {
		for _, directive := range strings.Split(policy, ";") {
			fields := strings.Fields(directive)
			if len(fields) > 1 && strings.EqualFold(fields[0], "frame-ancestors") {
				// A wildcard permits every embedding origin.
				if !slices.Contains(fields[1:], "*") {
					return true
				}
			}
		}
	}
	return false
}

func deduplicate(found []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(found))
	for _, f := range found {
		key := f.ID + "\x00" + f.Subject + "\x00" + f.Detail
		if !seen[key] {
			out = append(out, f)
			seen[key] = true
		}
	}
	return out
}
