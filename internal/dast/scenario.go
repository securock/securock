package dast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/securock/securock/internal/finding"
)

type Scenario struct {
	Version int            `json:"version"`
	Steps   []ScenarioStep `json:"steps"`
}
type ScenarioStep struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	BodyEnv     string            `json:"body_env,omitempty"`
	BearerEnv   string            `json:"bearer_env,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Status      int               `json:"status"`
	Capture     map[string]string `json:"capture,omitempty"`
}

var variable = regexp.MustCompile(`\{\{([A-Za-z][A-Za-z0-9_]{0,31})\}\}`)
var variableName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

func ReadScenario(r io.Reader) (Scenario, error) {
	var s Scenario
	raw, e := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return s, fmt.Errorf("scenario exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return s, fmt.Errorf("invalid scenario")
	}
	return s, validateScenario(s)
}
func validateScenario(s Scenario) error {
	if s.Version != 1 || len(s.Steps) == 0 || len(s.Steps) > 100 {
		return fmt.Errorf("scenario requires version 1 and 1-100 steps")
	}
	ids := map[string]bool{}
	known := map[string]bool{}
	for _, step := range s.Steps {
		if !variableName.MatchString(step.ID) || ids[step.ID] || !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, step.Method) || step.Status < 200 || step.Status > 599 {
			return fmt.Errorf("invalid scenario step")
		}
		ids[step.ID] = true
		if step.ContentType != "" && step.ContentType != "application/json" && step.ContentType != "application/x-www-form-urlencoded" {
			return fmt.Errorf("unsupported scenario content type")
		}
		if (step.Method == "GET" || step.Method == "HEAD") && step.BodyEnv != "" {
			return fmt.Errorf("read-only scenario steps cannot have a body")
		}
		for _, match := range variable.FindAllStringSubmatch(step.Path, -1) {
			if !known[match[1]] {
				return fmt.Errorf("scenario variable must be captured by an earlier step")
			}
		}
		path := variable.ReplaceAllString(step.Path, "value")
		u, e := url.Parse(path)
		if e != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.IsAbs() || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Path, "\\{}") {
			return fmt.Errorf("scenario paths must be same-origin paths without queries")
		}
		for _, part := range strings.Split(u.Path, "/") {
			if part == ".." || part == "." {
				return fmt.Errorf("scenario path traversal is not allowed")
			}
		}
		if len(step.Capture) > 20 {
			return fmt.Errorf("scenario capture limit exceeded")
		}
		for name, pointer := range step.Capture {
			if !variableName.MatchString(name) || known[name] || !strings.HasPrefix(pointer, "/") {
				return fmt.Errorf("invalid or duplicate scenario capture")
			}
			known[name] = true
		}
	}
	return nil
}

// RunScenario performs only an explicit, bounded user contract. Credentials,
// cookies, captured values and response bodies stay in memory and out of reports.
func RunScenario(ctx context.Context, origin string, s Scenario, mutations bool, getenv func(string) string, client *http.Client) (finding.Report, error) {
	report := finding.New("dast", nil)
	if e := validateScenario(s); e != nil {
		return report, e
	}
	base, e := ValidateURL(origin)
	if e != nil {
		return report, e
	}
	ip := net.ParseIP(base.Hostname())
	if base.Scheme != "https" && (ip == nil || !ip.IsLoopback()) {
		return report, fmt.Errorf("stateful DAST requires HTTPS or a loopback test server")
	}
	// Preflight every step and credential before the first request.
	for _, step := range s.Steps {
		if step.Method != "GET" && step.Method != "HEAD" && !mutations {
			return report, fmt.Errorf("scenario writes require --allow-mutations")
		}
		if step.BearerEnv != "" {
			v := getenv(step.BearerEnv)
			if v == "" || strings.ContainsAny(v, "\r\n") {
				return report, fmt.Errorf("scenario credential missing or invalid")
			}
		}
		if step.BodyEnv != "" {
			v := getenv(step.BodyEnv)
			if v == "" || len(v) > 1<<20 {
				return report, fmt.Errorf("scenario body environment is missing or exceeds limit")
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	h := &http.Client{Timeout: 15 * time.Second}
	if client != nil {
		*h = *client
	}
	h.Jar, _ = cookiejar.New(nil)
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	values := map[string]string{}
	fail := func(step ScenarioStep, id, title string, err error) (finding.Report, error) {
		report.Findings = append(report.Findings, finding.Finding{ID: "dast:" + id, Severity: finding.SeverityHigh, Subject: base.Scheme + "://" + base.Host + "/scenario/" + step.ID, Title: title, Remediation: "Review the explicit scenario contract and rerun against the authorized test deployment."})
		return finding.New("dast", report.Findings), err
	}
	for _, step := range s.Steps {
		path := variable.ReplaceAllStringFunc(step.Path, func(match string) string {
			key := variable.FindStringSubmatch(match)[1]
			return url.PathEscape(values[key])
		})
		// A captured dot segment or encoded separator cannot alter the intended route.
		for _, match := range variable.FindAllStringSubmatch(step.Path, -1) {
			value := values[match[1]]
			if value == "." || value == ".." || strings.ContainsAny(value, "/\\") {
				return fail(step, "analysis-incomplete", "Captured path value is outside the supported scope", fmt.Errorf("scenario path expansion failed"))
			}
		}
		ref, e := url.Parse(strings.TrimRight(base.EscapedPath(), "/") + path)
		if e != nil {
			return fail(step, "analysis-incomplete", "Scenario path expansion failed", fmt.Errorf("scenario path expansion failed"))
		}
		target := *base
		target.Path, target.RawPath = ref.Path, ref.RawPath
		body := ""
		if step.BodyEnv != "" {
			body = getenv(step.BodyEnv)
		}
		req, e := http.NewRequestWithContext(ctx, step.Method, target.String(), strings.NewReader(body))
		if e != nil {
			return fail(step, "analysis-incomplete", "Scenario request could not be created", fmt.Errorf("scenario request failed"))
		}
		req.Header.Set("User-Agent", "securock-dast-scenario")
		if step.ContentType != "" {
			req.Header.Set("Content-Type", step.ContentType)
		}
		if step.BearerEnv != "" {
			req.Header.Set("Authorization", "Bearer "+getenv(step.BearerEnv))
		}
		res, e := h.Do(req)
		if e != nil {
			return fail(step, "analysis-incomplete", "Scenario request failed", fmt.Errorf("scenario request failed"))
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
		res.Body.Close()
		if e != nil || len(raw) > 1<<20 {
			return fail(step, "analysis-incomplete", "Scenario response exceeds supported limits", fmt.Errorf("scenario response incomplete"))
		}
		if res.StatusCode != step.Status {
			return fail(step, "scenario-contract-violated", "Scenario response status differs from its contract", nil)
		}

		for name, path := range step.Capture {
			v, ok := pointer(raw, path)
			text, scalar := v.(string)
			if !ok || !scalar || text == "" || len(text) > 256 {
				return fail(step, "analysis-incomplete", "Scenario capture requires a bounded nonempty JSON string", fmt.Errorf("scenario capture failed"))
			}
			values[name] = text
		}
	}
	return report, nil
}
