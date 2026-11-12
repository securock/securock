package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func Save(path string, r finding.Report) error {
	raw, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".securock-state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(append(raw, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func Notify(ctx context.Context, endpoint string, r finding.Report) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("webhook must be an HTTPS URL without URL credentials")
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return fmt.Errorf("invalid webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("notification delivery failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint rejected delivery")
	}
	return nil
}

// Merge retains unobserved risks rather than inferring that missing scopes resolved them.
func Merge(old, current finding.Report) finding.Report {
	seen := map[string]bool{}
	out := append([]finding.Finding{}, current.Findings...)
	for _, f := range current.Findings {
		seen[baseline.Key(f)] = true
	}
	for _, f := range old.Findings {
		if !seen[baseline.Key(f)] && !baseline.Incomplete(f) {
			out = append(out, f)
		}
	}
	return finding.New(current.Tool, out)
}
