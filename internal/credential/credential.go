// Package credential performs explicit provider credential lifecycle operations.
package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Options struct {
	Provider     string
	Action       string
	Origin       string
	Token        string
	ClientID     string
	ClientSecret string
	Replacement  io.Writer
	Client       *http.Client
}
type Report struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Action   string `json:"action"`
	State    string `json:"state"`
}

func Execute(ctx context.Context, o Options) (Report, error) {
	out := Report{1, o.Provider, o.Action, "unknown"}
	u, e := url.Parse(o.Origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || o.Token == "" || strings.ContainsAny(o.Token, "\r\n") {
		return out, fmt.Errorf("HTTPS provider origin and valid credential required")
	}
	if o.Action != "check" && o.Action != "revoke" && o.Action != "rotate" {
		return out, fmt.Errorf("unknown credential action")
	}
	if o.Action == "rotate" && o.Replacement == nil {
		return out, fmt.Errorf("exclusive replacement file required before rotation")
	}
	method, path := "GET", ""
	var payload any
	switch o.Provider {
	case "gitlab":
		path = "/api/v4/personal_access_tokens/self"
		if o.Action == "revoke" {
			method = "DELETE"
		}
		if o.Action == "rotate" {
			method = "POST"
			path += "/rotate"
		}
	case "github":
		path = "/user"
		if o.Action != "check" {
			if o.ClientID == "" || o.ClientSecret == "" {
				return out, fmt.Errorf("GitHub token mutation requires the owning OAuth app credentials")
			}
			path = "/applications/" + url.PathEscape(o.ClientID) + "/token"
			method = "DELETE"
			if o.Action == "rotate" {
				method = "PATCH"
			}
			payload = map[string]string{"access_token": o.Token}
		}
	default:
		return out, fmt.Errorf("provider must be github or gitlab")
	}
	raw, _ := json.Marshal(payload)
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.Origin, "/")+path, bytes.NewReader(raw))
	if e != nil {
		return out, fmt.Errorf("invalid provider request")
	}
	req.Header.Set("Authorization", "Bearer "+o.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if o.Provider == "github" && o.Action != "check" {
		req.SetBasicAuth(o.ClientID, o.ClientSecret)
	}
	h := &http.Client{Timeout: 20 * time.Second}
	if o.Client != nil {
		*h = *o.Client
	}
	h.Jar = nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := h.Do(req)
	if e != nil {
		return out, fmt.Errorf("credential operation outcome unknown; reconcile with the provider")
	}
	defer resp.Body.Close()
	if o.Action == "check" {
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			out.State = "active"
			return out, nil
		case resp.StatusCode == 401:
			out.State = "inactive"
			return out, nil
		default:
			return out, fmt.Errorf("provider could not establish credential validity")
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("credential operation not confirmed by provider")
	}
	if o.Action == "revoke" {
		out.State = "revoked"
		return out, nil
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(body) > 65536 {
		return out, fmt.Errorf("rotation response unavailable; reconcile with provider")
	}
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(body, &token) != nil {
		return out, fmt.Errorf("invalid rotation response")
	}
	if token.Token == "" {
		return out, fmt.Errorf("replacement unavailable; reconcile with provider")
	}
	if _, e = io.WriteString(o.Replacement, token.Token+"\n"); e != nil {
		return out, fmt.Errorf("replacement write failed after rotation; reconcile with provider")
	}
	out.State = "rotated"
	return out, nil
}
