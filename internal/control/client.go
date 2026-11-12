package control

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

type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func (c Client) Call(ctx context.Context, method, path string, input, output any) error {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" && u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return fmt.Errorf("invalid control plane origin")
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	if c.Token == "" || strings.ContainsAny(c.Token, "\r\n") {
		return fmt.Errorf("invalid API token")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	h := &http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		*h = *c.HTTP
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := h.Do(req)
	if e != nil {
		return fmt.Errorf("control plane request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned status %d", resp.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if e != nil {
		return e
	}
	var envelope struct {
		Version int             `json:"version"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != 1 {
		return fmt.Errorf("invalid API response")
	}
	if output != nil {
		return json.Unmarshal(envelope.Data, output)
	}
	return nil
}
