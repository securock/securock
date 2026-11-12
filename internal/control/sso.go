package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type SSOConfig struct {
	AuthorizeURL string   `json:"authorize_url"`
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	SecretEnv    string   `json:"secret_env,omitempty"`
	PublicURL    string   `json:"public_url"`
	Scopes       []string `json:"scopes"`
}
type login struct {
	Verifier string
	Nonce    string
	Expires  time.Time
}
type session struct {
	Token   string
	Expires time.Time
}
type BrowserSSO struct {
	Config   SSOConfig
	Client   *http.Client
	mu       sync.Mutex
	pending  map[string]login
	sessions map[string]session
}

func NewBrowserSSO(c SSOConfig) (*BrowserSSO, error) {
	for _, raw := range []string{c.AuthorizeURL, c.TokenURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("SSO endpoints require pinned HTTPS URLs")
		}
	}
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid SSO public origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("SSO public origin requires HTTPS")
	}
	if c.ClientID == "" || len(c.Scopes) == 0 {
		return nil, fmt.Errorf("SSO client and scopes required")
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	return &BrowserSSO{Config: c, pending: map[string]login{}, sessions: map[string]session{}}, nil
}
func (b *BrowserSSO) cookie(name, value string, age int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(b.Config.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: age}
}
func (b *BrowserSSO) token(r *http.Request) (string, error) {
	if r.Method != "GET" && (r.Header.Get("X-Securock-Request") != "1" || r.Header.Get("Origin") != b.Config.PublicURL) {
		return "", fmt.Errorf("CSRF check failed")
	}
	c, e := r.Cookie("securock_session")
	if e != nil {
		return "", e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.sessions[c.Value]
	if !ok || !v.Expires.After(time.Now()) {
		delete(b.sessions, c.Value)
		return "", fmt.Errorf("session expired")
	}
	return v.Token, nil
}
func (s *Server) browserAuth(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/auth/") {
		return false
	}
	b := s.SSO
	if b == nil {
		reply(w, 404, nil)
		return true
	}
	switch r.URL.Path {
	case "/auth/login":
		if r.Method != "GET" {
			reply(w, 405, nil)
			return true
		}
		state := ID()
		verifier := ID() + ID()
		nonce := ID()
		b.mu.Lock()
		for id, v := range b.pending {
			if !v.Expires.After(time.Now()) {
				delete(b.pending, id)
			}
		}
		for id, v := range b.sessions {
			if !v.Expires.After(time.Now()) {
				delete(b.sessions, id)
			}
		}
		if len(b.pending) >= 1000 || len(b.sessions) >= 1000 {
			b.mu.Unlock()
			reply(w, 429, nil)
			return true
		}
		b.pending[state] = login{verifier, nonce, time.Now().Add(5 * time.Minute)}
		b.mu.Unlock()
		http.SetCookie(w, b.cookie("securock_login", state, 300))
		u, _ := url.Parse(b.Config.AuthorizeURL)
		q := u.Query()
		q.Set("client_id", b.Config.ClientID)
		q.Set("redirect_uri", b.Config.PublicURL+"/auth/callback")
		q.Set("response_type", "code")
		q.Set("scope", strings.Join(b.Config.Scopes, " "))
		q.Set("state", state)
		q.Set("nonce", nonce)
		sum := sha256.Sum256([]byte(verifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), 302)
		return true
	case "/auth/logout":
		if r.Method != "POST" || r.Header.Get("X-Securock-Request") != "1" || r.Header.Get("Origin") != b.Config.PublicURL {
			reply(w, 403, nil)
			return true
		}
		if c, e := r.Cookie("securock_session"); e == nil {
			b.mu.Lock()
			delete(b.sessions, c.Value)
			b.mu.Unlock()
		}
		http.SetCookie(w, b.cookie("securock_session", "", -1))
		reply(w, 200, map[string]string{"status": "signed out"})
		return true
	case "/auth/callback":
		if r.Method != "GET" {
			reply(w, 405, nil)
			return true
		}
		state := r.URL.Query().Get("state")
		cookie, e := r.Cookie("securock_login")
		if e != nil || state == "" || cookie.Value != state {
			reply(w, 401, nil)
			return true
		}
		b.mu.Lock()
		pending, ok := b.pending[state]
		delete(b.pending, state)
		b.mu.Unlock()
		http.SetCookie(w, b.cookie("securock_login", "", -1))
		code := r.URL.Query().Get("code")
		if !ok || !pending.Expires.After(time.Now()) || len(code) == 0 || len(code) > 4096 {
			reply(w, 401, nil)
			return true
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {b.Config.ClientID}, "redirect_uri": {b.Config.PublicURL + "/auth/callback"}, "code_verifier": {pending.Verifier}}
		req, e := http.NewRequestWithContext(r.Context(), "POST", b.Config.TokenURL, strings.NewReader(form.Encode()))
		if e != nil {
			reply(w, 401, nil)
			return true
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if b.Config.SecretEnv != "" {
			secret := os.Getenv(b.Config.SecretEnv)
			if secret == "" {
				reply(w, 503, nil)
				return true
			}
			req.SetBasicAuth(b.Config.ClientID, secret)
		}
		client := &http.Client{Timeout: 15 * time.Second}
		if b.Client != nil {
			*client = *b.Client
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, e := client.Do(req)
		if e != nil {
			reply(w, 401, nil)
			return true
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
		resp.Body.Close()
		var tokens struct {
			Access string `json:"access_token"`
			ID     string `json:"id_token"`
			Type   string `json:"token_type"`
		}
		if e != nil || len(raw) > 65536 || resp.StatusCode != 200 || json.Unmarshal(raw, &tokens) != nil || !strings.EqualFold(tokens.Type, "Bearer") {
			reply(w, 401, nil)
			return true
		}
		apiPrincipal, e := s.tokenPrincipal(tokens.Access)
		if e != nil {
			reply(w, 401, nil)
			return true
		}
		conf := s.identityConfig()
		conf.Audience = b.Config.ClientID
		idPrincipal, e := conf.Verify(tokens.ID, time.Now())
		parts := strings.Split(tokens.ID, ".")
		var claims struct {
			Nonce           string          `json:"nonce"`
			AuthorizedParty string          `json:"azp"`
			Audience        json.RawMessage `json:"aud"`
		}
		if len(parts) == 3 {
			body, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.NewDecoder(bytes.NewReader(body)).Decode(&claims)
		}
		var audiences []string
		_ = json.Unmarshal(claims.Audience, &audiences)
		if e != nil || idPrincipal.Subject != apiPrincipal.Subject || claims.Nonce != pending.Nonce || claims.AuthorizedParty != "" && claims.AuthorizedParty != b.Config.ClientID || len(audiences) > 1 && claims.AuthorizedParty != b.Config.ClientID {
			reply(w, 401, nil)
			return true
		}
		sid := ID() + ID()
		b.mu.Lock()
		if len(b.sessions) >= 1000 {
			b.mu.Unlock()
			reply(w, 429, nil)
			return true
		}
		b.sessions[sid] = session{tokens.Access, time.Now().Add(15 * time.Minute)}
		b.mu.Unlock()
		http.SetCookie(w, b.cookie("securock_session", sid, 900))
		http.Redirect(w, r, "/ui", 302)
		return true
	}
	reply(w, 404, nil)
	return true
}
func (s *Server) identityConfig() identity.Config {
	c := s.Identity
	c.Bindings = nil
	for tenant, t := range s.Store.Read().Tenants {
		for _, m := range t.Members {
			if m.Active {
				c.Bindings = append(c.Bindings, identity.Binding{Subject: m.Subject, Tenant: tenant, Roles: m.Roles})
			}
		}
	}
	return c
}
func (s *Server) tokenPrincipal(token string) (identity.Principal, error) {
	return s.identityConfig().Verify(token, time.Now())
}
