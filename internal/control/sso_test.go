package control_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBrowserLoginPKCEAndSessionCSRF(t *testing.T) {
	s, token, _ := fixture(t)
	nonce, challenge := "", ""
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("redirect_uri") != "https://control.example/auth/callback" {
			t.Error("PKCE/callback mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token("alice"), "id_token": token("alice|" + nonce), "token_type": "Bearer"})
	}))
	defer idp.Close()
	b, e := control.NewBrowserSSO(control.SSOConfig{AuthorizeURL: idp.URL + "/authorize", TokenURL: idp.URL + "/token", ClientID: "api", PublicURL: "https://control.example", Scopes: []string{"openid", "securock"}})
	if e != nil {
		t.Fatal(e)
	}
	b.Client = idp.Client()
	s.SSO = b
	start := request(s, "", "GET", "/auth/login", "")
	if start.Code != 302 {
		t.Fatal(start.Code)
	}
	location, _ := url.Parse(start.Header().Get("Location"))
	nonce = location.Query().Get("nonce")
	challenge = location.Query().Get("code_challenge")
	if location.Query().Get("code_challenge_method") != "S256" || nonce == "" {
		t.Fatal("missing PKCE")
	}
	callback := httptest.NewRequest("GET", "/auth/callback?code=fixture&state="+location.Query().Get("state"), nil)
	callback.AddCookie(start.Result().Cookies()[0])
	w := httptest.NewRecorder()
	s.ServeHTTP(w, callback)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "securock_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly {
		t.Fatal("unsafe session")
	}
	get := httptest.NewRequest("GET", "/api/v1/me", nil)
	get.AddCookie(sessionCookie)
	result := httptest.NewRecorder()
	s.ServeHTTP(result, get)
	if result.Code != 200 {
		t.Fatal(result.Code)
	}
	post := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"id":"x","name":"x","owner":"team"}`))
	post.AddCookie(sessionCookie)
	result = httptest.NewRecorder()
	s.ServeHTTP(result, post)
	if result.Code != 401 {
		t.Fatal("CSRF accepted")
	}
	post = httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"id":"x","name":"x","owner":"team"}`))
	post.AddCookie(sessionCookie)
	post.Header.Set("Origin", "https://control.example")
	post.Header.Set("X-Securock-Request", "1")
	result = httptest.NewRecorder()
	s.ServeHTTP(result, post)
	if result.Code != 201 {
		t.Fatal(result.Code)
	}
	replay := httptest.NewRecorder()
	s.ServeHTTP(replay, callback)
	if replay.Code != 401 {
		t.Fatal("login code replay")
	}
}
