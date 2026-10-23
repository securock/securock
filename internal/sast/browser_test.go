package sast_test

import (
	"slices"
	"testing"
)

func TestHeadlessBrowserSinks(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"puppeteer goto", `
const puppeteer = require('puppeteer');
app.get('/shot', async (req, res) => {
  const page = await (await puppeteer.launch()).newPage();
  await page.goto(req.query.url);
});`, []string{"sast:js/ssrf"}},
		{"puppeteer setContent", `
app.post('/pdf', async (req, res) => {
  const page = await browser.newPage();
  await page.setContent('<html>' + req.body.html + '</html>');
});`, []string{"sast:js/ssrf"}},
		{"page.evaluate runs code in the browser", `
app.post('/run', async (req, res) => {
  const page = await browser.newPage();
  await page.evaluate(` + "`fetch(${req.body.u})`" + `);
});`, []string{"sast:js/code-injection"}},
		{"wkhtmltopdf", `
const wkhtmltopdf = require('wkhtmltopdf');
app.get('/pdf', (req, res) => {
  wkhtmltopdf(req.query.u, { output: 'out.pdf' });
});`, []string{"sast:js/ssrf"}},
		{"constant url", `
app.get('/shot', async (req, res) => {
  const page = await browser.newPage();
  await page.goto('https://example.com');
});`, nil},
		{"goto on a router is not a browser", `
app.get('/x', (req, res) => {
  router.goto(req.query.to);
});`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"app.js": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWTSecretLiteral(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"literal secret in sign", "const jwt = require('jsonwebtoken');\nfunction f(u) { return jwt.sign({ id: u }, 'shhh'); }", []string{"sast:js/hardcoded-signing-key"}},
		{"literal secret held in a variable", "const jwt = require('jsonwebtoken');\nfunction f(t) { const secret = 'shhh'; return jwt.verify(t, secret); }", []string{"sast:js/hardcoded-signing-key"}},
		{"module-level secret constant", "const jwt = require('jsonwebtoken');\nconst SECRET = 'shhh-secret';\nfunction f(t) { return jwt.verify(t, SECRET); }", []string{"sast:js/hardcoded-signing-key"}},
		{"module-level name shadowed by a parameter", "const jwt = require('jsonwebtoken');\nconst key = 'shhh-secret';\nfunction f(t, key) { return jwt.verify(t, key); }", nil},
		{"secret from the environment", "const jwt = require('jsonwebtoken');\nfunction f(u) { return jwt.sign({ id: u }, process.env.JWT_SECRET); }", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"app.js": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJSObjectOptionChecks(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"none among the algorithms", "const jwt = require('jsonwebtoken');\nfunction f(t, k) { return jwt.verify(t, k, { algorithms: ['RS256', 'none'] }); }", []string{"sast:js/jwt-unverified"}},
		{"pinned algorithms", "const jwt = require('jsonwebtoken');\nfunction f(t, k) { return jwt.verify(t, k, { algorithms: ['RS256'] }); }", nil},
		{"passport secretOrKey literal", "const { Strategy } = require('passport-jwt');\nnew Strategy({ secretOrKey: 'HARDCODED-SECRET' }, () => {});", []string{"sast:js/hardcoded-signing-key"}},
		{"passport secretOrKey from env", "const { Strategy } = require('passport-jwt');\nnew Strategy({ secretOrKey: process.env.JWT_SECRET }, () => {});", nil},
		{"session secret literal", "const session = require('express-session');\napp.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));", []string{"sast:js/hardcoded-signing-key"}},
		{"session secret from env", "const session = require('express-session');\napp.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));", nil},
		{"cookie-session keys literal", "const cookieSession = require('cookie-session');\napp.use(cookieSession({ name: 'session', keys: ['key1-literal', 'key2-literal'] }));", []string{"sast:js/hardcoded-signing-key"}},
		{"cookie-session keys from env", "const cookieSession = require('cookie-session');\napp.use(cookieSession({ name: 'session', keys: [process.env.K1] }));", nil},
		{"electron nodeIntegration", "new BrowserWindow({ webPreferences: { nodeIntegration: true } });", []string{"sast:js/electron-insecure-window"}},
		{"electron contextIsolation off", "new BrowserWindow({ webPreferences: { contextIsolation: false } });", []string{"sast:js/electron-insecure-window"}},
		{"electron secure defaults", "new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true, webSecurity: true } });", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"app.js": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
