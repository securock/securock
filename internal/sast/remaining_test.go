package sast_test

import (
	"slices"
	"testing"
)

func TestRemainingChecks(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		// ---- log injection
		{"go log of request data", map[string]string{"main.go": "package main\nimport (\"log\"; \"net/http\")\nfunc h(r *http.Request) { log.Printf(\"user %s\", r.FormValue(\"u\")) }\n"}, []string{"sast:go/log-injection"}},
		{"go quoted log is fine", map[string]string{"main.go": "package main\nimport (\"log\"; \"net/http\"; \"strconv\")\nfunc h(r *http.Request) { log.Printf(\"user %s\", strconv.Quote(r.FormValue(\"u\"))) }\n"}, nil},
		{"js console.log of query", map[string]string{"a.js": "app.get('/', (req, res) => { console.log('user ' + req.query.u); });\n"}, []string{"sast:js/log-injection"}},
		{"js newlines stripped", map[string]string{"a.js": "app.get('/', (req, res) => { console.log('user ' + req.query.u.replace(/[\\r\\n]/g, '')); });\n"}, nil},
		{"py logger of request arg", map[string]string{"a.py": "import logging\nfrom flask import request\nlogger = logging.getLogger()\ndef f():\n    logger.info('user %s' % request.args['u'])\n"}, []string{"sast:py/log-injection"}},
		{"java logger", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A {\n  void f(HttpServletRequest req, Object logger) { logger.info(\"u=\" + req.getParameter(\"u\")); }\n}\n"}, []string{"sast:java/log-injection"}},
		{"log of a constant", map[string]string{"a.js": "console.log('started');\n"}, nil},

		// ---- CORS
		{"go reflected origin", map[string]string{"main.go": "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { w.Header().Set(\"Access-Control-Allow-Origin\", r.Header.Get(\"Origin\")) }\n"}, []string{"sast:go/cors-misconfiguration"}},
		{"go fixed origin", map[string]string{"main.go": "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { w.Header().Set(\"Access-Control-Allow-Origin\", \"https://app.example.com\") }\n"}, nil},
		{"go other header from the request", map[string]string{"main.go": "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { w.Header().Set(\"X-Echo\", r.Header.Get(\"X-In\")) }\n"}, nil},
		{"js reflected origin header", map[string]string{"a.js": "app.get('/', (req, res) => { res.setHeader('Access-Control-Allow-Origin', req.headers.origin); });\n"}, []string{"sast:js/cors-misconfiguration"}},
		{"js cors origin true with credentials", map[string]string{"a.js": "const cors = require('cors');\napp.use(cors({ origin: true, credentials: true }));\n"}, []string{"sast:js/cors-misconfiguration"}},
		{"js cors listed origin with credentials", map[string]string{"a.js": "const cors = require('cors');\napp.use(cors({ origin: 'https://a.example', credentials: true }));\n"}, nil},
		{"py flask_cors wildcard with credentials", map[string]string{"a.py": "from flask_cors import CORS\ndef f(app):\n    CORS(app, supports_credentials=True, origins='*')\n"}, []string{"sast:py/cors-misconfiguration"}},

		// ---- insecure randomness
		{"go math/rand for a token", map[string]string{"main.go": "package main\nimport \"math/rand\"\nfunc newSessionToken() int { return rand.Int() }\n"}, []string{"sast:go/insecure-random"}},
		{"go math/rand for a dice roll", map[string]string{"main.go": "package main\nimport \"math/rand\"\nfunc roll() int { return rand.Intn(6) }\n"}, nil},
		{"go crypto/rand for a token", map[string]string{"main.go": "package main\nimport \"crypto/rand\"\nfunc newToken() []byte { b := make([]byte, 16); rand.Read(b); return b }\n"}, nil},
		{"go assigned to a secret-named variable", map[string]string{"main.go": "package main\nimport \"math/rand\"\nfunc f() int { apiKey := rand.Int(); return apiKey }\n"}, []string{"sast:go/insecure-random"}},
		{"js Math.random for a token", map[string]string{"a.js": "function makeToken() { return Math.random().toString(36).slice(2); }\n"}, []string{"sast:js/insecure-random"}},
		{"js Math.random for animation", map[string]string{"a.js": "function jitter() { return Math.random() * 10; }\n"}, nil},
		{"py random for a password", map[string]string{"a.py": "import random\ndef make_password():\n    return ''.join(random.choice('abc') for _ in range(8))\n"}, []string{"sast:py/insecure-random"}},
		{"py secrets for a password", map[string]string{"a.py": "import secrets\ndef make_password():\n    return secrets.token_hex(8)\n"}, nil},
		{"php rand for a reset token", map[string]string{"a.php": "<?php\nfunction reset_token() { return md5(rand()); }\n"}, []string{"sast:php/insecure-random"}},
		{"ruby rand for a csrf value", map[string]string{"a.rb": "def csrf_value\n  rand(1_000_000).to_s\nend\n"}, []string{"sast:rb/insecure-random"}},
		{"java Random for a nonce", map[string]string{"A.java": "import java.util.Random;\npublic class A {\n  long nonce() { return new Random().nextLong(); }\n}\n"}, []string{"sast:java/insecure-random"}},

		// ---- TOCTOU
		{"go stat then remove", map[string]string{"main.go": "package main\nimport \"os\"\nfunc f(p string) {\n\tif _, err := os.Stat(p); err == nil {\n\t\tos.Remove(p)\n\t}\n}\n"}, []string{"sast:go/toctou"}},
		{"go stat then mkdirall is idempotent", map[string]string{"main.go": "package main\nimport \"os\"\nfunc f(p string) {\n\tif _, err := os.Stat(p); err != nil {\n\t\tos.MkdirAll(p, 0o755)\n\t}\n}\n"}, nil},
		{"py exists then remove", map[string]string{"a.py": "import os\ndef f(p):\n    if os.path.exists(p):\n        os.remove(p)\n"}, []string{"sast:py/toctou"}},
		{"py exists on one path and remove on another", map[string]string{"a.py": "import os\ndef f(p, q):\n    if os.path.exists(p):\n        os.remove(q)\n"}, nil},
		{"js existsSync then unlink", map[string]string{"a.js": "const fs = require('fs');\nfunction f(p) { if (fs.existsSync(p)) { fs.unlinkSync(p); } }\n"}, []string{"sast:js/toctou"}},
		{"php file_exists then unlink", map[string]string{"a.php": "<?php\nfunction f($p) { if (file_exists($p)) { unlink($p); } }\n"}, []string{"sast:php/toctou"}},
		{"ruby exist then delete", map[string]string{"a.rb": "def f(p)\n  File.delete(p) if File.exist?(p)\nend\n"}, []string{"sast:rb/toctou"}},
		{"java exists then delete", map[string]string{"A.java": "import java.io.File;\npublic class A {\n  void f(File p) { if (p.exists()) { p.delete(); } }\n}\n"}, []string{"sast:java/toctou"}},

		// ---- XXE
		{"java unhardened factory", map[string]string{"A.java": "import javax.xml.parsers.*;\npublic class A {\n  void f() throws Exception { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.newDocumentBuilder(); }\n}\n"}, []string{"sast:java/xxe"}},
		{"java hardened factory", map[string]string{"A.java": "import javax.xml.parsers.*;\npublic class A {\n  void f() throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder();\n  }\n}\n"}, nil},
		{"php LIBXML_NOENT", map[string]string{"a.php": "<?php\n$d = new DOMDocument();\n$d->loadXML($xml, LIBXML_NOENT);\n"}, []string{"sast:php/xxe"}},
		{"php default loadXML", map[string]string{"a.php": "<?php\n$d = new DOMDocument();\n$d->loadXML($xml);\n"}, nil},
		{"ruby Nokogiri NOENT", map[string]string{"a.rb": "def f(x)\n  Nokogiri::XML(x, nil, nil, Nokogiri::XML::ParseOptions::NOENT)\nend\n"}, []string{"sast:rb/xxe"}},
		{"ruby Nokogiri default", map[string]string{"a.rb": "def f(x)\n  Nokogiri::XML(x)\nend\n"}, nil},

		// ---- older JavaScript class idioms
		{"constructor function with this.method across files", map[string]string{
			"dao.js":   "function AllocationsDAO(db) {\n  this.byThreshold = (id, threshold, cb) => {\n    db.collection('a').find({ $where: `this.userId == ${id} && this.stocks > '${threshold}'` }, cb);\n  };\n}\nmodule.exports = AllocationsDAO;\n",
			"route.js": "const AllocationsDAO = require('./dao');\nfunction Handler(db) {\n  const dao = new AllocationsDAO(db);\n  this.show = (req, res) => { dao.byThreshold(1, req.query.threshold, () => {}); };\n}\n"},
			[]string{"sast:js/nosql-injection"}},
		{"prototype method", map[string]string{"a.js": "function Repo(db) { this.db = db; }\nRepo.prototype.find = function (n) { return this.db.query(\"SELECT '\" + n + \"'\"); };\napp.get('/', (req, res) => { new Repo(db).find(req.query.n); });\n"}, []string{"sast:js/sql-injection"}},
		{"arrow function assigned to a const is a callable function", map[string]string{"a.js": "const find = (n) => db.query(\"SELECT '\" + n + \"'\");\napp.get('/', (req, res) => { find(req.query.n); });\n"}, []string{"sast:js/sql-injection"}},

		// ---- configuration is not code
		{"unquoted assignment in code is an expression", map[string]string{"a.js": "res.locals.csrftoken = req.csrfToken();\n"}, nil},

		// ---- $where and recursive merge
		{"js $where from the request", map[string]string{"a.js": "app.get('/s', async (req, res) => {\n  res.json(await Item.find({ $where: \"this.name == '\" + req.query.n + \"'\" }));\n});\n"}, []string{"sast:js/nosql-injection"}},
		{"js recursive merge of the body", map[string]string{"a.js": "function merge(t, s) {\n  for (const k in s) {\n    if (typeof s[k] === 'object') merge(t[k], s[k]); else t[k] = s[k];\n  }\n  return t;\n}\napp.post('/s', (req, res) => res.json(merge({}, req.body)));\n"}, []string{"sast:js/prototype-pollution"}},
		{"js recursive merge of constants", map[string]string{"a.js": "function merge(t, s) {\n  for (const k in s) {\n    if (typeof s[k] === 'object') merge(t[k], s[k]); else t[k] = s[k];\n  }\n  return t;\n}\nmodule.exports = merge({}, defaults);\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, tt.files))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
