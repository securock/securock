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

func TestGapsFoundOnRealApplications(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"php $html collects output that a template prints", map[string]string{"a.php": "<?php\n$html .= '<p>Hello ' . $_GET['name'] . '</p>';\n"}, []string{"sast:php/xss"}},
		{"php $html with an escaped value", map[string]string{"a.php": "<?php\n$html .= '<p>Hello ' . htmlspecialchars($_GET['name']) . '</p>';\n"}, nil},
		{"py xml.sax external entities", map[string]string{"a.py": "from xml.sax import make_parser\nfrom xml.sax.handler import feature_external_ges\ndef f():\n    p = make_parser()\n    p.setFeature(feature_external_ges, True)\n"}, []string{"sast:py/xxe"}},
		{"py xml.sax external entities off", map[string]string{"a.py": "from xml.sax import make_parser\nfrom xml.sax.handler import feature_external_ges\ndef f():\n    p = make_parser()\n    p.setFeature(feature_external_ges, False)\n"}, nil},
		{"py class-based view", map[string]string{"a.py": "from django.views import View\nclass V(View):\n    def get(self, request):\n        return self.db.execute(\"SELECT '\" + self.request.GET['n'] + \"'\")\n"}, []string{"sast:py/sql-injection"}},
		{"ruby scope lambda", map[string]string{"model.rb": "class Analytics < ApplicationRecord\n  scope :hits, ->(ip, col = \"*\") { select(\"#{col}\").where(ip: ip) }\nend\n", "ctl.rb": "class AdminController < ApplicationController\n  def index\n    @a = Analytics.hits(params[:ip], params[:fields])\n  end\nend\n"}, []string{"sast:rb/sql-injection"}},
		{"ruby try with a request-chosen method", map[string]string{"a.rb": "class C < ApplicationController\n  def x\n    self.try(params[:graph])\n  end\nend\n"}, []string{"sast:rb/code-injection"}},
		{"js table dispatch on a request key", map[string]string{"a.js": "const handlers = { a: () => 1 };\napp.get('/', (req, res) => { handlers[req.query.action](); });\n"}, []string{"sast:js/code-injection"}},
		{"js autoescape off", map[string]string{"a.js": "const swig = require('swig');\nswig.setDefaults({ autoescape: false });\n"}, []string{"sast:js/template-autoescape-disabled"}},
		{"js autoescape on", map[string]string{"a.js": "const swig = require('swig');\nswig.setDefaults({ autoescape: true });\n"}, nil},
		{"py jinja Environment autoescape False", map[string]string{"a.py": "from jinja2 import Environment\nenv = Environment(autoescape=False)\n"}, []string{"sast:py/template-autoescape-disabled"}},
		{"php call_user_func with the request", map[string]string{"a.php": "<?php\ncall_user_func($_GET['fn']);\n"}, []string{"sast:php/code-injection"}},
		{"java Class.forName", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A {\n  void f(HttpServletRequest req) throws Exception { Class.forName(req.getParameter(\"c\")); }\n}\n"}, []string{"sast:java/code-injection"}},
		{"python getattr with a request name", map[string]string{"a.py": "import handlers\nfrom flask import request\ndef f():\n    return getattr(handlers, request.args['a'])()\n"}, []string{"sast:py/code-injection"}},

		// template files
		{"jinja |safe", map[string]string{"templates/p.html": "<p>{{ comment|safe }}</p>\n"}, []string{"sast:template/unescaped-output"}},
		{"jinja default escaping", map[string]string{"templates/p.html": "<p>{{ comment }}</p>\n"}, nil},
		{"jinja |safe on a literal", map[string]string{"templates/p.html": "<p>{{ '<b>hi</b>'|safe }}</p>\n"}, nil},
		{"ejs unescaped", map[string]string{"views/p.ejs": "<div><%- body %></div>\n"}, []string{"sast:template/unescaped-output"}},
		{"ejs escaped", map[string]string{"views/p.ejs": "<div><%= body %></div>\n"}, nil},
		{"handlebars triple", map[string]string{"views/p.hbs": "<div>{{{ body }}}</div>\n"}, []string{"sast:template/unescaped-output"}},
		{"blade raw", map[string]string{"views/p.blade.php": "<div>{!! $body !!}</div>\n"}, []string{"sast:template/unescaped-output"}},
		{"erb raw and html_safe", map[string]string{"views/p.html.erb": "<%= raw @body %>\n<%= @x.html_safe %>\n"}, []string{"sast:template/unescaped-output", "sast:template/unescaped-output"}},
		{"erb html_safe on a literal or an inspected value", map[string]string{"views/p.html.erb": "<%= u.admin ? '<i class=\"ok\"></i>'.html_safe : 'x'.html_safe %>\n<%= path.inspect.html_safe %>\n"}, nil},
		{"jinja csrf token marked safe", map[string]string{"templates/p.html": "<script>const t = \"{{ csrf_token|safe }}\";</script>\n"}, nil},
		{"vue v-html", map[string]string{"src/C.vue": "<template><div v-html=\"body\"></div></template>\n"}, []string{"sast:template/unescaped-output"}},
		{"not-equal in an html inline script is not pug", map[string]string{"index.html": "<script>\nif (a != b) { go(); }\n</script>\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, tt.files)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFallbackOperatorsKeepTaint(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"js or", map[string]string{"a.js": "app.get('/', (req, res) => { const q = req.query.q || ''; db.query('SELECT ' + q); });\n"}, []string{"sast:js/sql-injection"}},
		{"js nullish", map[string]string{"a.js": "app.get('/', (req, res) => { const q = req.query.q ?? 'x'; db.query('SELECT ' + q); });\n"}, []string{"sast:js/sql-injection"}},
		{"js and", map[string]string{"a.js": "app.get('/', (req, res) => { const q = req.query.ok && req.query.q; db.query('SELECT ' + q); });\n"}, []string{"sast:js/sql-injection"}},
		{"py or", map[string]string{"a.py": "from flask import request\ndef f(cur):\n    q = request.args.get('q') or ''\n    cur.execute('SELECT ' + q)\n"}, []string{"sast:py/sql-injection"}},
		{"php null coalescing", map[string]string{"a.php": "<?php\n$q = $_GET['q'] ?? '';\nmysqli_query($c, \"SELECT \" . $q);\n"}, []string{"sast:php/sql-injection"}},
		{"ruby or", map[string]string{"a.rb": "class C < ApplicationController\n  def x\n    q = params[:q] || ''\n    User.find_by_sql(\"SELECT #{q}\")\n  end\nend\n"}, []string{"sast:rb/sql-injection"}},
		{"js or with constants stays clean", map[string]string{"a.js": "app.get('/', (req, res) => { const q = limit || 'x'; db.query('SELECT ' + q); });\n"}, nil},
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

func TestDestructuredHandlerAndXMLOptions(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"typed destructured request", map[string]string{"a.ts": "import { type Request, type Response } from 'express'\nexport function h () {\n  return ({ query }: Request, res: Response) => {\n    const to: string = query.to as string\n    res.redirect(to)\n  }\n}\n"}, []string{"sast:js/open-redirect"}},
		{"destructured with a response sibling", map[string]string{"a.js": "app.get('/', ({ query, body }, res) => { res.redirect(query.next); });\n"}, []string{"sast:js/open-redirect"}},
		{"renamed destructuring", map[string]string{"a.js": "app.get('/', ({ query: q }, res) => { res.redirect(q.next); });\n"}, []string{"sast:js/open-redirect"}},
		{"destructuring something that is not a handler", map[string]string{"a.js": "function search({ query }, options) { return db.query('SELECT ' + query); }\n"}, nil},
		{"libxmljs noent", map[string]string{"a.js": "const libxml = require('libxmljs');\nfunction f(d) { return libxml.parseXml(d, { noent: true }); }\n"}, []string{"sast:js/xxe"}},
		{"libxmljs default", map[string]string{"a.js": "const libxml = require('libxmljs');\nfunction f(d) { return libxml.parseXml(d); }\n"}, nil},
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

func TestFlowFixesFoundByTheOWASPBenchmark(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"java fully qualified types and calls", map[string]string{"A.java": "public class A extends javax.servlet.http.HttpServlet {\n  public void doPost(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {\n    String p = java.net.URLDecoder.decode(request.getParameter(\"x\"), \"UTF-8\");\n    new java.io.FileInputStream(\"/tmp/\" + p);\n  }\n}\n"}, []string{"sast:java/path-traversal"}},
		{"java value assigned before a break reaches the code after the loop", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    Cookie[] cs = request.getCookies();\n    String p = \"\";\n    for (Cookie c : cs) {\n      if (c.getName().equals(\"x\")) { p = c.getValue(); break; }\n    }\n    new java.io.FileInputStream(\"/tmp/\" + p);\n  }\n}\n"}, []string{"sast:java/path-traversal"}},
		{"java dead branch by constant folding", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"x\");\n    String bar;\n    int num = 86;\n    if ((7 * 42) - num > 200) bar = \"fixed\"; else bar = p;\n    new java.io.FileInputStream(\"/tmp/\" + bar);\n  }\n}\n"}, nil},
		{"java map keys are tracked apart", map[string]string{"A.java": "import javax.servlet.http.*;\nimport java.util.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"x\");\n    HashMap<String, Object> m = new HashMap<String, Object>();\n    m.put(\"a\", \"safe\");\n    m.put(\"b\", p);\n    String bar = (String) m.get(\"a\");\n    new java.io.FileInputStream(\"/tmp/\" + bar);\n  }\n}\n"}, nil},
		{"unrelated classes with the same name do not share a summary", map[string]string{
			"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"x\");\n    String bar = new Test().doSomething(p);\n    new java.io.FileInputStream(\"/tmp/\" + bar);\n  }\n  private class Test { public String doSomething(String s) { return \"fixed\"; } }\n}\n",
			"B.java": "public class B {\n  private class Test { public String doSomething(String s) { return s; } }\n}\n"}, nil},
		{"toString on a library value does not pull in a project method", map[string]string{
			"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"x\");\n    String k = Float.toString(0.5f);\n    new java.io.FileInputStream(\"/tmp/\" + k);\n  }\n}\n",
			"B.java": "public class B {\n  public String toString() { return \"fixed\"; }\n}\n"}, nil},
		{"a project static call is still followed", map[string]string{
			"A.java":      "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    Runner.run(request.getParameter(\"c\"));\n  }\n}\n",
			"Runner.java": "public class Runner {\n  public static void run(String c) throws Exception { Runtime.getRuntime().exec(c); }\n}\n"}, []string{"sast:java/command-injection"}},
		{"flask route returning request data as a page", map[string]string{"a.py": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef f():\n    name = request.args.get('n')\n    return 'Hello ' + name\n"}, []string{"sast:py/xss"}},
		{"flask route returning escaped data", map[string]string{"a.py": "import html\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef f():\n    name = request.args.get('n')\n    return 'Hello ' + html.escape(name)\n"}, nil},
		{"flask route returning JSON", map[string]string{"a.py": "from flask import Flask, request, jsonify\napp = Flask(__name__)\n@app.route('/')\ndef f():\n    return jsonify({'n': request.args.get('n')})\n"}, nil},
		{"flask session key from the request", map[string]string{"a.py": "import flask\nfrom flask import request\ndef f():\n    flask.session[request.args['k']] = '1'\n"}, []string{"sast:py/trust-boundary"}},
		{"python weak random into a session", map[string]string{"a.py": "import random\nfrom flask import session\ndef f():\n    session['t'] = str(random.normalvariate())\n"}, []string{"sast:py/insecure-random"}},
		{"python Path.read_text", map[string]string{"a.py": "from pathlib import Path\nfrom flask import request\ndef f():\n    return Path('/srv/' + request.args['f']).read_text()\n"}, []string{"sast:py/path-traversal"}},
		{"lxml XPath constructor", map[string]string{"a.py": "import lxml.etree\nfrom flask import request\ndef f():\n    return lxml.etree.XPath(\"//u[@n='\" + request.args['n'] + \"']\")\n"}, []string{"sast:py/xpath-injection"}},
		{"java session attribute is a trust boundary", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    request.getSession().setAttribute(\"k\", request.getParameter(\"v\"));\n  }\n}\n"}, []string{"sast:java/trust-boundary"}},
		{"java weak random in a cookie", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    float r = new java.util.Random().nextFloat();\n    response.addCookie(new javax.servlet.http.Cookie(\"id\", Float.toString(r)));\n  }\n}\n"}, []string{"sast:java/insecure-cookie", "sast:java/insecure-random"}},
		{"java secure random in a cookie", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    float r = new java.security.SecureRandom().nextFloat();\n    response.addCookie(new javax.servlet.http.Cookie(\"id\", Float.toString(r)));\n  }\n}\n"}, []string{"sast:java/insecure-cookie"}},
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

func TestJuiceShopFixVariants(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"angular route query into bypassSecurityTrustHtml", map[string]string{"c.ts": "export class C {\n  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}\n  ngOnInit () {\n    let q: string = this.route.snapshot.queryParams.q\n    this.html = this.sanitizer.bypassSecurityTrustHtml(`<code>${q}</code>`)\n  }\n}\n"}, []string{"sast:js/xss"}},
		{"angular subscribe callback", map[string]string{"c.ts": "export class C {\n  ngOnInit () {\n    this.route.queryParams.subscribe((p: any) => { this.h = this.sanitizer.bypassSecurityTrustHtml(p.q) })\n  }\n}\n"}, []string{"sast:js/xss"}},
		{"angular sanitized content", map[string]string{"c.ts": "export class C {\n  ngOnInit () {\n    let q: string = this.route.snapshot.queryParams.q\n    this.h = this.sanitizer.sanitize(SecurityContext.HTML, q)\n  }\n}\n"}, nil},
		{"redirect allowlist by substring", map[string]string{"a.ts": "export const isRedirectAllowed = (url: string) => {\n  let allowed = false\n  for (const allowedUrl of redirectAllowlist) {\n    allowed = allowed || url.includes(allowedUrl)\n  }\n  return allowed\n}\n"}, []string{"sast:js/weak-allowlist"}},
		{"redirect allowlist by exact membership", map[string]string{"a.ts": "export const isRedirectAllowed = (url: string) => redirectAllowlist.has(url)\n"}, nil},
		{"java allowlist by prefix", map[string]string{"A.java": "public class A {\n  boolean ok(String url, java.util.List<String> allowedUrls) {\n    for (String allowedUrl : allowedUrls) { if (url.startsWith(allowedUrl)) return true; }\n    return false;\n  }\n}\n"}, []string{"sast:java/weak-allowlist"}},
		{"python allowlist by prefix", map[string]string{"a.py": "def ok(url, allowed_urls):\n    for allowed_url in allowed_urls:\n        if url.startswith(allowed_url):\n            return True\n    return False\n"}, []string{"sast:py/weak-allowlist"}},
		{"serve-index", map[string]string{"s.ts": "import serveIndex from 'serve-index'\napp.use('/ftp', serveIndex('ftp', { icons: true }))\n"}, []string{"sast:js/directory-listing"}},
		{"mass assignment of the request body", map[string]string{"a.ts": "app.post('/users', (req, res) => { UserModel.create(req.body) })\n"}, []string{"sast:js/mass-assignment"}},
		{"mass assignment with chosen fields", map[string]string{"a.ts": "app.post('/users', (req, res) => { UserModel.create({ email: req.body.email, password: req.body.password }) })\n"}, nil},
		{"rails mass assignment", map[string]string{"a.rb": "class C < ApplicationController\n  def create\n    User.create(params[:user])\n  end\n  def ok\n    User.create(params.require(:user).permit(:name))\n  end\nend\n"}, []string{"sast:rb/mass-assignment"}},
		{"llm system prompt from the request", map[string]string{"a.ts": "app.post('/chat', async (req, res) => {\n  const r = await generateText({ system: `You are ${req.body.persona}`, prompt: 'hi' })\n})\n"}, []string{"sast:js/prompt-injection"}},
		{"llm user message from the request", map[string]string{"a.ts": "app.post('/chat', async (req, res) => {\n  const r = await generateText({ system: 'You are helpful', prompt: req.body.text })\n})\n"}, nil},
		{"llm system message object", map[string]string{"a.ts": "app.post('/chat', async (req, res) => {\n  const m = [{ role: 'system', content: 'Rules: ' + req.body.rules }]\n})\n"}, []string{"sast:js/prompt-injection"}},
		{"python llm system role", map[string]string{"a.py": "from flask import request\ndef f():\n    return [{\"role\": \"system\", \"content\": \"Be \" + request.args['tone']}]\n"}, []string{"sast:py/prompt-injection"}},
		{"python llm system keyword", map[string]string{"a.py": "from flask import request\ndef f(client):\n    return client.messages.create(system='Be ' + request.json['tone'], messages=[])\n"}, []string{"sast:py/prompt-injection"}},
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

func TestWeakAPIChecks(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"py set_cookie without flags", map[string]string{"a.py": "def f(r):\n    r.set_cookie('a', 'b')\n"}, []string{"sast:py/insecure-cookie"}},
		{"py set_cookie with flags", map[string]string{"a.py": "def f(r):\n    r.set_cookie('a', 'b', secure=True, httponly=True)\n"}, nil},
		{"py weak ssl version", map[string]string{"a.py": "import ssl\ndef f(s):\n    return ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)\n"}, []string{"sast:py/tls-verification-disabled"}},
		{"py ECB mode", map[string]string{"a.py": "from cryptography.hazmat.primitives.ciphers import modes\ndef f():\n    return modes.ECB()\n"}, []string{"sast:py/weak-crypto"}},
		{"php md5 of a password", map[string]string{"a.php": "<?php\n$h = md5($password);\n$k = md5($cacheKey);\n"}, []string{"sast:php/weak-crypto"}},
		{"php anonymous ldap bind", map[string]string{"a.php": "<?php\nldap_bind($conn);\nldap_bind($conn, 'u', 'p');\n"}, []string{"sast:php/weak-crypto"}},
		{"php curl url from the request", map[string]string{"a.php": "<?php\ncurl_setopt($ch, CURLOPT_URL, $_POST['u']);\n"}, []string{"sast:php/ssrf"}},
		{"php file_get_contents of a fixed prefix is not ssrf", map[string]string{"a.php": "<?php\n$d = file_get_contents('/srv/' . $_GET['f']);\n"}, []string{"sast:php/path-traversal"}},
		{"ruby finder option from params", map[string]string{"a.rb": "class C < ApplicationController\n  def x\n    Product.find(:all, :order => params[:o])\n  end\nend\n"}, []string{"sast:rb/sql-injection"}},
		{"ruby force_ssl false", map[string]string{"a.rb": "config.force_ssl = false\n"}, []string{"sast:rb/https-not-enforced"}},
		{"ruby jwt without verify", map[string]string{"a.rb": "def f(t)\n  JWT.decode t, secret, false\nend\n"}, []string{"sast:rb/jwt-unverified"}},
		{"java weak SSLContext", map[string]string{"A.java": "import javax.net.ssl.SSLContext;\npublic class A {\n  void f() throws Exception { SSLContext.getInstance(\"TLSv1\"); SSLContext.getInstance(\"TLSv1.3\"); }\n}\n"}, []string{"sast:java/tls-verification-disabled"}},
		{"java NullCipher", map[string]string{"A.java": "public class A {\n  void f() { new javax.crypto.NullCipher(); }\n}\n"}, []string{"sast:java/weak-crypto"}},
		{"js cookie option off", map[string]string{"a.js": "app.use(session({ cookie: { httpOnly: false } }));\n"}, []string{"sast:js/insecure-cookie"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, tt.files)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGoCookieLiterals(t *testing.T) {
	got := analyze(t, map[string]string{"main.go": "package main\nimport \"net/http\"\nfunc a() *http.Cookie { return &http.Cookie{Name: \"s\", Value: \"v\"} }\nfunc b() *http.Cookie { return &http.Cookie{Name: \"s\", Secure: true, HttpOnly: true} }\nfunc c() *http.Cookie { return &http.Cookie{Name: \"s\", MaxAge: -1} }\n"})
	if !slices.Equal(got, []string{"sast:go/insecure-cookie"}) {
		t.Fatalf("got %v", got)
	}
}

func TestJavaCookieFlags(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"no flags", "import javax.servlet.http.*;\npublic class A {\n  void f(HttpServletResponse r) { Cookie c = new Cookie(\"a\", \"b\"); r.addCookie(c); }\n}\n", []string{"sast:java/insecure-cookie"}},
		{"only secure", "import javax.servlet.http.*;\npublic class A {\n  void f(HttpServletResponse r) { Cookie c = new Cookie(\"a\", \"b\"); c.setSecure(true); r.addCookie(c); }\n}\n", []string{"sast:java/insecure-cookie"}},
		{"both flags", "import javax.servlet.http.*;\npublic class A {\n  void f(HttpServletResponse r) { Cookie c = new Cookie(\"a\", \"b\"); c.setSecure(true); c.setHttpOnly(true); r.addCookie(c); }\n}\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"A.java": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmFromPropertiesAndConstants(t *testing.T) {
	got := analyze(t, map[string]string{
		"app.properties": "hashAlg=MD5\nsafeAlg=SHA-256\n",
		"A.java":         "public class A {\n  void a() throws Exception {\n    java.util.Properties p = new java.util.Properties();\n    String alg = p.getProperty(\"hashAlg\", \"SHA-512\");\n    java.security.MessageDigest.getInstance(alg);\n  }\n  void b() throws Exception {\n    java.util.Properties p = new java.util.Properties();\n    java.security.MessageDigest.getInstance(p.getProperty(\"safeAlg\", \"MD5\"));\n  }\n  void c() throws Exception {\n    String alg = \"SHA-\" + \"1\";\n    java.security.MessageDigest.getInstance(alg);\n  }\n}\n",
	})
	if !slices.Equal(got, []string{"sast:java/weak-crypto", "sast:java/weak-crypto"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSpringConfig(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"properties", map[string]string{"application.properties": "management.endpoints.web.exposure.include=*\nspring.h2.console.enabled=true\nserver.port=8080\n"}, []string{"sast:config/spring-actuator-exposed", "sast:config/spring-h2-console"}},
		{"yaml", map[string]string{"application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\nserver:\n  error:\n    include-stacktrace: always\n"}, []string{"sast:config/spring-actuator-exposed", "sast:config/spring-error-detail"}},
		{"safe settings", map[string]string{"application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\nspring:\n  h2:\n    console:\n      enabled: false\n"}, nil},
		{"other yaml is not spring config", map[string]string{"settings.yml": "spring:\n  h2:\n    console:\n      enabled: true\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, tt.files)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVendoredLibrariesAndScopeNames(t *testing.T) {
	got := analyze(t, map[string]string{
		"static/js/libs/mode.js": "var rules = { token : \"meta.tag.punctuation.tag-close.xml\" };\nvar k = { password: \"Zq8vN2kLm4TxR7pW\" };\n",
		"app/mode.js":            "var rules = { token : \"meta.tag.punctuation.tag-close.xml\" };\n",
	})
	if len(got) != 0 {
		t.Fatalf("a scope name is not a secret and a vendored library is not analyzed: got %v", got)
	}
	got = analyze(t, map[string]string{"libs/Util.go": "package libs\nimport \"crypto/md5\"\nfunc F(b []byte) { md5.Sum(b) }\n"})
	if len(got) != 1 {
		t.Fatalf("Go in a directory called libs is still first-party: got %v", got)
	}
}
