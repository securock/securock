package sast_test

import (
	"slices"
	"testing"
)

func TestMisuseAndExtraSinks(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		// ---- Python
		{"py requests verify=False", map[string]string{"a.py": "import requests\ndef f():\n    return requests.get('https://x', verify=False)\n"}, []string{"sast:py/tls-verification-disabled"}},
		{"py requests default verify", map[string]string{"a.py": "import requests\ndef f():\n    return requests.get('https://x', timeout=3)\n"}, nil},
		{"py md5 vs usedforsecurity", map[string]string{"a.py": "import hashlib\ndef f(b):\n    return hashlib.md5(b)\ndef g(b):\n    return hashlib.md5(b, usedforsecurity=False)\n"}, []string{"sast:py/weak-crypto"}},
		{"py hashlib.new md5 and sha256", map[string]string{"a.py": "import hashlib\ndef f(b):\n    return hashlib.new('md5', b)\ndef g(b):\n    return hashlib.new('sha256', b)\n"}, []string{"sast:py/weak-crypto"}},
		{"py flask debug", map[string]string{"a.py": "from flask import Flask\napp = Flask(__name__)\nif __name__ == '__main__':\n    app.run(debug=True)\n"}, []string{"sast:py/debug-enabled"}},
		{"py flask no debug", map[string]string{"a.py": "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0')\n"}, nil},
		{"py django DEBUG only in settings", map[string]string{"proj/settings.py": "DEBUG = True\n", "proj/other.py": "DEBUG = True\n"}, []string{"sast:py/debug-enabled"}},
		{"py mktemp", map[string]string{"a.py": "import tempfile\ndef f():\n    return tempfile.mktemp()\n"}, []string{"sast:py/insecure-temp-file"}},
		{"py chmod 777 vs 600", map[string]string{"a.py": "import os\ndef f(p):\n    os.chmod(p, 0o777)\ndef g(p):\n    os.chmod(p, 0o600)\n"}, []string{"sast:py/world-writable"}},
		{"py jwt verify False", map[string]string{"a.py": "import jwt\ndef f(t):\n    return jwt.decode(t, verify=False)\n"}, []string{"sast:py/jwt-unverified"}},
		{"py xpath injection", map[string]string{"a.py": "from flask import request\nfrom lxml import etree\ndef f(doc):\n    return doc.xpath(\"//u[@n='\" + request.args['n'] + \"']\")\n"}, []string{"sast:py/xpath-injection"}},
		{"py regex injection and escape", map[string]string{"a.py": "import re\nfrom flask import request\ndef f(s):\n    return re.search(request.args['p'], s)\ndef g(s):\n    return re.search(re.escape(request.args['p']), s)\n"}, []string{"sast:py/regex-injection"}},
		{"py ssl CERT_NONE", map[string]string{"a.py": "import ssl\ndef f():\n    c = ssl.create_default_context()\n    c.check_hostname = False\n    c.verify_mode = ssl.CERT_NONE\n    return c\n"}, []string{"sast:py/tls-verification-disabled", "sast:py/tls-verification-disabled"}},

		// ---- JavaScript
		{"js md5 vs sha256", map[string]string{"a.js": "const crypto = require('crypto');\nfunction f(d){ return crypto.createHash('md5').update(d).digest('hex'); }\nfunction g(d){ return crypto.createHash('sha256').update(d).digest('hex'); }\n"}, []string{"sast:js/weak-crypto"}},
		{"js rejectUnauthorized false", map[string]string{"a.js": "const https = require('https');\nconst agent = new https.Agent({ rejectUnauthorized: false });\n"}, []string{"sast:js/tls-verification-disabled"}},
		{"js rejectUnauthorized true", map[string]string{"a.js": "const https = require('https');\nconst agent = new https.Agent({ rejectUnauthorized: true });\n"}, nil},
		{"js NODE_TLS_REJECT_UNAUTHORIZED", map[string]string{"a.js": "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"}, []string{"sast:js/tls-verification-disabled"}},
		{"js jwt.decode", map[string]string{"a.js": "const jwt = require('jsonwebtoken');\nfunction f(t){ return jwt.decode(t); }\nfunction g(t,k){ return jwt.verify(t,k); }\n"}, []string{"sast:js/jwt-unverified"}},
		{"js regex from request", map[string]string{"a.js": "app.get('/s',(req,res)=>{ const r = new RegExp(req.query.q); res.json(items.filter(i=>r.test(i))); });\n"}, []string{"sast:js/regex-injection"}},
		{"js escaped regex", map[string]string{"a.js": "const escape = require('escape-string-regexp');\napp.get('/s',(req,res)=>{ const r = new RegExp(escape(req.query.q)); res.json([]); });\n"}, nil},
		{"js jquery html", map[string]string{"a.js": "const q = new URLSearchParams(window.location.search).get('q');\n$('#out').html(q);\n"}, []string{"sast:js/xss"}},
		{"js jquery text is safe", map[string]string{"a.js": "const q = new URLSearchParams(window.location.search).get('q');\n$('#out').text(q);\n"}, nil},

		// ---- Java
		{"java MD5 vs SHA-256", map[string]string{"A.java": "import java.security.*;\npublic class A {\n  void f() throws Exception { MessageDigest.getInstance(\"MD5\"); }\n  void g() throws Exception { MessageDigest.getInstance(\"SHA-256\"); }\n}\n"}, []string{"sast:java/weak-crypto"}},
		{"java Cipher DES ECB and GCM", map[string]string{"A.java": "import javax.crypto.*;\npublic class A {\n  void f() throws Exception { Cipher.getInstance(\"DES/ECB/PKCS5Padding\"); }\n  void g() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); }\n  void h() throws Exception { Cipher.getInstance(\"AES\"); }\n}\n"}, []string{"sast:java/weak-crypto", "sast:java/weak-crypto"}},
		{"java cookie flags", map[string]string{"A.java": "import javax.servlet.http.*;\npublic class A {\n  void f(Cookie c) { c.setSecure(false); }\n  void g(Cookie c) { c.setSecure(true); }\n}\n"}, []string{"sast:java/insecure-cookie"}},
		{"java regex injection", map[string]string{"A.java": "import javax.servlet.http.*;\nimport java.util.regex.*;\npublic class A {\n  void f(HttpServletRequest req) { Pattern.compile(req.getParameter(\"p\")); }\n}\n"}, []string{"sast:java/regex-injection"}},
		{"java quoted regex is safe", map[string]string{"A.java": "import javax.servlet.http.*;\nimport java.util.regex.*;\npublic class A {\n  void f(HttpServletRequest req) { Pattern.compile(Pattern.quote(req.getParameter(\"p\"))); }\n}\n"}, nil},
		{"java ldap injection", map[string]string{"A.java": "import javax.servlet.http.*;\nimport javax.naming.directory.*;\npublic class A {\n  void f(HttpServletRequest req, DirContext ctx) throws Exception { ctx.search(\"ou=u\", \"(uid=\" + req.getParameter(\"u\") + \")\", null); }\n}\n"}, []string{"sast:java/ldap-injection"}},

		// ---- PHP
		{"php curl verifypeer false", map[string]string{"a.php": "<?php\ncurl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);\n"}, []string{"sast:php/tls-verification-disabled"}},
		{"php curl verifypeer true", map[string]string{"a.php": "<?php\ncurl_setopt($c, CURLOPT_SSL_VERIFYPEER, true);\n"}, nil},
		{"php extract", map[string]string{"a.php": "<?php\nextract($_POST);\n"}, []string{"sast:php/variable-extraction"}},
		{"php extract of a local array", map[string]string{"a.php": "<?php\n$row = ['a' => 1];\nextract($row);\n"}, nil},
		{"php ldap_search", map[string]string{"a.php": "<?php\n$r = ldap_search($c, 'dc=x', '(uid=' . $_GET['u'] . ')');\n"}, []string{"sast:php/ldap-injection"}},
		{"php ldap_escape", map[string]string{"a.php": "<?php\n$r = ldap_search($c, 'dc=x', '(uid=' . ldap_escape($_GET['u'], '', LDAP_ESCAPE_FILTER) . ')');\n"}, nil},
		{"php preg with request pattern", map[string]string{"a.php": "<?php\npreg_match($_GET['p'], $subject);\n"}, []string{"sast:php/regex-injection"}},

		// ---- Ruby
		{"ruby md5", map[string]string{"a.rb": "require 'digest'\ndef f(x)\n  Digest::MD5.hexdigest(x)\nend\ndef g(x)\n  Digest::SHA256.hexdigest(x)\nend\n"}, []string{"sast:rb/weak-crypto"}},
		{"ruby verify none", map[string]string{"a.rb": "require 'net/http'\nhttp = Net::HTTP.new('x', 443)\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"}, []string{"sast:rb/tls-verification-disabled"}},
		{"ruby permit!", map[string]string{"a.rb": "class C < ApplicationController\n  def create\n    User.create(params.permit!)\n  end\nend\n"}, []string{"sast:rb/mass-assignment"}},
		{"ruby csrf skipped", map[string]string{"a.rb": "class C < ApplicationController\n  skip_before_action :verify_authenticity_token\nend\n"}, []string{"sast:rb/csrf-disabled"}},
		{"ruby xpath", map[string]string{"a.rb": "class C < ApplicationController\n  def x\n    doc.xpath(\"//u[@n='#{params[:n]}']\")\n  end\nend\n"}, []string{"sast:rb/xpath-injection"}},
		{"ruby Regexp.new with escape", map[string]string{"a.rb": "class C < ApplicationController\n  def x\n    Regexp.new(Regexp.escape(params[:q]))\n  end\n  def y\n    Regexp.new(params[:q])\n  end\nend\n"}, []string{"sast:rb/regex-injection"}},

		// ---- Go
		{"go world-writable modes", map[string]string{"main.go": "package main\nimport \"os\"\nfunc a() { os.WriteFile(\"x\", nil, 0o666) }\nfunc b() { os.WriteFile(\"x\", nil, 0o600) }\nfunc c() { os.MkdirAll(\"d\", 0o777) }\n"}, []string{"sast:go/world-writable", "sast:go/world-writable"}},
		{"go old TLS minimum", map[string]string{"main.go": "package main\nimport \"crypto/tls\"\nfunc a() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS10} }\nfunc b() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }\n"}, []string{"sast:go/tls-verification-disabled"}},
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

func TestSecretsScanner(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"aws key in any file", map[string]string{"deploy.sh": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7ABCDEFG\n"}, []string{"sast:secrets/aws-access-key"}},
		{"AWS docs example key is ignored", map[string]string{"deploy.sh": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"}, nil},
		{"github token", map[string]string{"ci.yml.txt": "x", "script.py": "TOKEN = 'ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789" + "'\n"}, []string{"sast:secrets/github-token"}},
		{"private key block", map[string]string{"id_rsa.conf": "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"}, []string{"sast:secrets/private-key"}},
		{"keyed literal in config", map[string]string{"config.yaml": "database:\n  password: \"k7Hq9ZxP2mWv4Tn8Lr\"\n"}, []string{"sast:secrets/hardcoded-credential"}},
		{"env file bare value", map[string]string{".env": "API_SECRET=q8Zr4Lm2Vt9Xk7Pw3Nc\nPORT=8080\n"}, []string{"sast:secrets/hardcoded-credential"}},
		{"variable reference and placeholder are not secrets", map[string]string{"config.yaml": "password: ${DB_PASSWORD}\ntoken: your-token-here-please\nsecret: my_secret_name_value\n"}, nil},
		{"lockfile hashes are skipped", map[string]string{"package-lock.json": "{\"integrity\": \"sha512-q8Zr4Lm2Vt9Xk7Pw3Nc8Zr4Lm2Vt9Xk7Pw3Nc\"}\n"}, nil},
		{"markdown is skipped", map[string]string{"README.md": "password = 'k7Hq9ZxP2mWv4Tn8Lr'\n"}, nil},
		{"secret value is never printed", map[string]string{"a.env": "TOKEN=k7Hq9ZxP2mWv4Tn8LrXY\n"}, []string{"sast:secrets/hardcoded-credential"}},
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
