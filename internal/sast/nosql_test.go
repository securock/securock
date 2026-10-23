package sast_test

import (
	"slices"
	"testing"
)

func TestNoSQLPrototypeAndZipSlip(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		// ---- NoSQL injection
		{"js login with request body objects", map[string]string{"a.js": "app.post('/login', async (req, res) => {\n  const u = await User.findOne({ name: req.body.name, pass: req.body.pass });\n  res.json(u);\n});\n"}, []string{"sast:js/nosql-injection"}},
		{"js query string object", map[string]string{"a.js": "app.get('/u', async (req, res) => {\n  res.json(await db.collection('u').find({ role: req.query.role }).toArray());\n});\n"}, []string{"sast:js/nosql-injection"}},
		{"js path parameter is always a string", map[string]string{"a.js": "app.get('/u/:id', async (req, res) => {\n  res.json(await User.findOne({ _id: req.params.id }));\n});\n"}, nil},
		{"js cast to string first", map[string]string{"a.js": "app.post('/login', async (req, res) => {\n  const u = await User.findOne({ name: String(req.body.name) });\n  res.json(u);\n});\n"}, nil},
		{"js lowercase array find is not a database", map[string]string{"a.js": "app.post('/f', (req, res) => {\n  const items = [1,2];\n  res.json(items.find(i => i === req.body.id));\n});\n"}, nil},
		{"py pymongo json body", map[string]string{"a.py": "from flask import request\ndef f(users):\n    return users.find_one({'name': request.json['name']})\n"}, []string{"sast:py/nosql-injection"}},
		{"py form field is a string", map[string]string{"a.py": "from flask import request\ndef f(users):\n    return users.find_one({'name': request.form['name']})\n"}, nil},
		{"php array from the request", map[string]string{"a.php": "<?php\n$u = $collection->findOne(['user' => $_POST['user'], 'pass' => $_POST['pass']]);\n"}, []string{"sast:php/nosql-injection"}},
		{"java parse of request text", map[string]string{"A.java": "import javax.servlet.http.*;\nimport org.bson.Document;\npublic class A {\n  void f(HttpServletRequest req) { Document.parse(req.getParameter(\"q\")); }\n}\n"}, []string{"sast:java/nosql-injection"}},

		// ---- Prototype pollution
		{"js lodash merge of the body", map[string]string{"a.js": "const _ = require('lodash');\napp.post('/s', (req, res) => {\n  const cfg = _.merge({}, req.body);\n  res.json(cfg);\n});\n"}, []string{"sast:js/prototype-pollution"}},
		{"js named import of merge", map[string]string{"a.ts": "import { merge } from 'lodash';\nexport function h(req: any) { return merge({}, req.body); }\n"}, []string{"sast:js/prototype-pollution"}},
		{"js lodash set with request path", map[string]string{"a.js": "const _ = require('lodash');\napp.post('/s', (req, res) => {\n  _.set(settings, req.body.path, req.body.value);\n});\n"}, []string{"sast:js/prototype-pollution"}},
		{"js merge of trusted objects", map[string]string{"a.js": "const _ = require('lodash');\nconst cfg = _.merge({}, defaults, overrides);\n"}, nil},
		{"js nested index assignment", map[string]string{"a.js": "app.post('/s', (req, res) => {\n  const [a, b] = req.body.path.split('.');\n  store[a][b] = req.body.value;\n});\n"}, []string{"sast:js/prototype-pollution"}},
		{"js single index assignment only changes one object", map[string]string{"a.js": "app.post('/s', (req, res) => {\n  store[req.body.key] = req.body.value;\n});\n"}, nil},
		{"js jquery deep extend", map[string]string{"a.js": "app.post('/s', (req, res) => { $.extend(true, {}, req.body); });\n"}, []string{"sast:js/prototype-pollution"}},

		// ---- Zip slip
		{"go zip entry name joined and written", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"os\"\n\t\"path/filepath\"\n)\nfunc unzip(r *zip.Reader, dest string) {\n\tfor _, f := range r.File {\n\t\tp := filepath.Join(dest, f.Name)\n\t\tos.MkdirAll(p, 0o755)\n\t}\n}\n"}, []string{"sast:go/path-traversal"}},
		{"go zip with a prefix check after Join", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\nfunc unzip(r *zip.Reader, dest string) {\n\tfor _, f := range r.File {\n\t\tp := filepath.Join(dest, f.Name)\n\t\tif !strings.HasPrefix(p, filepath.Clean(dest)+string(os.PathSeparator)) {\n\t\t\tcontinue\n\t\t}\n\t\tos.MkdirAll(p, 0o755)\n\t}\n}\n"}, nil},
		{"go prefix check on an uncleaned concatenation is not trusted", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"os\"\n\t\"strings\"\n)\nfunc unzip(r *zip.Reader, dest string) {\n\tfor _, f := range r.File {\n\t\tp := dest + \"/\" + f.Name\n\t\tif !strings.HasPrefix(p, dest) {\n\t\t\tcontinue\n\t\t}\n\t\tos.MkdirAll(p, 0o755)\n\t}\n}\n"}, []string{"sast:go/path-traversal"}},
		{"go zip with IsLocal", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"os\"\n\t\"path/filepath\"\n)\nfunc unzip(r *zip.Reader, dest string) {\n\tfor _, f := range r.File {\n\t\tif !filepath.IsLocal(f.Name) {\n\t\t\tcontinue\n\t\t}\n\t\tos.MkdirAll(filepath.Join(dest, f.Name), 0o755)\n\t}\n}\n"}, nil},
		{"go zip with a dotdot check", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"os\"\n\t\"path/filepath\"\n\t\"strings\"\n)\nfunc unzip(r *zip.Reader, dest string) {\n\tfor _, f := range r.File {\n\t\tif strings.Contains(f.Name, \"..\") {\n\t\t\tcontinue\n\t\t}\n\t\tos.MkdirAll(filepath.Join(dest, f.Name), 0o755)\n\t}\n}\n"}, nil},
		{"go zip entry name only logged", map[string]string{"main.go": "package main\nimport (\n\t\"archive/zip\"\n\t\"fmt\"\n)\nfunc list(r *zip.Reader) {\n\tfor _, f := range r.File {\n\t\tfmt.Println(f.Name)\n\t}\n}\n"}, nil},
		{"go tar header name", map[string]string{"main.go": "package main\nimport (\n\t\"archive/tar\"\n\t\"os\"\n\t\"path/filepath\"\n)\nfunc untar(tr *tar.Reader, dest string) {\n\th, _ := tr.Next()\n\tos.Create(filepath.Join(dest, h.Name))\n}\n"}, []string{"sast:go/path-traversal"}},
		{"py tar extractall without a filter", map[string]string{"a.py": "import tarfile\ndef f(p, d):\n    tar = tarfile.open(p)\n    tar.extractall(d)\n"}, []string{"sast:py/zip-slip"}},
		{"py tar extractall with filter", map[string]string{"a.py": "import tarfile\ndef f(p, d):\n    tar = tarfile.open(p)\n    tar.extractall(d, filter='data')\n"}, nil},
		{"py zip names joined", map[string]string{"a.py": "import os, zipfile\ndef f(p, d):\n    with zipfile.ZipFile(p) as z:\n        for n in z.namelist():\n            open(os.path.join(d, n), 'wb').write(z.read(n))\n"}, []string{"sast:py/path-traversal"}},
		{"py prefix without directory boundary is unsafe", map[string]string{"a.py": "import os, zipfile\ndef f(p, d):\n    with zipfile.ZipFile(p) as z:\n        for n in z.namelist():\n            t = os.path.realpath(os.path.join(d, n))\n            if not t.startswith(os.path.realpath(d)):\n                raise ValueError(n)\n            open(t, 'wb').write(z.read(n))\n"}, []string{"sast:py/path-traversal"}},
		{"py zip names checked with boundary", map[string]string{"a.py": "import os, zipfile\ndef f(p, d):\n    with zipfile.ZipFile(p) as z:\n        for n in z.namelist():\n            t = os.path.realpath(os.path.join(d, n))\n            if not t.startswith(os.path.realpath(d) + os.sep):\n                raise ValueError(n)\n            open(t, 'wb').write(z.read(n))\n"}, nil},
		{"java zip entry", map[string]string{"A.java": "import java.io.*;\nimport java.util.zip.*;\npublic class A {\n  void f(ZipInputStream zis, File dest) throws Exception {\n    ZipEntry e;\n    while ((e = zis.getNextEntry()) != null) {\n      File out = new File(dest, e.getName());\n      new FileOutputStream(out);\n    }\n  }\n}\n"}, []string{"sast:java/path-traversal"}},
		{"java prefix without directory boundary is unsafe", map[string]string{"A.java": "import java.io.*;\nimport java.util.zip.*;\npublic class A {\n  void f(ZipInputStream zis, File dest) throws Exception {\n    ZipEntry e;\n    while ((e = zis.getNextEntry()) != null) {\n      File out = new File(dest, e.getName());\n      if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath())) { throw new IOException(\"bad\"); }\n      new FileOutputStream(out);\n    }\n  }\n}\n"}, []string{"sast:java/path-traversal"}},
		{"java canonical path with boundary", map[string]string{"A.java": "import java.io.*;\nimport java.util.zip.*;\npublic class A {\n  void f(ZipInputStream zis, File dest) throws Exception {\n    ZipEntry e;\n    while ((e = zis.getNextEntry()) != null) {\n      File out = new File(dest, e.getName());\n      if (!out.getCanonicalPath().startsWith(dest.getCanonicalPath() + File.separator)) { throw new IOException(\"bad\"); }\n      new FileOutputStream(out);\n    }\n  }\n}\n"}, nil},
		{"js unzipper entry", map[string]string{"a.js": "const fs = require('fs');\nconst path = require('path');\nfunction x(entry, dest) {\n  entry.pipe(fs.createWriteStream(path.join(dest, entry.path)));\n}\n"}, []string{"sast:js/path-traversal"}},
		{"js prefix without directory boundary is unsafe", map[string]string{"a.js": "const fs = require('fs');\nconst path = require('path');\nfunction x(entry, dest) {\n  const p = path.resolve(dest, entry.path);\n  if (!p.startsWith(dest)) { throw new Error('bad'); }\n  entry.pipe(fs.createWriteStream(p));\n}\n"}, []string{"sast:js/path-traversal"}},
		{"js entry path checked with boundary", map[string]string{"a.js": "const fs = require('fs');\nconst path = require('path');\nfunction x(entry, dest) {\n  const p = path.resolve(dest, entry.path);\n  if (!p.startsWith(path.resolve(dest) + path.sep)) { throw new Error('bad'); }\n  entry.pipe(fs.createWriteStream(p));\n}\n"}, nil},
		{"ruby tar entry", map[string]string{"a.rb": "def x(tar, dest)\n  tar.each do |entry|\n    File.write(File.join(dest, entry.full_name), entry.read)\n  end\nend\n"}, []string{"sast:rb/path-traversal"}},
		{"php zip name index", map[string]string{"a.php": "<?php\n$zip = new ZipArchive();\nfor ($i = 0; $i < $zip->numFiles; $i++) {\n  file_put_contents('/srv/' . $zip->getNameIndex($i), $zip->getFromIndex($i));\n}\n"}, []string{"sast:php/path-traversal"}},
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

func TestGoUnresolvedPackageStillMatchesSinks(t *testing.T) {
	// go.mongodb.org/mongo-driver is not available, so Collection's methods cannot be
	// resolved by type. The call is still named from the type as it was written.
	got := analyze(t, map[string]string{"main.go": "package main\nimport (\n\t\"encoding/json\"\n\t\"net/http\"\n\t\"go.mongodb.org/mongo-driver/bson\"\n\t\"go.mongodb.org/mongo-driver/mongo\"\n)\nfunc h(c *mongo.Collection, r *http.Request) {\n\tvar f bson.M\n\tjson.NewDecoder(r.Body).Decode(&f)\n\tc.FindOne(r.Context(), f)\n}\n"})
	if !slices.Equal(got, []string{"sast:go/nosql-injection"}) {
		t.Fatalf("got %v", got)
	}
	got = analyze(t, map[string]string{"main.go": "package main\nimport (\n\t\"net/http\"\n\t\"go.mongodb.org/mongo-driver/bson\"\n\t\"go.mongodb.org/mongo-driver/mongo\"\n)\nfunc h(c *mongo.Collection, r *http.Request) {\n\tc.FindOne(r.Context(), bson.M{\"name\": r.FormValue(\"n\")})\n}\n"})
	if len(got) != 0 {
		t.Fatalf("a form value is always a string: got %v", got)
	}
}
