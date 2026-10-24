package sast_test

import (
	"slices"
	"testing"
)

// The installed packages a repository ships are analyzed too: a helper in a
// vendored package is followed into the API it calls, and a package that
// sanitizes its input is believed when it does.
func TestVendoredPackages(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"vendored helper reaches the database", map[string]string{
			"app.py": `from flask import request
import db
def route(cur):
    db.run(cur, request.args["q"])
`,
			"vendor/db/__init__.py": `def run(cur, sql):
    cur.execute(sql)
`,
		}, []string{"sast:py/sql-injection"}},
		{"vendored package reached through a re-export", map[string]string{
			"app.py": `from flask import request
import pkg
def route(cur):
    pkg.run(cur, request.args["q"])
`,
			"vendor/pkg/__init__.py": "from .impl import run\n",
			"vendor/pkg/impl.py": `def run(cur, sql):
    cur.execute(sql)
`,
		}, []string{"sast:py/sql-injection"}},
		{"vendored helper that escapes its input", map[string]string{
			"app.py": `from flask import render_template, request
import safe
def route():
    return render_template("t.html", q=safe.esc(request.args["q"]))
`,
			"vendor/safe/__init__.py": `import html
def esc(value):
    return html.escape(value)
`,
			"templates/t.html": "<h3>{{ q|safe }}</h3>\n",
		}, []string{"sast:template/unescaped-output"}},
		{"vendored package findings are not reported", map[string]string{
			"app.py": `def route():
    return "ok"
`,
			"vendor/risky/__init__.py": `CONFIG = "user input"
def go():
    eval(CONFIG)
`,
		}, nil},
		{"installed package is not project code", map[string]string{
			"app.py": `from flask import request
def route():
    return request.args["q"]
`,
			"vendor/pkg/__init__.py": "def helper():\n    return 1\n",
		}, nil},
		{"installed javascript package", map[string]string{
			"app.js": `const { run } = require('pkg')
const db = require('db')
function route(req) {
  run(db, req.query.q)
}
`,
			"node_modules/pkg/index.js": `function run(conn, sql) {
  conn.query(sql)
}
`,
		}, []string{"sast:js/sql-injection"}},
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

// The same project must produce the same report every time, with the
// installed packages included.
func TestVendoredPackagesAreDeterministic(t *testing.T) {
	files := map[string]string{
		"app.py": `from flask import request
import db
import safe
def route(cur):
    db.run(cur, request.args["q"])
    safe.esc(request.args["q"])
`,
		"vendor/db/__init__.py": `def run(cur, sql):
    cur.execute(sql)
`,
		"vendor/safe/__init__.py": `import html
def esc(value):
    return html.escape(value)
`,
	}
	first := analyze(t, files)
	for range 3 {
		if got := analyze(t, files); !slices.Equal(got, first) {
			t.Fatalf("%v != %v", got, first)
		}
	}
}
