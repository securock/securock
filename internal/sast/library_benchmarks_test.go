package sast_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/securock/securock/internal/sast"
)

// The installed packages a repository ships are analyzed too, so a helper in a
// vendored package is followed into the API it calls. These cases are
// hand-reviewed: each one is a small project with a package it imports, and
// the expected rule for the case.
func TestVendoredPackageCases(t *testing.T) {
	type libraryCase struct {
		name, rule string
		files      map[string]string
		vulnerable bool
	}
	cases := []libraryCase{
		{"package that executes a query", "sql-injection", map[string]string{
			"app.py": `from flask import request
import db
def route(cur):
    db.run(cur, request.args["q"])
`,
			"vendor/db/__init__.py": `def run(cur, sql):
    cur.execute(sql)
`,
		}, true},
		{"package that runs a command", "command-injection", map[string]string{
			"app.py": `from flask import request
import sh
def route():
    sh.run(request.args["cmd"])
`,
			"vendor/sh/__init__.py": `import os
def run(cmd):
    os.system(cmd)
`,
		}, true},
		{"package that opens a file", "path-traversal", map[string]string{
			"app.py": `from flask import request
import fs
def route():
    fs.read("/srv", request.args["f"])
`,
			"vendor/fs/__init__.py": `import os
def read(base, name):
    return open(os.path.join(base, name)).read()
`,
		}, true},
		{"package that re-exports the helper", "sql-injection", map[string]string{
			"app.py": `from flask import request
import pkg
def route(cur):
    pkg.run(cur, request.args["q"])
`,
			"vendor/pkg/__init__.py": "from .impl import run\n",
			"vendor/pkg/impl.py": `def run(cur, sql):
    cur.execute(sql)
`,
		}, true},
		{"package that escapes its input", "xss", map[string]string{
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
		}, false},
		{"package that parameterizes the query", "sql-injection", map[string]string{
			"app.py": `from flask import request
import db
def route(cur):
    db.run(cur, "SELECT * FROM t WHERE n = ?", (request.args["q"],))
`,
			"vendor/db/__init__.py": `def run(cur, sql, params):
    cur.execute(sql, params)
`,
		}, false},
		{"package with a vulnerability of its own", "code-injection", map[string]string{
			"app.py": `def route():
    return "ok"
`,
			"vendor/risky/__init__.py": `CONFIG = "user input"
def go():
    eval(CONFIG)
`,
		}, false},
	}
	tp, fp, tn := 0, 0, 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, src := range c.files {
				path := dir + "/" + name
				if err := writeFile(path, src); err != nil {
					t.Fatal(err)
				}
			}
			found, err := sast.Analyze(dir)
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			for _, f := range found {
				if f.ID == "sast:py/"+c.rule {
					hit = true
				}
				if f.ID == "sast:analysis-incomplete" {
					t.Errorf("analysis incomplete: %v", f.Location)
				}
			}
			switch {
			case c.vulnerable && hit:
				tp++
			case c.vulnerable:
				t.Errorf("lost detection: %s (%s)", c.name, c.rule)
			case hit:
				fp++
				t.Errorf("false positive: %s (%s)", c.name, c.rule)
			default:
				tn++
			}
		})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-10s %4s %4s %4s\n", "category", "TP", "FP", "TN")
	fmt.Fprintf(&b, "%-10s %4d %4d %4d\n", "vendored", tp, fp, tn)
	t.Log(b.String())
}

// writeFile writes a file of a test project, creating its directory.
func writeFile(path, src string) error {
	if i := strings.LastIndex(path, "/"); i > 0 {
		if err := os.MkdirAll(path[:i], 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(src), 0o644)
}
