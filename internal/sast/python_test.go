package sast_test

import (
	"slices"
	"testing"
)

func TestPython(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"flask sql concat", map[string]string{"app.py": `
from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.route("/u")
def u():
    conn = sqlite3.connect("x.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + request.args.get("id"))
`}, []string{"sast:py/sql-injection"}},
		{"parameterized is safe", map[string]string{"app.py": `
from flask import request
def u(cur):
    cur.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),))
`}, nil},
		{"f-string and format", map[string]string{"app.py": `
from flask import request
def a(cur):
    q = request.form["q"]
    cur.execute(f"SELECT {q}")
def b(cur):
    cur.execute("SELECT {}".format(request.form["q"]))
def c(cur):
    cur.execute("SELECT %s" % request.form["q"])
`}, []string{"sast:py/sql-injection"}},
		{"os.system", map[string]string{"app.py": `
import os
from flask import request
def ping():
    os.system("ping -c 1 " + request.args["host"])
`}, []string{"sast:py/command-injection"}},
		{"subprocess shell=True vs list", map[string]string{"a.py": `
import subprocess
from flask import request
def bad():
    subprocess.run("ls " + request.args["d"], shell=True)
`, "b.py": `
import subprocess
from flask import request
def ok():
    subprocess.run(["ls", request.args["d"]])
`}, []string{"sast:py/command-injection"}},
		{"shlex.quote sanitizes", map[string]string{"app.py": `
import os, shlex
from flask import request
def ping():
    os.system("ping " + shlex.quote(request.args["host"]))
`}, nil},
		{"django request", map[string]string{"views.py": `
from django.http import HttpResponse
def v(request):
    name = request.GET.get("name")
    return HttpResponse("<h1>" + name + "</h1>")
`}, []string{"sast:py/xss"}},
		{"django raw sql", map[string]string{"views.py": `
def v(request):
    return User.objects.raw("SELECT * FROM u WHERE n = '%s'" % request.POST["n"])
`}, []string{"sast:py/sql-injection"}},
		{"path traversal open", map[string]string{"app.py": `
from flask import request
def f():
    with open("/srv/" + request.args["f"]) as fh:
        return fh.read()
`}, []string{"sast:py/path-traversal"}},
		{"secure_filename sanitizes", map[string]string{"app.py": `
from flask import request
from werkzeug.utils import secure_filename
def f():
    with open("/srv/" + secure_filename(request.args["f"])) as fh:
        return fh.read()
`}, nil},
		{"ssrf requests", map[string]string{"app.py": `
import requests
from flask import request
def p():
    return requests.get(request.args["url"]).text
`}, []string{"sast:py/ssrf"}},
		{"pickle", map[string]string{"app.py": `
import pickle
from flask import request
def l():
    return pickle.loads(request.data)
`}, []string{"sast:py/insecure-deserialization"}},
		{"eval", map[string]string{"app.py": `
from flask import request
def e():
    return eval(request.args["x"])
`}, []string{"sast:py/code-injection"}},
		{"int sanitizes", map[string]string{"app.py": `
from flask import request
def u(cur):
    i = int(request.args["id"])
    cur.execute("SELECT * FROM t WHERE id = " + str(i))
`}, nil},
		{"fastapi route params are sources", map[string]string{"main.py": `
from fastapi import FastAPI
app = FastAPI()
@app.get("/items/{name}")
def read(name: str, db):
    db.execute("SELECT * FROM items WHERE name = '" + name + "'")
`}, []string{"sast:py/sql-injection"}},
		{"non-route function parameter is not a source", map[string]string{"util.py": `
def read(name, db):
    db.execute("SELECT * FROM items WHERE name = '" + name + "'")
`}, nil},
		{"allowlist guard", map[string]string{"app.py": `
from flask import request
ALLOWED = {"name", "age"}
def u(cur):
    col = request.args["sort"]
    if col not in ALLOWED:
        return "bad"
    cur.execute("SELECT * FROM t ORDER BY " + col)
`}, nil},
		{"across files", map[string]string{"views.py": `
from flask import request
from .repo import find
def v():
    return find(request.args["n"])
`, "repo.py": `
def find(name):
    return cursor.execute("SELECT * FROM u WHERE n = '" + name + "'")
`}, []string{"sast:py/sql-injection"}},
		{"class method via self", map[string]string{"svc.py": `
from flask import request
class Svc:
    def run(self):
        return self.find(request.args["n"])
    def find(self, name):
        return self.db.execute("SELECT '" + name + "'")
`}, []string{"sast:py/sql-injection"}},
		{"redirect", map[string]string{"app.py": `
from flask import redirect, request
def go():
    return redirect(request.args["next"])
`}, []string{"sast:py/open-redirect"}},
		{"unpacking and loops", map[string]string{"app.py": `
from flask import request
def u(cur):
    a, b = request.args["a"], 1
    for item in [a]:
        cur.execute("SELECT " + item)
`}, []string{"sast:py/sql-injection"}},
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
