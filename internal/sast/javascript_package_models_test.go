package sast_test

import (
	"slices"
	"testing"
)

func TestJavaScriptPackageModels(t *testing.T) {
	for _, tt := range []struct{ name, src, rule string }{
		{"extracted exec", `const run = require('child_process').exec; function route(req) { run(req.body.command) }`, "sast:js/command-injection"},
		{"node extracted exec", `const run = require('node:child_process').execSync; function route(req) { run(req.body.command) }`, "sast:js/command-injection"},
		{"extracted file read", `const read = require('fs').readFileSync; function route(req) { read(req.query.path) }`, "sast:js/path-traversal"},
		{"legacy math evaluation", `const math = require('mathjs'); function route(req) { return math.eval(req.body.expression) }`, "sast:js/code-injection"},
		{"md5 package alias", `const hash = require('md5'); function route(req) { return hash(req.body.password) }`, "sast:js/weak-crypto"},
		{"literal command", `const run = require('child_process').exec; run('date')`, ""},
		{"literal expression", `const math = require('mathjs'); math.eval('2+2')`, ""},
		{"unrelated eval method", `const math = {eval(x) { return x }}; function route(req) { return math.eval(req.body.expression) }`, ""},
		{"local md5 name", `function md5(x) { return x }; function route(req) { return md5(req.body.password) }`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{"app.js": tt.src}))
			var want []string
			if tt.rule != "" {
				want = []string{tt.rule}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
