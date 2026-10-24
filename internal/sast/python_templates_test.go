package sast_test

import (
	"slices"
	"testing"
)

// Template engines escape output by default, so a request value passed to a
// render is only XSS where the template prints it raw: the safe/raw filter, or
// a script element, where HTML escaping does not make the value safe JavaScript.
// A render whose template name comes from request data executes that file's
// content as a template.
func TestPythonTemplateRenders(t *testing.T) {
	handler := func(args, body string) string {
		return `from flask import Flask, render_template, request
app = Flask(__name__)
@app.route("/lab")
def lab():
    ` + body + `
`
	}
	tests := []struct {
		name, app, template string
		want                []string
	}{
		{"safe filter output", handler("", `return render_template("lab.html", query=request.args.get("q"))`),
			"<h3>{{ query|safe }}</h3>\n", []string{"sast:py/xss", "sast:template/unescaped-output"}},
		{"escaped by default is safe", handler("", `return render_template("lab.html", query=request.args.get("q"))`),
			"<h3>{{ query }}</h3>\n", nil},
		{"escaped helper is safe", handler("import html\n", `return render_template("lab.html", query=html.escape(request.args.get("q")))`),
			"<h3>{{ query|safe }}</h3>\n", []string{"sast:template/unescaped-output"}},
		{"script output", handler("", `return render_template("lab.js.html", code=request.args.get("c"))`),
			"<pre>{{ code }}</pre>\n<script>\n{{ code }}\n</script>\n", []string{"sast:py/xss"}},
		{"tojson is safe in script", handler("", `return render_template("lab.js.html", code=request.args.get("c"))`),
			"<script>\nvar x = {{ code|tojson }};\n</script>\n", nil},
		{"constant render without context", handler("", `return render_template("lab.html")`),
			"<h3>{{ query|safe }}</h3>\n", []string{"sast:template/unescaped-output"}},
		{"template name from request data", `
from flask import Flask, render_template
app = Flask(__name__)
@app.route("/blog/<filename>")
def view(filename):
    return render_template(f"blogs/{filename}")
`, "", []string{"sast:py/code-injection"}},
		{"django template name from request data", `
from django.shortcuts import render
def view(request):
    return render(request, request.GET["page"])
`, "", []string{"sast:py/code-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": tt.app}
			if tt.template != "" {
				files["templates/lab.html"] = tt.template
				files["templates/lab.js.html"] = tt.template
			}
			got := slices.Compact(analyze(t, files))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
