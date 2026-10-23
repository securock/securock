package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Template engines escape output by default, and each has a spelling that turns it off.
// Controllers can look clean while the template prints their data raw, so the template is
// checked on its own. These are patterns, not dataflow: a raw print of a constant is not
// reported, a raw print of anything else is.

type templatePattern struct {
	re     *regexp.Regexp
	engine string
	// exts limits the pattern to these file endings; empty means every template.
	exts []string
}

var templatePatterns = []templatePattern{
	{re: regexp.MustCompile(`\{\{[^}]*?\|\s*safe\b`), engine: "Jinja2/Django/Nunjucks |safe"},
	{re: regexp.MustCompile(`\{\{[^}]*?\|\s*raw\b`), engine: "Twig/Nunjucks |raw"},
	{re: regexp.MustCompile(`\{%-?\s*autoescape\s+(?:off|false)\b`), engine: "autoescape off"},
	{re: regexp.MustCompile(`<%-[^-%]`), engine: "EJS <%- unescaped"},
	{re: regexp.MustCompile(`\{\{\{[^}]+\}\}\}`), engine: "Handlebars {{{ }}} unescaped"},
	{re: regexp.MustCompile(`\{\{&\s*[^}]+\}\}`), engine: "Mustache {{& }} unescaped"},
	{re: regexp.MustCompile(`\{!!\s*[^!]+!!\}`), engine: "Blade {!! !!} unescaped"},
	{re: regexp.MustCompile(`<%==\s*[^%]`), engine: "ERB <%== unescaped"},
	{re: regexp.MustCompile(`<%=\s*raw[ (]`), engine: "ERB raw"},
	{re: regexp.MustCompile(`<%=[^%]*\.html_safe\b`), engine: "ERB html_safe"},
	{re: regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_.#-]*\s*!=\s*\S`), engine: "Pug != unescaped", exts: []string{".pug", ".jade"}},
	{re: regexp.MustCompile(`!\{[^}]+\}`), engine: "Pug !{ } unescaped", exts: []string{".pug", ".jade"}},
	{re: regexp.MustCompile(`@Html\.Raw\(\s*[^")\s]`), engine: "Razor @Html.Raw", exts: []string{".cshtml", ".razor"}},
	{re: regexp.MustCompile(`@\(?\(?(?:new\s+)?(?:Html|Mvc)String\(`), engine: "Razor HtmlString", exts: []string{".cshtml", ".razor"}},
	{re: regexp.MustCompile(`<%=\s*[^%]`), engine: "ASP.NET <%= unencoded", exts: []string{".aspx", ".ascx", ".master"}},
	{re: regexp.MustCompile(`\(MarkupString\)`), engine: "Blazor MarkupString", exts: []string{".razor"}},
	{re: regexp.MustCompile(`\bv-html\s*=`), engine: "Vue v-html"},
	{re: regexp.MustCompile(`\[innerHTML\]\s*=`), engine: "Angular [innerHTML]"},
}

// constantOutput matches a raw print whose expression is a plain string literal.
var constantOutput = regexp.MustCompile(`(\{\{|<%-|<%==|\{\{\{|\{!!)\s*['"][^'"]*['"]\s*(\|\s*(safe|raw))?\s*(\}\}|%>|\}\}\}|!!\})`)

func hasSuffixAny(name string, suffixes []string) bool {
	low := strings.ToLower(name)
	for _, s := range suffixes {
		if strings.HasSuffix(low, s) {
			return true
		}
	}
	return false
}

// harmlessRaw removes raw prints that cannot carry markup an attacker chose: a quoted
// literal marked safe, an inspected (quoted) value, and a CSRF token the framework made.
var harmlessRaw = regexp.MustCompile(`'[^']*'\.html_safe|"[^"#]*"\.html_safe|\.inspect\.html_safe|csrf[_a-z]*\s*\|\s*safe`)

func isTemplate(name string) bool {
	low := strings.ToLower(name)
	for _, suf := range []string{".html", ".htm", ".jinja", ".jinja2", ".j2", ".njk", ".twig", ".ejs", ".hbs", ".handlebars", ".mustache", ".erb", ".blade.php", ".pug", ".jade", ".vue", ".swig", ".cshtml", ".razor", ".aspx", ".ascx", ".master"} {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

func scanTemplate(root, full, rel string) []finding.Finding {
	st, err := os.Stat(full)
	if err != nil || st.Size() == 0 || st.Size() > 512<<10 {
		return nil
	}
	src, err := os.ReadFile(full)
	if err != nil {
		return nil
	}
	rel = filepath.ToSlash(rel)
	var out []finding.Finding
	seen := map[int]bool{}
	for i, line := range strings.Split(string(src), "\n") {
		if len(line) > 4000 || constantOutput.MatchString(line) {
			continue
		}
		line = harmlessRaw.ReplaceAllString(line, "")
		for _, p := range templatePatterns {
			if len(p.exts) > 0 && !hasSuffixAny(rel, p.exts) {
				continue
			}
			if p.re.MatchString(line) && !seen[i] {
				seen[i] = true
				out = append(out, finding.Finding{
					ID:          "sast:template/unescaped-output",
					Severity:    finding.SeverityLow,
					Title:       "Template prints a value without HTML escaping (CWE-79)",
					Detail:      p.engine + ": anything that reaches this expression is written to the page as markup",
					Subject:     rel + "#" + p.engine,
					Remediation: "Remove the raw/safe marker so the engine escapes the value, or sanitize it with an HTML sanitizer before it is marked safe.",
					Location:    &finding.Location{File: rel, Line: i + 1},
				})
			}
		}
	}
	return out
}
