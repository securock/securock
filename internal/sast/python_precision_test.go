package sast_test

import (
	"slices"
	"strings"
	"testing"
)

func TestPythonQuotedCodeGuard(t *testing.T) {
	guard := `if not value.startswith("'") or not value.endswith("'") or "'" in value[1:-1]:
        return`
	for _, tt := range []struct {
		name, check, after string
		want               []string
	}{
		{"eval literal", guard, "eval(value)", nil},
		{"exec literal", guard, "exec(value)", nil},
		{"double quoted literal", `if not value.startswith('"') or not value.endswith('"') or '"' in value[1:-1]:
        return`, "eval(value)", nil},
		{"positive conjunction", `if value.startswith("'") and value.endswith("'") and "'" not in value[1:-1]:
        eval(value)`, "", nil},
		{"unguarded", "", "eval(value)", []string{"sast:py/code-injection"}},
		{"no interior check", `if not value.startswith("'") or not value.endswith("'"):
        return`, "eval(value)", []string{"sast:py/code-injection"}},
		{"no prefix check", `if not value.endswith("'") or "'" in value[1:-1]:
        return`, "eval(value)", []string{"sast:py/code-injection"}},
		{"no suffix check", `if not value.startswith("'") or "'" in value[1:-1]:
        return`, "eval(value)", []string{"sast:py/code-injection"}},
		{"different quotes", strings.Replace(guard, `endswith("'")`, `endswith('"')`, 1), "eval(value)", []string{"sast:py/code-injection"}},
		{"different variable", strings.Replace(guard, "value.endswith", "other.endswith", 1), "eval(value)", []string{"sast:py/code-injection"}},
		{"incomplete interior slice", strings.Replace(guard, "[1:-1]", "[2:-1]", 1), "eval(value)", []string{"sast:py/code-injection"}},
		{"slice with step", strings.Replace(guard, "[1:-1]", "[1:-1:2]", 1), "eval(value)", []string{"sast:py/code-injection"}},
		{"nonterminating rejection", strings.Replace(guard, "return", "print('invalid')", 1), "eval(value)", []string{"sast:py/code-injection"}},
		{"reassignment", guard, "value = request.args['other']\n    exec(value)", []string{"sast:py/code-injection"}},
		{"reassignment in try", guard, "try:\n        value = request.args['other']\n    except ValueError:\n        pass\n    eval(value)", []string{"sast:py/code-injection"}},
		{"unknown transformation", guard, "eval(transform(value))", []string{"sast:py/code-injection"}},
		{"only one validated branch", "if other:\n        " + strings.ReplaceAll(guard, "\n", "\n    "), "eval(value)", []string{"sast:py/code-injection"}},
		{"literal is not template safety", guard, "render_template_string(value)", []string{"sast:py/code-injection"}},
		{"literal is not sql safety", guard, "db.execute(value)", []string{"sast:py/sql-injection"}},
		{"literal is not shell safety", guard, "os.system(value)", []string{"sast:py/command-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from flask import request, render_template_string\nimport os\ndef route(db, other):\n    value = request.args['code']\n    " + tt.check + "\n    " + tt.after + "\n"
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonParsedRedirectGuard(t *testing.T) {
	check := "parsed = parse(value)\n    if parsed.netloc not in ['example.com'] or parsed.scheme != 'https':\n        return"
	tryCheck := "try:\n        parsed = parse(value)\n        if parsed.netloc not in ['example.com'] or parsed.scheme != 'https':\n            return\n    except ValueError:\n        return"
	for _, tt := range []struct {
		name, check, after string
		want               []string
	}{
		{"exact host and scheme", check, "redirect(value)", nil},
		{"urlsplit alias", strings.Replace(check, "parse(value)", "split(value)", 1), "redirect(value)", nil},
		{"local host list", "allowed = ['example.com']\n    " + strings.Replace(check, "['example.com']", "allowed", 1), "redirect(value)", nil},
		{"exception returns", tryCheck, "redirect(value)", nil},
		{"positive conjunction", "parsed = parse(value)\n    if parsed.netloc in ['example.com'] and parsed.scheme == 'https':\n        redirect(value)", "", nil},
		{"parsing alone", "parsed = parse(value)", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"scheme alone", "parsed = parse(value)\n    if parsed.scheme != 'https':\n        return", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"host alone", "parsed = parse(value)\n    if parsed.netloc not in ['example.com']:\n        return", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"hostname ignores userinfo", strings.Replace(check, ".netloc", ".hostname", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"untrusted hosts", strings.Replace(check, "['example.com']", "request.args['hosts']", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"mutated host list", "allowed = ['example.com']\n    allowed[0] = request.args['host']\n    " + strings.Replace(check, "['example.com']", "allowed", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"prefix host", "parsed = parse(value)\n    if not parsed.netloc.startswith('example.com') or parsed.scheme != 'https':\n        return", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"different parsed values", "other = parse(request.args['other'])\n    " + strings.Replace(check, "parsed.scheme", "other.scheme", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"different source", strings.Replace(check, "parse(value)", "parse(other)", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"source reassigned before guard", strings.Replace(check, "\n    if", "\n    value = request.args['other']\n    if", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"source reassigned after guard", check, "value = request.args['other']\n    redirect(value)", []string{"sast:py/open-redirect"}},
		{"source reassigned in try after guard", check, "try:\n        value = request.args['other']\n    except ValueError:\n        pass\n    redirect(value)", []string{"sast:py/open-redirect"}},
		{"parsed value reassigned", strings.Replace(check, "\n    if", "\n    parsed = unknown()\n    if", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"parse alias reassigned", "parse = unknown\n    " + check, "redirect(value)", []string{"sast:py/open-redirect"}},
		{"source reassigned in a branch", strings.Replace(check, "\n    if", "\n    if other:\n        value = request.args['other']\n    if", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"parse in only one branch", "if other:\n        parsed = parse(value)\n    if parsed.netloc not in ['example.com'] or parsed.scheme != 'https':\n        return", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"nonterminating rejection", strings.Replace(check, "return", "print('invalid')", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"exception falls through", strings.Replace(tryCheck, "except ValueError:\n        return", "except ValueError:\n        pass", 1), "redirect(value)", []string{"sast:py/open-redirect"}},
		{"finally reassigns", tryCheck + "\n    finally:\n        value = request.args['other']", "redirect(value)", []string{"sast:py/open-redirect"}},
		{"unknown transformation", check, "redirect(transform(value))", []string{"sast:py/open-redirect"}},
		{"not sql safety", check, "db.execute(value)", []string{"sast:py/sql-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from flask import request, redirect\nfrom urllib.parse import urlparse as parse, urlsplit as split\ndef route(db, other):\n    value = request.args['next']\n    " + tt.check + "\n    " + tt.after + "\n"
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
