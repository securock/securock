package sast_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"github.com/securock/securock/schemas"
)

func writeDataflowFiles(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDataflowTraceAndDeterminism(t *testing.T) {
	dir := writeDataflowFiles(t, map[string]string{
		"helper.js": "export function setQuery(box,x) { const alias=box; alias.query=x; }\n",
		"route.js":  "import { setQuery } from './helper.js';\napp.get('/', (req,res) => { const box={}; setQuery(box,req.query.q); db.query('SELECT '+box.query); });\n",
	})
	var previous []finding.Finding
	for i := range 5 {
		found, err := sast.Analyze(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].ID != "sast:js/sql-injection" {
			t.Fatalf("unexpected findings: %+v", found)
		}
		if i > 0 && !reflect.DeepEqual(previous, found) {
			t.Fatal("analysis is not deterministic")
		}
		previous = found
		f := found[0]
		if f.Location.File != "route.js" || f.Location.Line != 2 {
			t.Fatalf("wrong sink location: %+v", f.Location)
		}
		var messages []string
		for _, step := range f.Trace {
			if filepath.IsAbs(step.File) || step.Line < 1 {
				t.Fatalf("invalid trace location: %+v", step)
			}
			messages = append(messages, step.Message)
		}
		trace := strings.Join(messages, "\n")
		if !strings.Contains(trace, "untrusted data:") || !strings.Contains(trace, "written by setQuery") || !strings.Contains(trace, "reaches") {
			t.Fatalf("missing source, effect or sink: %s", trace)
		}
		var buf bytes.Buffer
		report := finding.New("sast", found)
		if err := finding.Write(&buf, report, "json"); err != nil {
			t.Fatal(err)
		}
		if err := schemas.Validate("sast-report.schema.json", buf.Bytes()); err != nil {
			t.Fatal(err)
		}
		buf.Reset()
		if err := finding.Write(&buf, report, "sarif"); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`"codeFlows"`)) || !bytes.Contains(buf.Bytes(), []byte("written by setQuery")) {
			t.Fatal("SARIF lost the dataflow trace")
		}
	}
}

func TestLoopConvergenceBudget(t *testing.T) {
	var src strings.Builder
	src.WriteString("function h(req, flag) {\n")
	for i := range 140 {
		fmt.Fprintf(&src, "let x%d='';\n", i)
	}
	src.WriteString("while(flag) {\n")
	for i := range 139 {
		fmt.Fprintf(&src, "x%d=x%d;\n", i, i+1)
	}
	src.WriteString("x139=req.query.q;\n}\ndb.query('SELECT '+x0);\n}\n")
	got := analyze(t, map[string]string{"a.js": src.String()})
	if !reflect.DeepEqual(got, []string{"sast:analysis-incomplete"}) {
		t.Fatalf("budget exhaustion must be explicit, got %v", got)
	}
}

func TestRecursiveDataflow(t *testing.T) {
	for _, src := range []string{
		"function f(x,flag) { if(flag) return x; return f(x,flag); }\napp.get('/',(req,res)=>db.query('SELECT '+f(req.query.q,false)));\n",
		"function f(x,flag) { if(flag) return x; return g(x,flag); }\nfunction g(x,flag) { return f(x,flag); }\napp.get('/',(req,res)=>db.query('SELECT '+f(req.query.q,false)));\n",
	} {
		if got := analyze(t, map[string]string{"a.js": src}); !reflect.DeepEqual(got, []string{"sast:js/sql-injection"}) {
			t.Fatalf("got %v", got)
		}
	}
}

func TestWidenedFieldsRetainTaint(t *testing.T) {
	for _, src := range []string{
		"function h(req) { const o={}; o.a.b.c.d.e.f.g.h.i=req.query.q; o.a.b.c.d.e.f.g.h.j='safe'; db.query('SELECT '+o.a.b.c.d.e.f.g.h.i); }",
		"function h(req) { const o={}; o.a.b.c.d.e.f.g.h.i=req.query.q; if(!/^[a-z]+$/.test(o.a.b.c.d.e.f.g.h.j)) return; db.query('SELECT '+o.a.b.c.d.e.f.g.h.i); }",
	} {
		if got := analyze(t, map[string]string{"a.js": src}); !reflect.DeepEqual(got, []string{"sast:js/sql-injection"}) {
			t.Fatalf("widening lost taint: %v", got)
		}
	}
}

func TestDeepGoSourceReturn(t *testing.T) {
	var src strings.Builder
	src.WriteString("package main\nimport (\"database/sql\"; \"net/http\")\nvar request *http.Request\n")
	for i := range 24 {
		fmt.Fprintf(&src, "func f%d() string { return f%d() }\n", i, i+1)
	}
	src.WriteString("func f24() string { return request.FormValue(\"q\") }\nfunc h(db *sql.DB) { db.Query(\"SELECT \"+f0()) }\n")
	if got := analyze(t, map[string]string{"a.go": src.String()}); !reflect.DeepEqual(got, []string{"sast:go/sql-injection"}) {
		t.Fatalf("got %v", got)
	}
}

func BenchmarkSASTDataflow(b *testing.B) {
	for _, size := range []int{100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			var src strings.Builder
			for i := range size {
				fmt.Fprintf(&src, "function f%d(x) { return f%d(x); }\n", i, i+1)
			}
			fmt.Fprintf(&src, "function f%d(x) { return x; }\n", size)
			src.WriteString("app.get('/',(req,res)=>db.query('SELECT '+f0(req.query.q)));\n")
			dir := writeDataflowFiles(b, map[string]string{"a.js": src.String()})
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				found, err := sast.Analyze(dir)
				if err != nil || len(found) != 1 || found[0].ID != "sast:js/sql-injection" {
					b.Fatalf("found=%+v err=%v", found, err)
				}
			}
		})
	}
}

func FuzzSASTDataflow(f *testing.F) {
	langs := []string{"go", "js", "py", "java", "kt", "cs", "php", "rb"}
	seeds := []string{
		"package main\nfunc f(x string) string { return x }\n",
		"function f(x) { const a={value:x}; let b=a; if(x) b={}; b.value=x; return a.value; }\n",
		"def f(x):\n    d={'x':x}\n    return d['x']\n",
		"class A { String f(String x) { return x; } }\n",
		"fun f(x: String): String { return x }\n",
		"class A { string F(string x) { return x; } }\n",
		"<?php function f($x) { return $x; }\n",
		"class A\n def f(x)\n  @x=x\n end\nend\n",
	}
	for i, src := range seeds {
		f.Add(uint8(i), src)
	}
	f.Fuzz(func(t *testing.T, language uint8, src string) {
		if len(src) > 16<<10 {
			t.Skip()
		}
		lang := langs[int(language)%len(langs)]
		dir := writeDataflowFiles(t, map[string]string{"a." + lang: src})
		found, err := sast.Analyze(dir)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := finding.Write(&buf, finding.New("sast", found), "json"); err != nil {
			t.Fatal(err)
		}
		if err := schemas.Validate("sast-report.schema.json", buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	})
}
