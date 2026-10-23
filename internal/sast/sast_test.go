package sast_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/securock/securock/internal/sast"
)

func analyze(t *testing.T, files map[string]string) []string {
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
	got, err := sast.Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	slices.Sort(ids)
	return ids
}

func TestTaintRules(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"sql concat", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
	db.Query("SELECT * FROM t WHERE id = " + r.FormValue("id"))
}`, []string{"sast:go/sql-injection"}},
		{"sql placeholder is safe", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
	db.Query("SELECT * FROM t WHERE id = ?", r.FormValue("id"))
}`, nil},
		{"sql via sprintf and variable", `package main
import ("database/sql"; "fmt"; "net/http")
func h(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := fmt.Sprintf("SELECT * FROM t WHERE id = '%s'", id)
	db.Exec(q)
}`, []string{"sast:go/sql-injection"}},
		{"integer conversion sanitizes", `package main
import ("database/sql"; "fmt"; "net/http"; "strconv")
func h(db *sql.DB, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil { return }
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))
}`, nil},
		{"command injection", `package main
import ("net/http"; "os/exec")
func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", "ping "+r.FormValue("host")).Run()
}`, []string{"sast:go/command-injection"}},
		{"fixed executable with tainted argument is not flagged", `package main
import ("net/http"; "os/exec")
func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("ping", "-c", "1", r.FormValue("host")).Run()
}`, nil},
		{"path traversal", `package main
import ("net/http"; "os"; "path/filepath")
func h(w http.ResponseWriter, r *http.Request) {
	b, _ := os.ReadFile(filepath.Join("/srv", r.FormValue("f")))
	w.Write(b)
}`, []string{"sast:go/path-traversal"}},
		{"filepath.Base sanitizes path traversal", `package main
import ("net/http"; "os"; "path/filepath")
func h(w http.ResponseWriter, r *http.Request) {
	b, _ := os.ReadFile(filepath.Join("/srv", filepath.Base(r.FormValue("f"))))
	_ = b
}`, nil},
		{"ssrf", `package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	http.Get(r.FormValue("url"))
}`, []string{"sast:go/ssrf"}},
		{"xss", `package main
import ("fmt"; "net/http")
func h(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<p>%s</p>", r.FormValue("name"))
}`, []string{"sast:go/xss"}},
		{"escaping clears xss only", `package main
import ("fmt"; "html"; "net/http")
func h(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(r.FormValue("name")))
}`, nil},
		{"open redirect", `package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.FormValue("next"), 302)
}`, []string{"sast:go/open-redirect"}},
		{"digest of tainted data is not tainted", `package main
import ("crypto/sha256"; "encoding/hex"; "net/http"; "os"; "path/filepath")
func h(r *http.Request) {
	sum := sha256.Sum256([]byte(r.FormValue("k")))
	os.ReadFile(filepath.Join("/cache", hex.EncodeToString(sum[:])))
}`, nil},
		{"html escaping does not stop sql injection", `package main
import ("database/sql"; "html"; "net/http")
func h(db *sql.DB, r *http.Request) {
	db.Query("SELECT " + html.EscapeString(r.FormValue("c")))
}`, []string{"sast:go/sql-injection"}},
		{"flow through a helper in another function", `package main
import ("database/sql"; "net/http")
func find(db *sql.DB, name string) { db.Query("SELECT * FROM u WHERE n = '" + name + "'") }
func h(db *sql.DB, r *http.Request) { find(db, r.FormValue("n")) }`, []string{"sast:go/sql-injection"}},
		{"helper returning source data", `package main
import ("database/sql"; "net/http")
func param(r *http.Request) string { return r.FormValue("n") }
func h(db *sql.DB, r *http.Request) { db.Query("SELECT " + param(r)) }`, []string{"sast:go/sql-injection"}},
		{"helper never called with tainted data", `package main
import "database/sql"
func find(db *sql.DB, name string) { db.Query("SELECT * FROM u WHERE n = '" + name + "'") }
func h(db *sql.DB) { find(db, "admin") }`, nil},
		{"struct field is tracked on its own", `package main
import ("database/sql"; "net/http")
type q struct{ a, b string }
func h(db *sql.DB, r *http.Request) {
	var v q
	v.a = r.FormValue("x")
	v.b = "constant"
	db.Query(v.b)
}`, nil},
		{"tainted struct field", `package main
import ("database/sql"; "net/http")
type q struct{ a, b string }
func h(db *sql.DB, r *http.Request) {
	var v q
	v.a = r.FormValue("x")
	db.Query(v.a)
}`, []string{"sast:go/sql-injection"}},
		{"overwritten before use", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
	s := r.FormValue("x")
	s = "SELECT 1"
	db.Query(s)
}`, nil},
		{"json body into struct", `package main
import ("database/sql"; "encoding/json"; "net/http")
type in struct{ Name string }
func h(db *sql.DB, r *http.Request) {
	var v in
	json.NewDecoder(r.Body).Decode(&v)
	db.Query("SELECT " + v.Name)
}`, []string{"sast:go/sql-injection"}},
		{"closure handler", `package main
import ("database/sql"; "net/http")
func main() {
	var db *sql.DB
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		db.Query("SELECT " + r.FormValue("c"))
	})
}`, []string{"sast:go/sql-injection"}},
		{"branch keeps taint from either side", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request, ok bool) {
	s := "SELECT 1"
	if ok { s = "SELECT " + r.FormValue("c") }
	db.Query(s)
}`, []string{"sast:go/sql-injection"}},
		{"both branches overwrite", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request, ok bool) {
	s := r.FormValue("c")
	if ok { s = "SELECT 1" } else { s = "SELECT 2" }
	db.Query(s)
}`, nil},
		{"type switch variable", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
	var x any = r.FormValue("c")
	switch v := x.(type) {
	case string:
		db.Query(v)
	}
}`, []string{"sast:go/sql-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"main.go": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestASTRules(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"md5", `package main
import "crypto/md5"
func f(b []byte) { _ = md5.Sum(b) }`, []string{"sast:go/weak-crypto"}},
		{"tls skip verify", `package main
import "crypto/tls"
func f() { _ = &tls.Config{InsecureSkipVerify: true} }`, []string{"sast:go/tls-verification-disabled"}},
		{"tls verify on", `package main
import "crypto/tls"
func f() { _ = &tls.Config{InsecureSkipVerify: false} }`, nil},
		{"hardcoded secret", `package main
func f() { apiKey := "Zk3pQ9vLm2XcT7wRb5NhY8aD"; _ = apiKey }`, []string{"sast:go/hardcoded-secret"}},
		{"placeholder is not a secret", `package main
func f() { password := "changeme-please"; _ = password }`, nil},
		{"word is not a secret", `package main
func f() { tokenizerName := "whitespace-tokenizer"; _ = tokenizerName }`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"main.go": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnparsableFileIsReportedNotSkipped(t *testing.T) {
	got := analyze(t, map[string]string{"bad.go": "package main\nfunc ("})
	if !slices.Equal(got, []string{"sast:analysis-incomplete"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSkipsVendorTestdataAndTests(t *testing.T) {
	vuln := `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) { db.Query("SELECT " + r.FormValue("c")) }`
	got := analyze(t, map[string]string{
		"vendor/x/x.go":   vuln,
		"testdata/x/x.go": vuln,
		"a_test.go":       vuln,
	})
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestCrossPackageFlow(t *testing.T) {
	got := analyze(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22\n",
		"store/store.go": `package store
import "database/sql"
func Find(db *sql.DB, name string) { db.Query("SELECT * FROM u WHERE n = '" + name + "'") }`,
		"main.go": `package main
import ("database/sql"; "net/http"; "example.com/app/store")
func h(db *sql.DB, r *http.Request) { store.Find(db, r.FormValue("n")) }`,
	})
	if !slices.Equal(got, []string{"sast:go/sql-injection"}) {
		t.Fatalf("got %v", got)
	}
}

func TestFindingCarriesLocationAndTrace(t *testing.T) {
	dir := t.TempDir()
	src := `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
	id := r.FormValue("id")
	db.Query("SELECT " + id)
}`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sast.Analyze(dir)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	f := got[0]
	if f.Location == nil || f.Location.File != "main.go" || f.Location.Line != 5 {
		t.Fatalf("location = %+v", f.Location)
	}
	if len(f.Trace) < 2 || f.Trace[0].Line != 4 || !strings.Contains(f.Trace[len(f.Trace)-1].Message, "CWE-89") {
		t.Fatalf("trace = %+v", f.Trace)
	}
	if f.Subject != "main.go#h/(*sql.DB).Query" {
		t.Fatalf("subject = %q", f.Subject)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	files := map[string]string{
		"a.go": `package main
import ("database/sql"; "net/http"; "os/exec")
func a(db *sql.DB, r *http.Request) { db.Query("x" + r.FormValue("a")); exec.Command("sh", "-c", r.FormValue("b")) }`,
		"b.go": `package main
import ("net/http")
func b(w http.ResponseWriter, r *http.Request) { http.Get(r.FormValue("u")) }`,
	}
	first := analyze(t, files)
	for range 3 {
		if got := analyze(t, files); !slices.Equal(got, first) {
			t.Fatalf("%v != %v", got, first)
		}
	}
}

func TestCompileMethodOnAVariableIsNotARegexp(t *testing.T) {
	got := analyze(t, map[string]string{"main.go": `package main
type builder struct{}
func (builder) Compile(s string) string { return s }
func f() { var b builder; _ = b.Compile("^x$") }`})
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestUnresolvedThirdPartyTypesDoNotBreakAnalysis(t *testing.T) {
	// example.com/yaml.v3 is not available and its package name (yaml) is not even
	// derivable from the path, so its types and methods are unresolved. The
	// analysis must still run and find the real issue, without reporting a failure.
	got := analyze(t, map[string]string{"main.go": `package main
import ("bytes"; "database/sql"; "net/http"; "example.com/yaml.v3")
func h(db *sql.DB, r *http.Request) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	enc.Encode(r.FormValue("x"))
	db.Query("SELECT " + r.FormValue("x"))
}`})
	if !slices.Equal(got, []string{"sast:go/sql-injection"}) {
		t.Fatalf("got %v", got)
	}
}
