package sast_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestDeepDataflow(t *testing.T) {
	for _, lang := range []string{"go", "js", "py", "java", "kt", "cs", "php", "rb"} {
		t.Run(lang, func(t *testing.T) {
			var src strings.Builder
			file := "a." + lang
			switch lang {
			case "go":
				src.WriteString("package main\nimport (\"net/http\"; \"database/sql\")\n")
			case "py":
				src.WriteString("from flask import request\n")
			case "java":
				file = "A.java"
				src.WriteString("import javax.servlet.http.*;\nclass A {\n")
			case "cs":
				src.WriteString("using System.Data.SqlClient;\nusing Microsoft.AspNetCore.Mvc;\n[ApiController]\nclass A : ControllerBase {\n")
			case "php":
				src.WriteString("<?php\n")
			}
			// The order forces information to travel one edge per round.
			for i := range 24 {
				switch lang {
				case "go":
					fmt.Fprintf(&src, "func f%d(x string) string { return f%d(x) }\n", i, i+1)
				case "js":
					fmt.Fprintf(&src, "function f%d(x) { return f%d(x); }\n", i, i+1)
				case "py":
					fmt.Fprintf(&src, "def f%d(x):\n    return f%d(x)\n", i, i+1)
				case "java", "cs":
					fmt.Fprintf(&src, "static %s f%d(%s x) { return f%d(x); }\n", map[string]string{"java": "String", "cs": "string"}[lang], i, map[string]string{"java": "String", "cs": "string"}[lang], i+1)
				case "kt":
					fmt.Fprintf(&src, "fun f%d(x: String): String { return f%d(x) }\n", i, i+1)
				case "php":
					fmt.Fprintf(&src, "function f%d($x) { return f%d($x); }\n", i, i+1)
				case "rb":
					fmt.Fprintf(&src, "def f%d(x)\n  f%d(x)\nend\n", i, i+1)
				}
			}
			switch lang {
			case "go":
				src.WriteString("func f24(x string) string { return x }\nfunc h(db *sql.DB, r *http.Request) { db.Query(\"SELECT \" + f0(r.FormValue(\"q\"))) }\n")
			case "js":
				src.WriteString("function f24(x) { return x; }\napp.get('/', (req, res) => db.query('SELECT ' + f0(req.query.q)));\n")
			case "py":
				src.WriteString("def f24(x):\n    return x\ndef h(cursor):\n    cursor.execute('SELECT ' + f0(request.args['q']))\n")
			case "java":
				src.WriteString("static String f24(String x) { return x; }\nvoid h(HttpServletRequest req, java.sql.Statement st) throws Exception { st.executeQuery(\"SELECT \" + f0(req.getParameter(\"q\"))); }\n}\n")
			case "cs":
				src.WriteString("static string f24(string x) { return x; }\n[HttpGet]\npublic void H([FromQuery] string q) { var c = new SqlCommand(\"SELECT \" + f0(q)); }\n}\n")
			case "kt":
				src.WriteString("fun f24(x: String): String { return x }\nfun h(req: HttpServletRequest, conn: Connection) { conn.createStatement().executeQuery(\"SELECT \" + f0(req.getParameter(\"q\"))) }\n")
			case "php":
				src.WriteString("function f24($x) { return $x; }\nmysqli_query($db, 'SELECT ' . f0($_GET['q']));\n")
			case "rb":
				src.WriteString("def f24(x)\n  x\nend\nUser.find_by_sql('SELECT ' + f0(params[:q]))\n")
			}
			want := []string{"sast:" + lang + "/sql-injection"}
			if got := analyze(t, map[string]string{file: src.String()}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestAdvancedDataflow(t *testing.T) {
	tests := []struct {
		name, file, src string
		want            []string
	}{
		{"go loop back edges", "a.go", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB, r *http.Request) {
 a,b,c,d := "","","",""
 for range 10 { db.Query("SELECT " + a); a=b; b=c; c=d; d=r.FormValue("q") }
}`, []string{"sast:go/sql-injection"}},
		{"js loop back edges", "a.js", `function h(req) {
 let a='', b='', c='', d='';
 for (let i=0; i<10; i++) { db.query('SELECT ' + a); a=b; b=c; c=d; d=req.query.q; }
}`, []string{"sast:js/sql-injection"}},
		{"go setter", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query string }
func (j *Job) set(x string) { j.query=x }
func (j *Job) run(db *sql.DB) { db.Query("SELECT " + j.query) }
func h(db *sql.DB,r *http.Request) { j:=&Job{}; j.set(r.FormValue("q")); j.run(db) }
`, []string{"sast:go/sql-injection"}},
		{"js setter", "a.js", `class Job {
 set(x) { this.query=x; }
 run() { db.query('SELECT ' + this.query); }
}
function h(req) { const j=new Job(); j.set(req.query.q); j.run(); }
`, []string{"sast:js/sql-injection"}},
		{"python setter", "a.py", `from flask import request
class Job:
    def set_query(self, x):
        self.query = x
    def run(self, cursor):
        cursor.execute('SELECT ' + self.query)
def h(cursor):
    j=Job()
    j.set_query(request.args['q'])
    j.run(cursor)
`, []string{"sast:py/sql-injection"}},
		{"java setter", "A.java", `import javax.servlet.http.*;
class Job {
 String query;
 void setQuery(String x) { query=x; }
 void run(java.sql.Statement st) throws Exception { st.executeQuery("SELECT " + query); }
}
class A { void h(HttpServletRequest req, java.sql.Statement st) throws Exception {
 Job j=new Job(); j.setQuery(req.getParameter("q")); j.run(st);
} }
`, []string{"sast:java/sql-injection"}},
		{"kotlin setter", "a.kt", `class Job {
 var query: String = ""
 fun setQuery(x: String) { this.query=x }
 fun run(conn: Connection) { conn.createStatement().executeQuery("SELECT " + this.query) }
}
fun h(req: HttpServletRequest, conn: Connection) { val j=Job(); j.setQuery(req.getParameter("q")); j.run(conn) }
`, []string{"sast:kt/sql-injection"}},
		{"csharp setter", "A.cs", `using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
class Job {
 string query;
 public void SetQuery(string x) { query=x; }
 public void Run() { var c=new SqlCommand("SELECT " + query); }
}
[ApiController] class A : ControllerBase {
 [HttpGet] public void H([FromQuery] string q) { var j=new Job(); j.SetQuery(q); j.Run(); }
}
`, []string{"sast:cs/sql-injection"}},
		{"php setter", "a.php", `<?php
class Job {
 function setQuery($x) { $this->query=$x; }
 function run($db) { mysqli_query($db, 'SELECT ' . $this->query); }
}
$j=new Job(); $j->setQuery($_GET['q']); $j->run($db);
`, []string{"sast:php/sql-injection"}},
		{"ruby setter", "a.rb", `class Job
 def set_query(x)
  @query=x
 end
 def run
  User.find_by_sql('SELECT ' + @query)
 end
end
j=Job.new
j.set_query(params[:q])
j.run
`, []string{"sast:rb/sql-injection"}},
		{"go reference argument", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query string }
func set(j *Job,x string) { j.query=x }
func h(db *sql.DB,r *http.Request) { j:=&Job{}; set(j,r.FormValue("q")); db.Query("SELECT " + j.query) }
`, []string{"sast:go/sql-injection"}},
		{"js reference argument across aliases", "a.js", `function set(j,x) { const alias=j; alias.query=x; }
function h(req) { const j={}; set(j,req.query.q); db.query('SELECT '+j.query); }
`, []string{"sast:js/sql-injection"}},
		{"python reordered keywords", "a.py", `from flask import request
def query(cursor, ignored, text):
    cursor.execute('SELECT '+text)
def h(cursor):
    query(cursor, text=request.args['q'], ignored='')
`, []string{"sast:py/sql-injection"}},
		{"python safe reordered keywords", "a.py", `from flask import request
def query(cursor, ignored, text):
    cursor.execute('SELECT '+text)
def h(cursor):
    query(cursor, text='1', ignored=request.args['q'])
`, nil},
		{"js constructor and getter", "a.js", `class Job {
 constructor(x) { this.query=x; }
 getQuery() { return this.query; }
}
function h(req) { const j=new Job(req.query.q); db.query('SELECT '+j.getQuery()); }
`, []string{"sast:js/sql-injection"}},
		{"python constructor", "a.py", `from flask import request
class Job:
    def __init__(self,x):
        self.query=x
def h(cursor):
    j=Job(request.args['q'])
    cursor.execute('SELECT '+j.query)
`, []string{"sast:py/sql-injection"}},
		{"go returned struct fields", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query,note string }
func makeJob(x string) Job { return Job{query:x,note:""} }
func h(db *sql.DB,r *http.Request) { j:=makeJob(r.FormValue("q")); db.Query("SELECT " + j.query) }
`, []string{"sast:go/sql-injection"}},
		{"go returned other field is safe", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query,note string }
func makeJob(x string) Job { return Job{query:"1",note:x} }
func h(db *sql.DB,r *http.Request) { j:=makeJob(r.FormValue("q")); db.Query("SELECT " + j.query) }
`, nil},
		{"js returned object fields", "a.js", `function makeJob(x) { return {query:x,note:''}; }
function h(req) { const j=makeJob(req.query.q); db.query('SELECT '+j.query); }
`, []string{"sast:js/sql-injection"}},
		{"js returned other field is safe", "a.js", `function makeJob(x) { return {query:'1',note:x}; }
function h(req) { const j=makeJob(req.query.q); db.query('SELECT '+j.query); }
`, nil},
		{"python returned dictionary", "a.py", `from flask import request
def make_job(x):
    return {'query':x,'note':''}
def h(cursor):
    j=make_job(request.args['q'])
    cursor.execute('SELECT '+j['query'])
`, []string{"sast:py/sql-injection"}},
		{"python dictionary key isolation", "a.py", `from flask import request
def make_job(x):
    return {'query':'1','note':x}
def h(cursor):
    j=make_job(request.args['q'])
    cursor.execute('SELECT '+j['query'])
`, nil},
		{"js safe field overwrite", "a.js", `function h(req) { const j={query:req.query.q}; j.query='1'; db.query('SELECT '+j.query); }`, nil},
		{"go value copy is independent", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query string }
func h(db *sql.DB,r *http.Request) { j:=Job{}; copy:=j; copy.query=r.FormValue("q"); db.Query("SELECT " + j.query) }
`, nil},
		{"js detached alias", "a.js", `function h(req) { const a={}; let b=a; const c=b; b={}; c.query=req.query.q; db.query('SELECT '+a.query); }`, []string{"sast:js/sql-injection"}},
		{"js distinct objects stay independent", "a.js", `function h(req) { const a={}; const b={}; b.query=req.query.q; db.query('SELECT '+a.query); }`, nil},
		{"js rebind argument is local", "a.js", `function set(j,x) { j={}; j.query=x; }
function h(req) { const j={}; set(j,req.query.q); db.query('SELECT '+j.query); }`, nil},
		{"go rebind argument is local", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query string }
func set(j *Job,x string) { j=&Job{}; j.query=x }
func h(db *sql.DB,r *http.Request) { j:=&Job{}; set(j,r.FormValue("q")); db.Query("SELECT " + j.query) }
`, nil},
		{"go field isolation", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { table, note string }
func (j *Job) run(db *sql.DB) { db.Query("SELECT * FROM " + j.table) }
func h(db *sql.DB,r *http.Request) { j:=&Job{table:"users"}; j.note=r.FormValue("q"); j.run(db) }
`, nil},
		{"js field isolation", "a.js", `class Job { run() { db.query('SELECT * FROM ' + this.table); } }
function h(req) { const j=new Job(); j.table='users'; j.note=req.query.q; j.run(); }
`, nil},
		{"go pointer alias", "a.go", `package main
import ("database/sql"; "net/http")
type Job struct { query string }
func h(db *sql.DB,r *http.Request) { j:=&Job{}; alias:=j; alias.query=r.FormValue("q"); db.Query("SELECT " + j.query) }
`, []string{"sast:go/sql-injection"}},
		{"js object alias", "a.js", `function h(req) { const j={}; const alias=j; alias.query=req.query.q; db.query('SELECT ' + j.query); }`, []string{"sast:js/sql-injection"}},
		{"go path check does not sanitize sql", "a.go", `package main
import ("database/sql"; "net/http"; "path/filepath")
func h(db *sql.DB,r *http.Request) { q:=r.FormValue("q"); if !filepath.IsLocal(q) { return }; db.Query("SELECT " + q) }
`, []string{"sast:go/sql-injection"}},
		{"go reassign invalidates validation", "a.go", `package main
import ("net/http"; "os"; "path/filepath")
func h(r *http.Request) { q:=r.URL.Path; if !filepath.IsLocal(q) { return }; r.URL.Path=r.FormValue("new"); os.ReadFile(r.URL.Path) }
`, []string{"sast:go/path-traversal"}},
		{"go pointer output argument", "a.go", `package main
import ("database/sql"; "net/http")
func set(p *string,x string) { *p=x }
func h(db *sql.DB,r *http.Request) { q:=""; p:=&q; set(p,r.FormValue("q")); db.Query("SELECT "+q) }
`, []string{"sast:go/sql-injection"}},
		{"js tainted allowlist", "a.js", `function h(req) {
 const q=req.query.q;
 if (!req.body.allowed.includes(q)) return;
 db.query('SELECT '+q);
}`, []string{"sast:js/sql-injection"}},
		{"go stale lookup boolean", "a.go", `package main
import ("database/sql"; "net/http")
var allowed=map[string]bool{"name":true}
func h(db *sql.DB,r *http.Request) { col:=r.FormValue("q"); _,ok:=allowed[col]; ok=true; if !ok { return }; db.Query("SELECT "+col) }
`, []string{"sast:go/sql-injection"}},
		{"go unreachable sink", "a.go", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB,r *http.Request) { return; db.Query(r.FormValue("q")) }
`, nil},
		{"js unreachable sink", "a.js", `function h(req) { return; db.query(req.query.q); }`, nil},
		{"go break does not feed next iteration", "a.go", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB,r *http.Request) { q:=""; for range 10 { db.Query("SELECT "+q); q=r.FormValue("q"); break } }
`, nil},
		{"js break does not feed next iteration", "a.js", `function h(req,flag) { let q=''; while(flag) { db.query('SELECT '+q); q=req.query.q; break; } }`, nil},
		{"go continue feeds next iteration", "a.go", `package main
import ("database/sql"; "net/http")
func h(db *sql.DB,r *http.Request) { q:=""; for range 10 { db.Query("SELECT "+q); q=r.FormValue("q"); continue } }
`, []string{"sast:go/sql-injection"}},
		{"js continue feeds next iteration", "a.js", `function h(req,flag) { let q=''; while(flag) { db.query('SELECT '+q); q=req.query.q; continue; } }`, []string{"sast:js/sql-injection"}},
		{"js path validation does not clean sql", "a.js", `const path=require('path');
function h(req) { const p=path.resolve('/srv',req.query.q); if(!p.startsWith('/srv/')) return; db.query('SELECT '+p); }`, []string{"sast:js/sql-injection"}},
		{"js reassign invalidates field validation", "a.js", `function h(req) { if(!/^[a-z]+$/.test(req.query.q)) return; req.query.q=req.body.q; db.query('SELECT '+req.query.q); }`, []string{"sast:js/sql-injection"}},
		{"js field validation does not clean siblings", "a.js", `function use(obj) { if(!/^[a-z]+$/.test(obj.name)) return; db.query('SELECT '+obj.query); }
function h(req) { use({name:'safe',query:req.query.q}); }`, []string{"sast:js/sql-injection"}},
		{"js branch constants stay local", "a.js", `function h(req, flag) {
 let n=0; let q=''; if(flag) { n=1; } else { if(n===0) q=req.query.q; }
 db.query('SELECT '+q);
}`, []string{"sast:js/sql-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := analyze(t, map[string]string{tt.file: tt.src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
