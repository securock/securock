package sast_test

import (
	"fmt"
	"slices"
	"testing"
)

func TestPythonConstantBranches(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		vulnerable bool
	}{
		{"greater than", "limit = 12\n    if limit > 3:\n        query = request.args['q']\n    else:\n        query = 'SELECT 1'", true},
		{"less than", "limit = 12\n    if limit < 3:\n        query = request.args['q']\n    else:\n        query = 'SELECT 1'", false},
		{"not equal", "if 4 != 8:\n        query = request.args['q']\n    else:\n        query = 'SELECT 1'", true},
		{"arithmetic", "offset = 10\n    if 9 * 4 - offset >= 20:\n        query = 'SELECT 1'\n    else:\n        query = request.args['q']", false},
		{"conditional expression", "query = 'SELECT 1' if 6 * 8 > 40 else request.args['q']", false},
		{"conditional false", "query = 'SELECT 1' if 6 * 8 <= 40 else request.args['q']", true},
		{"string equality", "mode = 'public'\n    query = 'SELECT 1' if mode == 'public' else request.args['q']", false},
		{"string inequality", "mode = 'public'\n    query = request.args['q'] if mode != 'private' else 'SELECT 1'", true},
		{"unknown condition", "query = request.args['q'] if request.args['mode'] == 'public' else 'SELECT 1'", true},
		{"unknown multiplication preserves strings", "query = request.args['q'] * 2", true},
		{"floor division", "query = request.args['q'] if -7 // 3 == -3 else 'SELECT 1'", true},
		{"true division is not integer division", "query = request.args['q'] if 7 / 2 > 3 else 'SELECT 1'", true},
		{"large integer does not wrap", "query = request.args['q'] if 9223372036854775807 + 2 > 0 else 'SELECT 1'", true},
		{"chained comparison", "query = request.args['q'] if 2 < 4 < 8 else 'SELECT 1'", true},
		{"chained false comparison", "query = request.args['q'] if 2 < 9 < 8 else 'SELECT 1'", false},
		{"escaped string stays conservative", `query = request.args['q'] if '\x61' == 'a' else 'SELECT 1'`, true},
		{"formatted string stays conservative", `query = request.args['q'] if '{}'.format('a') == 'a' else 'SELECT 1'`, true},
		{"interpolated string stays conservative", `query = request.args['q'] if f"prefix{'a'}" == 'prefixa' else 'SELECT 1'`, true},
		{"numeric interpolation is not addition", `query = request.args['q'] if f"{2}{3}" != 5 else 'SELECT 1'`, true},
		{"exception branch cannot prove a constant", "mode = 'unsafe'\n    try:\n        may_raise()\n    except Exception:\n        mode = 'safe'\n    query = request.args['q'] if mode == 'unsafe' else 'SELECT 1'", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("from flask import request\ndef route(db):\n    %s\n    db.execute(query)\n", tt.body)
			got := analyze(t, map[string]string{"app.py": src})
			var want []string
			if tt.vulnerable {
				want = []string{"sast:py/sql-injection"}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestTypedLibrarySinks(t *testing.T) {
	for _, tt := range []struct {
		name, file, src string
		want            []string
	}{
		{"java ldap arbitrary receiver name", "Query.java", `
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;
class Query {
  void run(HttpServletRequest request, InitialDirContext directory) throws Exception {
    directory.search("ou=people", "(uid=" + request.getParameter("user") + ")", null);
  }
}`, []string{"sast:java/ldap-injection"}},
		{"java parameterized ldap", "Query.java", `
import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;
class Query {
  void run(HttpServletRequest request, DirContext directory) throws Exception {
    directory.search("ou=people", "(uid={0})", new Object[]{request.getParameter("user")}, null);
  }
}`, nil},
		{"java file metadata", "Query.java", `
import java.io.File;
import javax.servlet.http.HttpServletRequest;
class Query {
  boolean run(HttpServletRequest request) {
    File target = new File("/srv", request.getParameter("file"));
    return target.exists();
  }
}`, []string{"sast:java/path-traversal"}},
		{"java path construction alone", "Query.java", `
import java.io.File;
import javax.servlet.http.HttpServletRequest;
class Query {
  File run(HttpServletRequest request) {
    return new File("/srv", request.getParameter("file"));
  }
}`, nil},
		{"python pathlib division", "app.py", "from pathlib import Path\nfrom flask import request\ndef route():\n    p = Path('/srv') / request.args['file']\n    return p.exists()\n", []string{"sast:py/path-traversal"}},
		{"python pathlib alias and joinpath", "app.py", "from pathlib import Path as LocalPath\nfrom flask import request\ndef route():\n    p = LocalPath('/srv').joinpath(request.args['file'])\n    return p.stat()\n", []string{"sast:py/path-traversal"}},
		{"python safe path", "app.py", "from pathlib import Path\nfrom flask import request\nfrom werkzeug.utils import secure_filename\ndef route():\n    p = Path('/srv') / secure_filename(request.args['file'])\n    return p.exists()\n", nil},
		{"python unrelated exists", "app.py", "from flask import request\ndef route(db):\n    db.exists(request.args['name'])\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := analyze(t, map[string]string{tt.file: tt.src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConstantSwitches(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		vulnerable bool
	}{
		{"character selector", `String choices = "xyz"; char selected = choices.charAt(1);
String query = input; switch(selected) { case 'x': query = input; break; case 'y': query = "SELECT 1"; break; default: query = input; }`, false},
		{"tainted arm", `String selected = "dynamic"; String query = "SELECT 1";
switch(selected) { case "dynamic": query = input; break; default: query = "SELECT 1"; }`, true},
		{"fallthrough", `int selected = 2; String query = "SELECT 1";
switch(selected) { case 2: query = "SELECT 2"; case 3: query = input; break; default: query = "SELECT 3"; }`, true},
		{"default", `int selected = 9; String query = input;
switch(selected) { case 1: query = input; break; default: query = "SELECT 1"; }`, false},
		{"no match retains state", `int selected = 9; String query = input;
switch(selected) { case 1: query = "SELECT 1"; break; }`, true},
		{"unknown selector", `String selected = input; String query = "SELECT 1";
switch(selected) { case "dynamic": query = input; break; default: query = "SELECT 1"; }`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := `import javax.servlet.http.HttpServletRequest; import java.sql.Statement;
class Query { void run(HttpServletRequest request, Statement db) throws Exception {
String input = request.getParameter("q"); ` + tt.body + ` db.executeQuery(query); } }`
			var want []string
			if tt.vulnerable {
				want = []string{"sast:java/sql-injection"}
			}
			if got := analyze(t, map[string]string{"Query.java": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestPythonRoundTripsAndGuards(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      []string
	}{
		{"configparser to sql", "from flask import request\nimport configparser\ndef route(db):\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', request.args['q'])\n    bar = conf.get('s', 'k')\n    db.execute(bar)\n", []string{"sast:py/sql-injection"}},
		{"configparser to path", "from flask import request\nimport configparser\ndef route():\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', request.args['q'])\n    open(conf.get('s', 'k'))\n", []string{"sast:py/path-traversal"}},
		{"configparser constant", "import configparser\ndef route(db):\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', 'SELECT 1')\n    db.execute(conf.get('s', 'k'))\n", nil},
		{"configparser unrelated type", "from flask import request\ndef route(db):\n    cache = OtherCache()\n    cache.set('s', 'k', request.args['q'])\n    db.execute(cache.get('s', 'k'))\n", nil},
		{"configparser unknown key stays conservative", "from flask import request\nimport configparser\ndef route(db, section):\n    conf = configparser.ConfigParser()\n    conf.set(section, 'k', request.args['q'])\n    db.execute(conf.get('s', 'k'))\n", []string{"sast:py/sql-injection"}},
		{"configparser read_dict", "from flask import request\nimport configparser\ndef route(db):\n    conf = configparser.ConfigParser()\n    conf.read_dict({'s': {'k': request.args['q']}})\n    db.execute(conf.get('s', 'k'))\n", []string{"sast:py/sql-injection"}},
		{"configparser reassignment clears", "from flask import request\nimport configparser\ndef route(db):\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', request.args['q'])\n    conf = configparser.ConfigParser()\n    conf.set('s', 'k', 'SELECT 1')\n    db.execute(conf.get('s', 'k'))\n", nil},
		{"dot-dot rejection protects path", "from flask import request\ndef route():\n    value = request.args['f']\n    if '../' in value:\n        return 'bad'\n    open('/srv/' + value)\n", nil},
		{"dot-dot rejection is not sql safety", "from flask import request\ndef route(db):\n    value = request.args['q']\n    if '../' in value:\n        return 'bad'\n    db.execute(value)\n", []string{"sast:py/sql-injection"}},
		{"unrelated substring is not path validation", "from flask import request\ndef route():\n    value = request.args['f']\n    if 'public' in value:\n        return 'bad'\n    open('/srv/' + value)\n", []string{"sast:py/path-traversal"}},
		{"make_response header is not a page", "from flask import request, make_response\ndef route():\n    value = request.args['q']\n    resp = make_response(('plain text', {'X-Test': value}))\n    return resp\n", nil},
		{"make_response body is a page", "from flask import request, make_response\ndef route():\n    value = request.args['q']\n    resp = make_response((value, {'X-Test': 'fixed'}))\n    return resp\n", []string{"sast:py/xss"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := analyze(t, map[string]string{"app.py": tt.src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonMatchBranches(t *testing.T) {
	for _, tt := range []struct {
		name, subject, pattern, guard string
		vulnerable                    bool
	}{
		{"literal", "'alpha'", "'beta'", "", false},
		{"matching literal", "'alpha'", "'alpha'", "", true},
		{"union pattern", "'alpha'", "'beta' | 'alpha'", "", true},
		{"string index", "'xyz'[1]", "'x'", "", false},
		{"negative string index", "'xyz'[-1]", "'z'", "", true},
		{"unicode string index", "'é猫'[1]", "'猫'", "", true},
		{"unknown subject", "request.args['mode']", "'alpha'", "", true},
		{"unknown guard", "'alpha'", "'alpha'", " if check()", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf("from flask import request\ndef route(db):\n    query = 'SELECT 1'\n    match %s:\n        case %s%s:\n            query = request.args['q']\n        case _:\n            query = 'SELECT 1'\n    db.execute(query)\n", tt.subject, tt.pattern, tt.guard)
			var want []string
			if tt.vulnerable {
				want = []string{"sast:py/sql-injection"}
			}
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
