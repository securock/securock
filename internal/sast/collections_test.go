package sast_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPythonSequences(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		bad        bool
	}{
		{"literal safe slot", "values = [input, 'SELECT 1']\n    query = values[1]", false},
		{"literal tainted slot", "values = [input, 'SELECT 1']\n    query = values[0]", true},
		{"append and remove safe slot", "values = []\n    values.append('first')\n    values.append(input)\n    values.append('SELECT 1')\n    values.pop(0)\n    query = values[1]", false},
		{"append and remove tainted slot", "values = []\n    values.append('first')\n    values.append(input)\n    values.append('SELECT 1')\n    values.pop(0)\n    query = values[0]", true},
		{"pop result", "values = ['SELECT 1', input]\n    query = values.pop()", true},
		{"pop leaves safe list", "values = ['SELECT 1', input]\n    values.pop()\n    query = values[0]", false},
		{"negative index", "values = ['SELECT 1', input]\n    query = values[-1]", true},
		{"insert shifts", "values = [input]\n    values.insert(0, 'SELECT 1')\n    query = values[0]", false},
		{"insert preserves taint", "values = [input]\n    values.insert(0, 'SELECT 1')\n    query = values[1]", true},
		{"unknown index", "values = [input, 'SELECT 1']\n    query = values[index]", true},
		{"unknown removal", "values = [input, 'SELECT 1']\n    values.pop(index)\n    query = values[0]", true},
		{"branch-dependent position", "values = ['SELECT 1', input]\n    if flag:\n        values.pop(0)\n    query = values[0]", true},
		{"branch-dependent length", "values = ['SELECT 1']\n    if flag:\n        values.append(input)\n    query = values[-1]", true},
		{"alias mutation", "values = ['SELECT 1']\n    alias = values\n    alias.append(input)\n    query = values[1]", true},
		{"unknown call can reorder", "values = ['SELECT 1', input]\n    reorder(values)\n    query = values[0]", true},
		{"unknown method can reorder", "values = ['SELECT 1', input]\n    values.reverse()\n    query = values[0]", true},
		{"helper mutation", "values = ['SELECT 1']\n    fill(values, input)\n    query = values[0]", true},
		{"starred literal", "items = [input]\n    values = ['SELECT 1', *items]\n    query = values[1]", true},
		{"loop mutation", "values = ['SELECT 1']\n    for item in unknown:\n        values.append(input)\n    query = values[-1]", true},
		{"self reference", "values = []\n    values.append(values)\n    values.append(input)\n    query = values[0][1]", true},
		{"nested mutable list", "inner = []\n    values = [inner]\n    inner.append(input)\n    query = values[0][0]", true},
		{"appended mutable list", "inner = []\n    values = []\n    values.append(inner)\n    inner.append(input)\n    query = values[0][0]", true},
		{"tracking budget falls back", "values = ['SELECT 1']\n    for i in range(70):\n        values.append(input)\n    query = values[-1]", true},
		{"large literal falls back", "values = [" + strings.Repeat("'SELECT 1',", 65) + "input]\n    query = values[65]", true},
		{"append past tracking budget", "values = []\n    " + strings.Repeat("values.append('SELECT 1')\n    ", 64) + "values.append(input)\n    query = values[64]", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from flask import request\ndef fill(target, value):\n    target[0] = value\ndef route(db, index, flag, unknown):\n    input = request.args['q']\n    " + tt.body + "\n    db.execute(query)\n"
			var want []string
			if tt.bad {
				want = []string{"sast:py/sql-injection"}
			}
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestJavaSequences(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		bad        bool
	}{
		{"remove shifts safe slot", `values.add("first"); values.add(input); values.add("SELECT 1"); values.remove(0); String query = values.get(1);`, false},
		{"remove shifts tainted slot", `values.add("first"); values.add(input); values.add("SELECT 1"); values.remove(0); String query = values.get(0);`, true},
		{"set overwrites", `values.add(input); values.set(0, "SELECT 1"); String query = values.get(0);`, false},
		{"set preserves another slot", `values.add(input); values.add("SELECT 1"); values.set(1, "SELECT 2"); String query = values.get(0);`, true},
		{"remove by value stays conservative", `values.add(input); values.add("SELECT 1"); values.remove("SELECT 1"); String query = values.get(0);`, true},
		{"unknown index", `values.add(input); String query = values.get(index);`, true},
		{"alias mutation", `List<String> alias = values; alias.add(input); String query = values.get(0);`, true},
		{"unknown call", `values.add("SELECT 1"); values.add(input); Collections.reverse(values); String query = values.get(0);`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := fmt.Sprintf(`import java.util.*; import java.sql.Statement; import javax.servlet.http.HttpServletRequest;
class Route { void run(HttpServletRequest request, Statement db, int index) throws Exception {
String input = request.getParameter("q"); List<String> values = new ArrayList<String>(); %s db.executeQuery(query); } }`, tt.body)
			var want []string
			if tt.bad {
				want = []string{"sast:java/sql-injection"}
			}
			if got := analyze(t, map[string]string{"Route.java": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestElementpathQueries(t *testing.T) {
	for _, tt := range []struct {
		call string
		bad  bool
	}{
		{`ep.select(document, "/users/user[@id='" + input + "']")`, true},
		{`ep.iter_select(document, path=input)`, true},
		{`ep.Selector(path=input)`, true},
		{`ep.select(input, "/users/user")`, false},
		{`ep.select(document, "/users/user[@id=$id]", variables={"id": input})`, false},
	} {
		t.Run(tt.call, func(t *testing.T) {
			src := "import elementpath as ep\nfrom flask import request\ndef route(document):\n    input = request.args['q']\n    " + tt.call + "\n"
			var want []string
			if tt.bad {
				want = []string{"sast:py/xpath-injection"}
			}
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
