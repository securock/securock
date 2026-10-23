package sast_test

import (
	"slices"
	"testing"
)

func TestKotlin(t *testing.T) {
	const head = "import java.sql.Connection\nimport java.io.File\nimport javax.servlet.http.HttpServletRequest\nimport org.springframework.web.bind.annotation.*\n\n@RestController\nclass C(private val conn: Connection) {\n"
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"sql concatenation", "@GetMapping(\"/a\")\nfun g(@RequestParam name: String): String {\n val rs = conn.createStatement().executeQuery(\"SELECT * FROM t WHERE n = '\" + name + \"'\")\n return \"\"\n}", []string{"sast:kt/sql-injection"}},
		{"sql string template", "@GetMapping(\"/a\")\nfun g(@RequestParam id: String): String {\n val rs = conn.createStatement().executeQuery(\"SELECT * FROM t WHERE i = $id\")\n return \"\"\n}", []string{"sast:kt/sql-injection"}},
		{"prepared statement", "@GetMapping(\"/a\")\nfun g(@RequestParam id: String): String {\n val ps = conn.prepareStatement(\"SELECT * FROM t WHERE i = ?\")\n ps.setString(1, id)\n return ps.executeQuery().toString()\n}", nil},
		{"constant query", "@GetMapping(\"/a\")\nfun g(@RequestParam id: String): String {\n val rs = conn.createStatement().executeQuery(\"SELECT 1\")\n return \"\"\n}", nil},
		{"path traversal", "@GetMapping(\"/a\")\nfun g(@RequestParam p: String): String {\n return File(p).readText()\n}", []string{"sast:kt/path-traversal"}},
		{"command injection", "fun g(req: HttpServletRequest) {\n Runtime.getRuntime().exec(req.getParameter(\"c\"))\n}", []string{"sast:kt/command-injection"}},
		{"ktor parameter", "fun routes(r: io.ktor.server.routing.Route, conn: Connection) {\n r.get(\"/a\") {\n  val id = call.parameters[\"id\"]\n  conn.createStatement().executeQuery(\"SELECT \" + id)\n }\n}", []string{"sast:kt/sql-injection"}},
		{"ktor body", "suspend fun h(call: io.ktor.server.application.ApplicationCall) {\n val b = call.receiveText()\n Runtime.getRuntime().exec(b)\n}", []string{"sast:kt/command-injection"}},
		{"ktor header", "suspend fun h(call: io.ktor.server.application.ApplicationCall) {\n val h = call.request.headers[\"X-Cmd\"]\n Runtime.getRuntime().exec(h)\n}", []string{"sast:kt/command-injection"}},
		{"ktor receive", "suspend fun h(call: io.ktor.server.application.ApplicationCall) {\n val b = call.receive<String>()\n Runtime.getRuntime().exec(b)\n}", []string{"sast:kt/command-injection"}},
		{"channel receive is not request data", "suspend fun h(ch: kotlinx.coroutines.channels.Channel<String>) {\n val b = ch.receive()\n Runtime.getRuntime().exec(b)\n}", nil},
		{"class literal in an annotation before an extension function", "}\n@OptIn(Foo::class)\nfun Route.r(conn: Connection) {\n get(\"/a\") {\n  conn.createStatement().executeQuery(\"SELECT \" + call.parameters[\"id\"])\n }\n}\nclass D {", []string{"sast:kt/sql-injection"}},
		{"annotated extension function after an annotated class", "}\n@Serializable\ndata class U(val a: String)\n\n@Suppress(\"UNUSED\")\nfun Route.r(conn: Connection) {\n get(\"/a\") {\n  conn.createStatement().executeQuery(\"SELECT \" + call.parameters[\"id\"])\n }\n}\nclass D {", []string{"sast:kt/sql-injection"}},
		{"visibility before suspend on an extension function", "}\ninternal suspend fun Route.r(conn: Connection) {\n get(\"/a\") {\n  conn.createStatement().executeQuery(\"SELECT \" + call.parameters[\"id\"])\n }\n}\nclass D {", []string{"sast:kt/sql-injection"}},
		{"generic call with arguments on following lines", "fun r(conn: Connection, call: ApplicationCall) {\n val id = call.parameters[\"id\"]\n take<Row>(a,\n  b, c)\n conn.createStatement().executeQuery(\"SELECT \" + id)\n}", []string{"sast:kt/sql-injection"}},
		{"javaObjectType class reference", "fun r(conn: Connection, call: ApplicationCall) {\n val c = m.getCache(\"k\", Int::class.javaObjectType, K::class.java)\n conn.createStatement().executeQuery(\"SELECT \" + call.parameters[\"id\"])\n}", []string{"sast:kt/sql-injection"}},
		{"two indexed assignments in one function", "fun r(conn: Connection, call: ApplicationCall, model: MutableMap<String, Any>) {\n model[\"a\"] = 1\n model[\"b\"] = 2\n conn.createStatement().executeQuery(\"SELECT \" + call.parameters[\"id\"])\n}", []string{"sast:kt/sql-injection"}},
		{"taint stored by an indexed assignment is read back", "fun r(conn: Connection, call: ApplicationCall) {\n val m = HashMap<String, String>()\n m[\"a\"] = call.parameters[\"id\"]!!\n m[\"b\"] = \"x\"\n conn.createStatement().executeQuery(\"SELECT \" + m[\"a\"])\n}", []string{"sast:kt/sql-injection"}},
		{"ktor constant", "fun routes(r: io.ktor.server.routing.Route, conn: Connection) {\n r.get(\"/a\") {\n  conn.createStatement().executeQuery(\"SELECT 1\")\n }\n}", nil},
		{"taint through a helper", "private fun q(s: String) = conn.createStatement().executeQuery(s)\n@GetMapping(\"/a\")\nfun g(@RequestParam n: String) {\n q(\"SELECT \" + n)\n}", []string{"sast:kt/sql-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"C.kt": head + tt.body + "\n}\n"})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
