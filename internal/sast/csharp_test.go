package sast_test

import (
	"slices"
	"testing"
)

func TestCSharp(t *testing.T) {
	const head = "using System;\nusing System.Data.SqlClient;\nusing System.IO;\nusing System.Net.Http;\nusing Microsoft.AspNetCore.Mvc;\n[ApiController]\npublic class C : ControllerBase {\n  private readonly SqlConnection _conn;\n  private readonly HttpClient _http;\n"
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"sql concatenation", "[HttpGet]\npublic IActionResult G([FromQuery] string name) {\n var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + name + \"'\", _conn);\n return Ok();\n}", []string{"sast:cs/sql-injection"}},
		{"sql interpolation from Request.Query", "[HttpGet]\npublic IActionResult G() {\n var id = Request.Query[\"id\"];\n var cmd = new SqlCommand($\"SELECT * FROM t WHERE i = {id}\", _conn);\n return Ok();\n}", []string{"sast:cs/sql-injection"}},
		{"parameterized sql", "[HttpGet]\npublic IActionResult G([FromQuery] string name) {\n var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = @n\", _conn);\n cmd.Parameters.AddWithValue(\"@n\", name);\n return Ok();\n}", nil},
		{"int parse sanitizes", "[HttpGet]\npublic IActionResult G([FromQuery] string id) {\n int n = int.Parse(id);\n var cmd = new SqlCommand(\"SELECT * FROM t WHERE i = \" + n, _conn);\n return Ok();\n}", nil},
		{"action parameters of a controller are request data", "[HttpGet]\npublic IActionResult G(string name) {\n var cmd = new SqlCommand(\"SELECT \" + name, _conn);\n return Ok();\n}", []string{"sast:cs/sql-injection"}},
		{"numeric action parameter", "[HttpGet]\npublic IActionResult G(int id) {\n var cmd = new SqlCommand(\"SELECT \" + id, _conn);\n return Ok();\n}", nil},
		{"command injection", "[HttpGet]\npublic IActionResult G([FromQuery] string host) {\n System.Diagnostics.Process.Start(\"ping\", host);\n return Ok();\n}", []string{"sast:cs/command-injection"}},
		{"path traversal", "[HttpGet]\npublic IActionResult G([FromQuery] string f) {\n return Content(File.ReadAllText(\"/srv/\" + f));\n}", []string{"sast:cs/path-traversal"}},
		{"GetFileName sanitizes", "[HttpGet]\npublic IActionResult G([FromQuery] string f) {\n return Content(File.ReadAllText(\"/srv/\" + Path.GetFileName(f)));\n}", nil},
		{"ssrf", "[HttpGet]\npublic async System.Threading.Tasks.Task<IActionResult> G([FromQuery] string url) {\n var s = await _http.GetStringAsync(url);\n return Ok(s);\n}", []string{"sast:cs/ssrf"}},
		{"open redirect", "[HttpGet]\npublic IActionResult G([FromQuery] string next) {\n return Redirect(next);\n}", []string{"sast:cs/open-redirect"}},
		{"LocalRedirect is safe", "[HttpGet]\npublic IActionResult G([FromQuery] string next) {\n return LocalRedirect(next);\n}", nil},
		{"IsLocalUrl guard", "[HttpGet]\npublic IActionResult G([FromQuery] string next) {\n if (!Url.IsLocalUrl(next)) { return BadRequest(); }\n return Redirect(next);\n}", nil},
		{"allowlist guard", "static readonly string[] ok = { \"a\" };\n[HttpGet]\npublic IActionResult G([FromQuery] string next) {\n if (!ok.Contains(next)) { return BadRequest(); }\n return Redirect(next);\n}", nil},
		{"weak md5", "public void H(byte[] b) { var m = System.Security.Cryptography.MD5.Create(); }", []string{"sast:cs/weak-crypto"}},
		{"ecb mode", "public void H(System.Security.Cryptography.Aes a) { a.Mode = CipherMode.ECB; }", []string{"sast:cs/weak-crypto"}},
		{"cookie flags off", "public void H(CookieOptions o) { o.HttpOnly = false; o.Secure = false; }", []string{"sast:cs/insecure-cookie", "sast:cs/insecure-cookie"}},
		{"jwt validation off", "public void H(TokenValidationParameters p) { p.ValidateIssuerSigningKey = false; }", []string{"sast:cs/jwt-unverified"}},
		{"deserialization", "[HttpPost]\npublic IActionResult G([FromBody] System.IO.Stream s) {\n var f = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();\n f.Deserialize(s);\n return Ok();\n}", []string{"sast:cs/insecure-deserialization"}},
		{"log injection", "private readonly Microsoft.Extensions.Logging.ILogger _logger;\n[HttpGet]\npublic IActionResult G([FromQuery] string u) {\n _logger.LogInformation(\"user \" + u);\n return Ok();\n}", []string{"sast:cs/log-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"C.cs": head + tt.body + "\n}\n"})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
