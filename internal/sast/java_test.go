package sast_test

import (
	"slices"
	"testing"
)

func TestJava(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"servlet jdbc concat", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String id = req.getParameter("id");
    Connection c = DriverManager.getConnection("jdbc:x");
    Statement st = c.createStatement();
    ResultSet rs = st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
  }
}`}, []string{"sast:java/sql-injection"}},
		{"prepared statement with placeholder is safe", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A {
  void f(HttpServletRequest req, Connection c) throws Exception {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    ps.setString(1, req.getParameter("id"));
    ps.executeQuery();
  }
}`}, nil},
		{"prepared statement built by concatenation", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A {
  void f(HttpServletRequest req, Connection c) throws Exception {
    PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = " + req.getParameter("id"));
  }
}`}, []string{"sast:java/sql-injection"}},
		{"spring request param", map[string]string{"C.java": `
import org.springframework.web.bind.annotation.*;
@RestController
public class C {
  private final JdbcTemplate jdbcTemplate;
  @GetMapping("/u")
  public Object get(@RequestParam("name") String name) {
    return jdbcTemplate.queryForList("SELECT * FROM u WHERE n = '" + name + "'");
  }
}`}, []string{"sast:java/sql-injection"}},
		{"integer parse sanitizes", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A {
  void f(HttpServletRequest req, Statement st) throws Exception {
    int id = Integer.parseInt(req.getParameter("id"));
    st.executeQuery("SELECT * FROM t WHERE id = " + id);
  }
}`}, nil},
		{"runtime exec", map[string]string{"A.java": `
import javax.servlet.http.*;
public class A {
  void f(HttpServletRequest req) throws Exception {
    Runtime.getRuntime().exec("ping " + req.getParameter("h"));
  }
}`}, []string{"sast:java/command-injection"}},
		{"process builder shell", map[string]string{"A.java": `
import javax.servlet.http.*;
public class A {
  void f(HttpServletRequest req) throws Exception {
    new ProcessBuilder("sh", "-c", req.getParameter("c")).start();
  }
}`}, []string{"sast:java/command-injection"}},
		{"process builder fixed program is safe", map[string]string{"A.java": `
import javax.servlet.http.*;
public class A {
  void f(HttpServletRequest req) throws Exception {
    new ProcessBuilder("ping", req.getParameter("c")).start();
  }
}`}, nil},
		{"path traversal", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.io.*;
public class A {
  void f(HttpServletRequest req) throws Exception {
    new FileInputStream("/srv/" + req.getParameter("f"));
  }
}`}, []string{"sast:java/path-traversal"}},
		{"ssrf", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.net.*;
public class A {
  void f(HttpServletRequest req) throws Exception {
    URL u = new URL(req.getParameter("u"));
  }
}`}, []string{"sast:java/ssrf"}},
		{"xss via writer", map[string]string{"A.java": `
import javax.servlet.http.*;
public class A {
  void f(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    resp.getWriter().println("<p>" + req.getParameter("n") + "</p>");
  }
}`}, []string{"sast:java/xss"}},
		{"html escape sanitizes", map[string]string{"A.java": `
import javax.servlet.http.*;
import org.springframework.web.util.HtmlUtils;
public class A {
  void f(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    resp.getWriter().println("<p>" + HtmlUtils.htmlEscape(req.getParameter("n")) + "</p>");
  }
}`}, nil},
		{"open redirect", map[string]string{"A.java": `
import javax.servlet.http.*;
public class A {
  void f(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    resp.sendRedirect(req.getParameter("next"));
  }
}`}, []string{"sast:java/open-redirect"}},
		{"string builder carries taint", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A {
  void f(HttpServletRequest req, Statement st) throws Exception {
    StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE n = '");
    sb.append(req.getParameter("n"));
    st.executeQuery(sb.toString());
  }
}`}, []string{"sast:java/sql-injection"}},
		{"allowlist guard", map[string]string{"A.java": `
import javax.servlet.http.*;
import java.sql.*;
public class A {
  static final java.util.Set<String> COLS = java.util.Set.of("a", "b");
  void f(HttpServletRequest req, Statement st) throws Exception {
    String col = req.getParameter("sort");
    if (!COLS.contains(col)) { return; }
    st.executeQuery("SELECT * FROM t ORDER BY " + col);
  }
}`}, nil},
		{"field injected repository across classes", map[string]string{"C.java": `
import javax.servlet.http.*;
public class C {
  private Repo repo;
  void f(HttpServletRequest req) { repo.find(req.getParameter("n")); }
}`, "Repo.java": `
import java.sql.*;
public class Repo {
  private Statement st;
  void find(String n) throws Exception { st.executeQuery("SELECT '" + n + "'"); }
}`}, []string{"sast:java/sql-injection"}},
		{"interface implementation", map[string]string{"C.java": `
import javax.servlet.http.*;
public class C {
  private UserRepo repo;
  void f(HttpServletRequest req) { repo.find(req.getParameter("n")); }
}`, "UserRepo.java": `
public interface UserRepo { void find(String n); }`, "JdbcUserRepo.java": `
import java.sql.*;
public class JdbcUserRepo implements UserRepo {
  private Statement st;
  public void find(String n) { try { st.executeQuery("SELECT '" + n + "'"); } catch (Exception e) {} }
}`}, []string{"sast:java/sql-injection"}},
		{"main args", map[string]string{"M.java": `
import java.sql.*;
public class M {
  public static void main(String[] args) throws Exception {
    Statement st = null;
    st.executeQuery("SELECT " + args[0]);
  }
}`}, []string{"sast:java/sql-injection"}},
		{"plain method parameter is not a source", map[string]string{"A.java": `
import java.sql.*;
public class A {
  void find(Statement st, String n) throws Exception { st.executeQuery("SELECT '" + n + "'"); }
}`}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, tt.files))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJavaStringConstants(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"static final signing key", map[string]string{
			"A.java": "import io.jsonwebtoken.Jwts;\nimport io.jsonwebtoken.SignatureAlgorithm;\nclass A {\n private static final String KEY = \"shhh-secret\";\n String f(String u) { return Jwts.builder().setSubject(u).signWith(SignatureAlgorithm.HS256, KEY).compact(); }\n}",
		}, []string{"sast:java/hardcoded-signing-key"}},
		{"constant from another class", map[string]string{
			"Keys.java": "class Keys { public static final String JWT = \"shhh-secret\"; }",
			"A.java":    "import io.jsonwebtoken.Jwts;\nimport io.jsonwebtoken.SignatureAlgorithm;\nclass A {\n String f(String u) { return Jwts.builder().setSubject(u).signWith(SignatureAlgorithm.HS256, Keys.JWT).compact(); }\n}",
		}, []string{"sast:java/hardcoded-signing-key"}},
		{"literal key as bytes", map[string]string{
			"A.java": "import io.jsonwebtoken.Jwts;\nimport io.jsonwebtoken.SignatureAlgorithm;\nclass A {\n private static final String KEY = \"shhh-secret\";\n String f(String u) { return Jwts.builder().setSubject(u).signWith(SignatureAlgorithm.HS256, KEY.getBytes()).compact(); }\n String g(String u) { return Jwts.builder().setSubject(u).signWith(SignatureAlgorithm.HS256, \"inline-secret\".getBytes()).compact(); }\n}",
		}, []string{"sast:java/hardcoded-signing-key", "sast:java/hardcoded-signing-key"}},
		{"key read from configuration", map[string]string{
			"A.java": "import io.jsonwebtoken.Jwts;\nimport io.jsonwebtoken.SignatureAlgorithm;\nclass A {\n private static final String KEY = System.getenv(\"KEY\");\n String f(String u) { return Jwts.builder().setSubject(u).signWith(SignatureAlgorithm.HS256, KEY).compact(); }\n}",
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, tt.files)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHardcodedEncryptionKey(t *testing.T) {
	tests := []struct {
		name string
		file string
		src  string
		want []string
	}{
		{"java literal", "A.java", "import javax.crypto.spec.SecretKeySpec;\nclass A { private static final String K = \"0123456789abcdef\";\n Object f() { return new SecretKeySpec(K.getBytes(), \"AES\"); } }", []string{"sast:java/hardcoded-key"}},
		{"java key from a parameter", "A.java", "import javax.crypto.spec.SecretKeySpec;\nclass A { Object f(byte[] k) { return new SecretKeySpec(k, \"AES\"); } }", nil},
		{"node createCipheriv", "a.js", "const crypto = require('crypto');\nfunction f(iv) { return crypto.createCipheriv('aes-256-cbc', '0123456789abcdef0123456789abcdef', iv); }", []string{"sast:js/hardcoded-key"}},
		{"node key from env", "a.js", "const crypto = require('crypto');\nfunction f(iv) { return crypto.createCipheriv('aes-256-cbc', process.env.KEY, iv); }", nil},
		{"ruby constant and cipher key", "a.rb", "require 'openssl'\nKEY = '0123456789abcdef0123456789abcdef'\nclass E\n  def go\n    cipher = OpenSSL::Cipher.new('aes-256-cbc')\n    cipher.key = KEY\n  end\nend\n", []string{"sast:rb/hardcoded-key"}},
		{"ruby cipher key from env", "a.rb", "require 'openssl'\nclass E\n  def go\n    cipher = OpenSSL::Cipher.new('aes-256-cbc')\n    cipher.key = ENV['KEY']\n  end\nend\n", nil},
		{"ruby jwt literal secret", "a.rb", "require 'jwt'\nclass E\n  def go(u)\n    JWT.encode({ id: u }, 'hardcoded-jwt-secret', 'HS256')\n  end\nend\n", []string{"sast:rb/hardcoded-signing-key"}},
		{"c# aes key literal", "A.cs", "using System.Security.Cryptography;\nusing System.Text;\nclass A { public void F() { var aes = Aes.Create(); aes.Key = Encoding.UTF8.GetBytes(\"0123456789abcdef\"); } }", []string{"sast:cs/hardcoded-key"}},
		{"c# hmac key constant", "A.cs", "using System.Security.Cryptography;\nusing System.Text;\nclass A { private const string K = \"0123456789abcdef\";\n public object F() { return new HMACSHA256(Encoding.UTF8.GetBytes(K)); } }", []string{"sast:cs/hardcoded-key"}},
		{"c# hmac key from a parameter", "A.cs", "using System.Security.Cryptography;\nclass A { public object F(byte[] k) { return new HMACSHA256(k); } }", nil},
		{"php define constant", "a.php", "<?php\ndefine('ENC_KEY', '0123456789abcdef');\nfunction f($d, $iv) { return openssl_encrypt($d, 'aes-256-cbc', ENC_KEY, 0, $iv); }", []string{"sast:php/hardcoded-key"}},
		{"php const", "a.php", "<?php\nconst ENC_KEY = '0123456789abcdef';\nfunction f($d, $iv) { return openssl_encrypt($d, 'aes-256-cbc', ENC_KEY, 0, $iv); }", []string{"sast:php/hardcoded-key"}},
		{"php self:: class constant", "a.php", "<?php\nclass E {\n const KEY = '0123456789abcdef';\n function f($d, $iv) { return openssl_encrypt($d, 'aes-256-cbc', self::KEY, 0, $iv); }\n}", []string{"sast:php/hardcoded-key"}},
		{"php Class:: constant", "a.php", "<?php\nclass E {\n const KEY = '0123456789abcdef';\n function f($d, $iv) { return openssl_encrypt($d, 'aes-256-cbc', E::KEY, 0, $iv); }\n}", []string{"sast:php/hardcoded-key"}},
		{"php ecb mode is still weak crypto", "a.php", "<?php\nfunction f($d, $k) { return openssl_encrypt($d, 'aes-128-ecb', $k); }", []string{"sast:php/weak-crypto"}},
		{"php key from env", "a.php", "<?php\nfunction f($d, $iv) { return openssl_encrypt($d, 'aes-256-cbc', getenv('KEY'), 0, $iv); }", nil},
		{"python AES", "a.py", "from Crypto.Cipher import AES\n\ndef f():\n    return AES.new(b'0123456789abcdef', AES.MODE_GCM)\n", []string{"sast:py/hardcoded-key"}},
		{"python key from env", "a.py", "import os\nfrom Crypto.Cipher import AES\n\ndef f():\n    return AES.new(os.environ['K'].encode(), AES.MODE_GCM)\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{tt.file: tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
