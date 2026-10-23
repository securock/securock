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
