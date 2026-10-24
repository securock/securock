package sast_test

import (
	"slices"
	"strings"
	"testing"
)

func TestJavaSessionKeys(t *testing.T) {
	for _, tt := range []struct {
		name, call string
		bad        bool
	}{
		{"untrusted key", `request.getSession().setAttribute(request.getParameter("key"), "fixed");`, true},
		{"untrusted value", `request.getSession().setAttribute("profile", request.getParameter("value"));`, true},
		{"legacy untrusted key", `request.getSession().putValue(request.getParameter("key"), "fixed");`, true},
		{"html escaping is not key validation", `request.getSession().setAttribute(org.owasp.encoder.Encode.forHtml(request.getParameter("key")), "fixed");`, true},
		{"fixed key and value", `request.getSession().setAttribute("role", "viewer");`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := `import javax.servlet.http.HttpServletRequest; class Route { void run(HttpServletRequest request) { ` + tt.call + ` } }`
			var want []string
			if tt.bad {
				want = []string{"sast:java/trust-boundary"}
			}
			if got := analyze(t, map[string]string{"Route.java": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestJavaRandomBufferEffects(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		bad        bool
	}{
		{"direct receiver", `byte[] data = new byte[24]; new Random().nextBytes(data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, true},
		{"receiver variable", `Random generator = new Random(); byte[] data = new byte[24]; generator.nextBytes(data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, true},
		{"buffer alias", `byte[] data = new byte[24]; byte[] alias = data; new Random().nextBytes(alias); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, true},
		{"helper effect", `byte[] data = new byte[24]; fill(new Random(), data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, true},
		{"secure generator", `byte[] data = new byte[24]; new SecureRandom().nextBytes(data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, false},
		{"secure generator through Random type", `Random generator = new SecureRandom(); byte[] data = new byte[24]; generator.nextBytes(data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, false},
		{"secure helper", `byte[] data = new byte[24]; fill(new SecureRandom(), data); Cookie cookie = new Cookie("id", Base64.getEncoder().encodeToString(data));`, false},
		{"nonsecret random buffer", `byte[] data = new byte[24]; new Random().nextBytes(data); System.out.println(data.length);`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.body
			if strings.Contains(body, "Cookie cookie") {
				body += ` cookie.setSecure(true); cookie.setHttpOnly(true);`
			}
			src := `import java.util.Random; import java.util.Base64; import java.security.SecureRandom; import javax.servlet.http.Cookie;
class Route { static void fill(Random generator, byte[] output) { generator.nextBytes(output); } void run() { ` + body + ` } }`
			var want []string
			if tt.bad {
				want = []string{"sast:java/insecure-random"}
			}
			if got := analyze(t, map[string]string{"Route.java": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
