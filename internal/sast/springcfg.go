package sast

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/finding"
	"gopkg.in/yaml.v3"
)

// Spring Boot settings that expose internals or turn protections off. They are looked up
// in application*.properties and application*.yml, flattened to dotted keys.

type springRule struct {
	key, id, cwe, title, fix string
	bad                      func(v string) bool
	sev                      finding.Severity
}

func isOneOf(vals ...string) func(string) bool {
	return func(v string) bool {
		v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
		for _, x := range vals {
			if v == x {
				return true
			}
		}
		return false
	}
}

var springRules = []springRule{
	{"management.endpoints.web.exposure.include", "spring-actuator-exposed", "CWE-200", "All actuator endpoints are exposed over HTTP",
		"List only the endpoints you need (health, info) and put the rest behind authentication.", func(v string) bool { return strings.Contains(v, "*") }, finding.SeverityHigh},
	{"management.endpoint.env.show-values", "spring-actuator-exposed", "CWE-200", "Actuator shows environment values",
		"Use when-authorized or never.", isOneOf("always"), finding.SeverityMedium},
	{"spring.h2.console.enabled", "spring-h2-console", "CWE-489", "The H2 database console is enabled",
		"Disable the console outside local development; it allows remote code execution when exposed.", isOneOf("true"), finding.SeverityHigh},
	{"server.error.include-stacktrace", "spring-error-detail", "CWE-209", "Stack traces are returned to clients",
		"Use never, or on_param only in development.", isOneOf("always"), finding.SeverityMedium},
	{"server.error.include-message", "spring-error-detail", "CWE-209", "Exception messages are returned to clients",
		"Use never.", isOneOf("always"), finding.SeverityLow},
	{"server.ssl.enabled", "spring-tls-off", "CWE-319", "TLS is switched off on the embedded server",
		"Terminate TLS in the server or in a trusted proxy and say so in the deployment.", isOneOf("false"), finding.SeverityMedium},
	{"spring.security.csrf.enabled", "spring-csrf-off", "CWE-352", "CSRF protection is switched off",
		"Keep CSRF protection on for state-changing requests.", isOneOf("false"), finding.SeverityMedium},
	{"debug", "spring-debug", "CWE-489", "Debug logging is enabled",
		"Do not ship debug=true.", isOneOf("true"), finding.SeverityLow},
	{"spring.devtools.restart.enabled", "spring-devtools", "CWE-489", "Spring DevTools is enabled",
		"Exclude DevTools from production builds.", isOneOf("true"), finding.SeverityLow},
}

func isSpringConfig(name string) bool {
	low := strings.ToLower(name)
	if !strings.HasPrefix(low, "application") && !strings.HasPrefix(low, "bootstrap") {
		return false
	}
	return strings.HasSuffix(low, ".properties") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")
}

// scanSpringConfig reports the unsafe settings of one Spring Boot configuration file.
func scanSpringConfig(full, rel string) []finding.Finding {
	st, err := os.Stat(full)
	if err != nil || st.Size() > 256<<10 {
		return nil
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil
	}
	rel = filepath.ToSlash(rel)
	values := map[string]string{}
	lines := map[string]int{}
	if strings.HasSuffix(strings.ToLower(full), ".properties") {
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == '!' {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				k = strings.TrimSpace(k)
				values[k], lines[k] = strings.TrimSpace(v), i+1
			}
		}
	} else {
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		for {
			var n yaml.Node
			if dec.Decode(&n) != nil {
				break
			}
			root := &n
			if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
				root = root.Content[0]
			}
			flattenYAML(root, "", values, lines)
		}
	}
	var out []finding.Finding
	for _, r := range springRules {
		v, ok := values[r.key]
		if !ok || !r.bad(v) {
			continue
		}
		out = append(out, finding.Finding{
			ID:          "sast:config/" + r.id,
			Severity:    r.sev,
			Title:       r.title + " (" + r.cwe + ")",
			Detail:      r.key + " is " + v,
			Subject:     rel + "#" + r.key,
			Remediation: r.fix,
			Location:    &finding.Location{File: rel, Line: max(lines[r.key], 1)},
		})
	}
	return out
}

func flattenYAML(n *yaml.Node, prefix string, values map[string]string, lines map[string]int) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if prefix != "" {
				k = prefix + "." + k
			}
			flattenYAML(n.Content[i+1], k, values, lines)
		}
	case yaml.ScalarNode:
		values[prefix], lines[prefix] = n.Value, n.Line
	case yaml.SequenceNode:
		var parts []string
		for _, c := range n.Content {
			parts = append(parts, c.Value)
		}
		values[prefix], lines[prefix] = strings.Join(parts, ","), n.Line
	}
}
