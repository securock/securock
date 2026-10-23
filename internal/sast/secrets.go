package sast

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Credentials committed to the repository. Provider tokens have a fixed shape and are
// reported wherever they appear; a generic "password = <literal>" is reported only in
// files that hold configuration or code, and only when the literal looks random.

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b`)},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"stripe-key", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"pypi-token", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`)},
	{"sendgrid-key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{32,}\b`)},
	{"openai-key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b`)},
	{"twilio-key", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
}

var (
	reKeyedQuoted = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']([^"'\s]{12,128})["']`)
	reKeyedBare   = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token)[A-Za-z0-9_.-]*)\s*[:=]\s*([^\s"'#]{12,128})\s*$`)
	// referenceLike values name another variable (var.db_password, config.apiKey,
	// my_secret_name) rather than being a credential.
	referenceLike = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_\[\]-]*)+|[a-z_][a-z0-9_]*|[A-Z_][A-Z0-9_]*)$`)
	// "Server=db;Password=hunter2;" and "postgres://user:hunter2@db/app": a credential
	// inside a connection string, which the name-based patterns do not see.
	reConnPassword  = regexp.MustCompile(`(?i)\b(?:password|pwd)\s*=\s*([^;"'\s{}$<>%]{4,64})\s*(?:;|"|'|$)`)
	reConnContext   = regexp.MustCompile(`(?i)(server|data source|host|database|initial catalog|user id|uid|provider|dsn|port)\s*=`)
	reURLPassword   = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^:/@\s"'{}$<>]+:([^@\s"'{}$<>/]{4,64})@[^\s"'{}$<>]+`)
	placeholderWord = regexp.MustCompile(`(?i)example|sample|dummy|fake|placeholder|changeme|your[_-]|xxxx|redacted|\*{4}`)
)

// skippedForSecrets are files whose content is data or generated: hashes in lockfiles and
// source maps look like secrets and are not.
func skippedForSecrets(name string) bool {
	low := strings.ToLower(name)
	switch low {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "cargo.lock", "composer.lock", "poetry.lock",
		"gemfile.lock", "securock.lock", "bun.lockb", "pipfile.lock", "mix.lock", "pubspec.lock", "packages.lock.json":
		return true
	}
	switch strings.ToLower(filepath.Ext(low)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2", ".ttf", ".eot",
		".mp3", ".mp4", ".mov", ".wasm", ".so", ".dylib", ".dll", ".exe", ".class", ".jar", ".pyc", ".map", ".svg",
		".md", ".mdx", ".rst", ".txt", ".csv", ".lock", ".sum", ".min":
		return true
	}
	return strings.HasSuffix(low, ".min.js") || strings.HasSuffix(low, ".min.css")
}

func isCodeFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".php", ".rb", ".kt", ".cs", ".rs", ".go", ".gradle":
		return true
	}
	return false
}

// keyedFile reports files where "name = literal" is configuration or code worth checking.
func keyedFile(name string) (check bool, isGo bool) {
	low := strings.ToLower(name)
	if low == ".env" || strings.HasPrefix(low, ".env.") || strings.HasSuffix(low, ".env") {
		return true, false
	}
	switch strings.ToLower(filepath.Ext(low)) {
	case ".go":
		return true, true
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".php", ".rb", ".yaml", ".yml", ".json", ".properties",
		".ini", ".cfg", ".conf", ".toml", ".tf", ".tfvars", ".sh", ".kt", ".cs", ".rs", ".xml", ".gradle":
		return true, false
	}
	return false, false
}

// scanSecrets reads one file and reports the credentials in it. The value itself is never
// copied into the report.
func scanSecrets(root, full, rel, name string) []finding.Finding {
	if skippedForSecrets(name) {
		return nil
	}
	st, err := os.Stat(full)
	if err != nil || st.Size() == 0 || st.Size() > 512<<10 {
		return nil
	}
	src, err := os.ReadFile(full)
	if err != nil || bytes.IndexByte(src[:min(len(src), 8192)], 0) >= 0 {
		return nil
	}
	keyed, isGo := keyedFile(name)
	rel = filepath.ToSlash(rel)
	var out []finding.Finding
	seen := map[string]bool{}
	add := func(kind string, line int, sev finding.Severity, detail string) {
		key := kind + "|" + rel + "|" + string(rune(line))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, finding.Finding{
			ID:          "sast:secrets/" + kind,
			Severity:    sev,
			Title:       "Credential committed to the repository (CWE-798)",
			Detail:      detail,
			Subject:     rel + "#" + kind,
			Remediation: "Revoke and rotate the credential, remove it from the history, and load it from the environment or a secret manager.",
			Location:    &finding.Location{File: rel, Line: line},
		})
	}
	for i, line := range strings.Split(string(src), "\n") {
		if len(line) > 2000 || placeholderWord.MatchString(line) {
			continue
		}
		for _, p := range secretPatterns {
			if p.re.MatchString(line) {
				add(p.name, i+1, finding.SeverityHigh, p.name+" found; the value is not shown")
			}
		}
		if keyed {
			if m := reConnPassword.FindStringSubmatch(line); m != nil && reConnContext.MatchString(line) && !referenceLike.MatchString(m[1]) && !strings.ContainsAny(m[1], "()[]") && len(m[1]) >= 6 {
				add("connection-string-password", i+1, finding.SeverityMedium, "a connection string contains a password")
			} else if m := reURLPassword.FindStringSubmatch(line); m != nil && !referenceLike.MatchString(m[1]) && !strings.EqualFold(m[1], "password") {
				add("url-credentials", i+1, finding.SeverityMedium, "a URL contains a user name and password")
			}
		}
		if !keyed || isGo {
			continue // Go literals are reported by the typed analysis
		}
		res := []*regexp.Regexp{reKeyedQuoted}
		if !isCodeFile(name) {
			// "KEY=value" with no quotes is configuration; in code it is an expression.
			res = append(res, reKeyedBare)
		}
		for _, re := range res {
			if m := re.FindStringSubmatch(line); m != nil && !notSecret.MatchString(m[1]) && !referenceLike.MatchString(m[2]) &&
				!strings.ContainsAny(m[2], "()[]{};,<>\"'`") && looksLikeSecret(m[2]) {
				add("hardcoded-credential", i+1, finding.SeverityMedium, m[1]+" is set to a literal that looks like a secret")
				break
			}
		}
	}
	return out
}
