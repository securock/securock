package sast

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/securock/securock/internal/finding"
	"gopkg.in/yaml.v3"
)

// Infrastructure-as-code checks. They share the finding model with the source rules but
// are configuration lookups, not dataflow: a setting that is present and unsafe.

type iacRule struct {
	id, cwe, title, fix string
	sev                 finding.Severity
}

var iacRules = map[string]iacRule{
	"docker-root-user":      {"sast:iac/docker-root-user", "CWE-250", "Container runs as root", "Add a USER instruction with an unprivileged user before the final CMD or ENTRYPOINT.", finding.SeverityMedium},
	"docker-unpinned-image": {"sast:iac/docker-unpinned-image", "CWE-829", "Base image is not pinned", "Pin the base image to a version tag, or better to a digest (image@sha256:...).", finding.SeverityLow},
	"docker-add-remote":     {"sast:iac/docker-add-remote", "CWE-494", "ADD downloads a remote file", "Download with curl or wget, verify its checksum, then COPY it.", finding.SeverityMedium},
	"docker-pipe-to-shell":  {"sast:iac/docker-pipe-to-shell", "CWE-494", "Downloaded script is piped to a shell", "Download the script, verify its checksum or signature, then run it.", finding.SeverityHigh},
	"docker-secret":         {"sast:iac/hardcoded-secret", "CWE-798", "Hard-coded credential", "Pass the secret at runtime or with a BuildKit secret mount instead of baking it into the image.", finding.SeverityHigh},
	"privileged":            {"sast:iac/privileged-container", "CWE-250", "Privileged container", "Remove privileged: true and grant only the specific capabilities the workload needs.", finding.SeverityHigh},
	"host-namespace":        {"sast:iac/host-namespace", "CWE-668", "Container shares a host namespace", "Remove hostNetwork, hostPID and hostIPC unless the workload truly needs them.", finding.SeverityHigh},
	"privilege-escalation":  {"sast:iac/privilege-escalation", "CWE-269", "Privilege escalation is allowed", "Set allowPrivilegeEscalation: false.", finding.SeverityMedium},
	"run-as-root":           {"sast:iac/run-as-root", "CWE-250", "Container is allowed to run as root", "Set runAsNonRoot: true and a non-zero runAsUser.", finding.SeverityMedium},
	"host-path":             {"sast:iac/host-path-mount", "CWE-668", "Host path is mounted", "Use a persistent volume or emptyDir instead of mounting the host filesystem.", finding.SeverityMedium},
	"docker-socket":         {"sast:iac/docker-socket-mount", "CWE-250", "Container Docker socket is mounted", "Do not mount /var/run/docker.sock; it gives the container control of the host.", finding.SeverityHigh},
	"dangerous-capability":  {"sast:iac/dangerous-capability", "CWE-250", "Container adds a dangerous capability", "Drop ALL capabilities and add back only the ones required.", finding.SeverityHigh},
	"unpinned-k8s-image":    {"sast:iac/docker-unpinned-image", "CWE-829", "Image is not pinned", "Pin the image to a version tag, or better to a digest.", finding.SeverityLow},
	"open-ingress":          {"sast:iac/open-ingress", "CWE-284", "Administrative port open to the internet", "Restrict the CIDR range to known addresses.", finding.SeverityHigh},
	"public-bucket":         {"sast:iac/public-bucket", "CWE-284", "Storage bucket is publicly accessible", "Use a private ACL and enable the public access block.", finding.SeverityHigh},
	"unencrypted-storage":   {"sast:iac/unencrypted-storage", "CWE-311", "Storage is not encrypted", "Enable encryption at rest.", finding.SeverityMedium},
	"public-database":       {"sast:iac/public-database", "CWE-284", "Database is publicly accessible", "Set publicly_accessible = false and reach it through a private network.", finding.SeverityHigh},
	"iam-wildcard":          {"sast:iac/iam-wildcard", "CWE-269", "IAM policy allows all actions on all resources", "Grant only the actions and resources the workload needs.", finding.SeverityHigh},
	"tf-secret":             {"sast:iac/hardcoded-secret", "CWE-798", "Hard-coded credential", "Read the secret from a variable marked sensitive or a secret manager.", finding.SeverityHigh},
	"actions-injection":     {"sast:iac/actions-script-injection", "CWE-78", "Workflow step interpolates untrusted input into a script", "Pass the value through an environment variable and reference it as \"$VAR\" in the script.", finding.SeverityHigh},
	"actions-pwn-request":   {"sast:iac/actions-pwn-request", "CWE-94", "pull_request_target checks out untrusted code", "Do not check out the pull request head in a pull_request_target workflow, or run it without secrets.", finding.SeverityHigh},
}

type iacScan struct {
	root, full, rel string
	out             []finding.Finding
}

func (s *iacScan) add(key string, line int, subject, detail string) {
	r := iacRules[key]
	s.out = append(s.out, finding.Finding{
		ID:          r.id,
		Severity:    r.sev,
		Title:       r.title + " (" + r.cwe + ")",
		Detail:      detail,
		Subject:     s.rel + "#" + subject,
		Remediation: r.fix,
		Location:    &finding.Location{File: s.rel, Line: max(line, 1)},
	})
}

func isDockerfile(name string) bool {
	low := strings.ToLower(name)
	return low == "dockerfile" || low == "containerfile" || strings.HasPrefix(low, "dockerfile.") ||
		strings.HasSuffix(low, ".dockerfile") || strings.HasSuffix(low, ".containerfile")
}

// iacKind classifies a file by name; yaml files are classified by content later.
func iacKind(rel, name string) string {
	low := strings.ToLower(name)
	switch {
	case isDockerfile(name):
		return "docker"
	case strings.HasSuffix(low, ".tf"):
		return "terraform"
	case strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml"):
		if strings.Contains(filepath.ToSlash(rel), ".github/workflows/") {
			return "actions"
		}
		return "yaml"
	}
	return ""
}

// scanIaC checks one configuration file and returns its findings. A file that cannot be
// read or parsed is reported as incomplete instead of passing silently.
func scanIaC(root, full, rel, kind string) []finding.Finding {
	st, err := os.Stat(full)
	if err != nil || st.Size() > maxFileBytes {
		if kind == "yaml" {
			return nil // a large YAML file is data, not a manifest
		}
		return []finding.Finding{unanalyzed(root, full, "file is larger than the analysis limit")}
	}
	src, err := os.ReadFile(full)
	if err != nil {
		return []finding.Finding{unanalyzed(root, full, "it cannot be read")}
	}
	s := &iacScan{root: root, full: full, rel: filepath.ToSlash(rel)}
	switch kind {
	case "docker":
		s.dockerfile(string(src))
	case "terraform":
		s.terraform(string(src))
	case "actions", "yaml":
		if !s.yamlFile(src, kind == "actions") {
			return []finding.Finding{unanalyzed(root, full, "it is not valid YAML")}
		}
	}
	return s.out
}

// ---- Dockerfile

var (
	reFrom       = regexp.MustCompile(`(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
	rePipeShell  = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:/\S*/)?(?:ba|z|da|k)?sh\b`)
	reEnvPair    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(.*)$`)
	reDigestSpec = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)
)

type dockerLine struct {
	n    int
	text string
}

// dockerLines joins backslash continuations and drops comments.
func dockerLines(src string) []dockerLine {
	var out []dockerLine
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(raw)
		if cur.Len() == 0 {
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			start = i + 1
		} else if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\") + " ")
			continue
		}
		cur.WriteString(t)
		out = append(out, dockerLine{start, cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, dockerLine{start, cur.String()})
	}
	return out
}

func (s *iacScan) dockerfile(src string) {
	lines := dockerLines(src)
	stages := map[string]bool{}
	lastUser, lastUserLine, lastFrom := "", 0, 0
	hasStage := false
	for _, l := range lines {
		word, rest, _ := strings.Cut(l.text, " ")
		rest = strings.TrimSpace(rest)
		switch strings.ToUpper(word) {
		case "FROM":
			hasStage = true
			lastUser, lastUserLine, lastFrom = "", 0, l.n
			m := reFrom.FindStringSubmatch(l.text)
			if m == nil {
				continue
			}
			image := m[1]
			if m[2] != "" {
				stages[strings.ToLower(m[2])] = true
			}
			if strings.EqualFold(image, "scratch") || stages[strings.ToLower(image)] || strings.Contains(image, "$") || reDigestSpec.MatchString(image) {
				continue
			}
			name := image
			if i := strings.LastIndex(name, "/"); i >= 0 {
				name = name[i+1:]
			}
			if !strings.Contains(name, ":") || strings.HasSuffix(name, ":latest") {
				s.add("docker-unpinned-image", l.n, "FROM "+image, image+" has no version tag or uses latest")
			}
		case "USER":
			lastUser, lastUserLine = strings.ToLower(strings.Fields(rest + " x")[0]), l.n
		case "ADD":
			for _, f := range strings.Fields(rest) {
				if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
					s.add("docker-add-remote", l.n, "ADD", "ADD fetches "+f)
					break
				}
			}
		case "RUN":
			if rePipeShell.MatchString(rest) {
				s.add("docker-pipe-to-shell", l.n, "RUN", "a downloaded script is executed without verification")
			}
		case "ENV", "ARG":
			s.dockerSecret(l, rest)
		}
	}
	if hasStage {
		switch {
		case lastUser == "" || lastUser == "root" || lastUser == "0" || strings.HasPrefix(lastUser, "root:") || strings.HasPrefix(lastUser, "0:"):
			line := lastUserLine
			if line == 0 {
				line = lastFrom
			}
			s.add("docker-root-user", line, "USER", "the final stage runs as root")
		}
	}
}

func (s *iacScan) dockerSecret(l dockerLine, rest string) {
	// ENV A=1 B=2 and ENV A 1 are both valid.
	pairs := []string{rest}
	if strings.Contains(rest, "=") {
		pairs = strings.Fields(rest)
	}
	for _, p := range pairs {
		m := reEnvPair.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		name, val := m[1], strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if secretName.MatchString(name) && !notSecret.MatchString(name) && looksLikeSecret(val) {
			s.add("docker-secret", l.n, name, name+" is set to a literal that looks like a secret")
		}
	}
}

// ---- YAML: Kubernetes, Compose, GitHub Actions

func (s *iacScan) yamlFile(src []byte, actions bool) bool {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	any := false
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				return true
			}
			// A YAML file that is a template (Helm) is not valid YAML; do not call it an
			// analysis failure for files that do not look like infrastructure anyway.
			return !any && !looksLikeInfra(src, actions)
		}
		any = true
		root := &doc
		if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
			root = root.Content[0]
		}
		if root.Kind != yaml.MappingNode {
			continue
		}
		switch {
		case actions || mapHas(root, "jobs") && mapHas(root, "on"):
			s.workflow(root)
		case mapHas(root, "apiVersion") && mapHas(root, "kind"):
			s.manifest(root, mapString(root, "kind"))
		case mapHas(root, "services"):
			s.manifest(root, "compose")
		}
	}
}

func looksLikeInfra(src []byte, actions bool) bool {
	return actions || bytes.Contains(src, []byte("apiVersion:")) || bytes.Contains(src, []byte("services:"))
}

func mapHas(n *yaml.Node, key string) bool { return mapGet(n, key) != nil }

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func mapString(n *yaml.Node, key string) string {
	if v := mapGet(n, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func yamlTrue(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && (n.Value == "true" || n.Value == "True" || n.Value == "yes")
}

func yamlFalse(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && (n.Value == "false" || n.Value == "False" || n.Value == "no")
}

var dangerousCaps = map[string]bool{"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true, "NET_RAW": true}

// manifest walks a Kubernetes or Compose document for unsafe settings. The keys are
// distinctive enough that matching them anywhere in the tree finds pods, workloads, cron
// jobs and compose services alike.
func (s *iacScan) manifest(root *yaml.Node, owner string) {
	name := owner
	if md := mapGet(root, "metadata"); md != nil {
		if n := mapString(md, "name"); n != "" {
			name = owner + "/" + n
		}
	}
	var walk func(n *yaml.Node, key string)
	walk = func(n *yaml.Node, key string) {
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				s.manifestKey(k, v, name, n)
				walk(v, k.Value)
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				if key == "volumes" && c.Kind == yaml.ScalarNode && strings.Contains(c.Value, "docker.sock") {
					s.add("docker-socket", c.Line, name, "the Docker socket is mounted into the container")
				}
				walk(c, key)
			}
		}
	}
	walk(root, "")
}

func (s *iacScan) manifestKey(k, v *yaml.Node, name string, parent *yaml.Node) {
	switch k.Value {
	case "privileged":
		if yamlTrue(v) {
			s.add("privileged", k.Line, name, "privileged: true gives the container full access to the host")
		}
	case "hostNetwork", "hostPID", "hostIPC":
		if yamlTrue(v) {
			s.add("host-namespace", k.Line, name, k.Value+": true shares the host namespace with the container")
		}
	case "network_mode", "pid", "ipc":
		if v.Kind == yaml.ScalarNode && v.Value == "host" {
			s.add("host-namespace", k.Line, name, k.Value+": host shares the host namespace with the container")
		}
	case "allowPrivilegeEscalation":
		if yamlTrue(v) {
			s.add("privilege-escalation", k.Line, name, "allowPrivilegeEscalation is true")
		}
	case "runAsNonRoot":
		if yamlFalse(v) {
			s.add("run-as-root", k.Line, name, "runAsNonRoot is false")
		}
	case "runAsUser":
		if v.Kind == yaml.ScalarNode && v.Value == "0" {
			s.add("run-as-root", k.Line, name, "runAsUser is 0")
		}
	case "hostPath":
		if v.Kind == yaml.MappingNode {
			s.add("host-path", k.Line, name, "hostPath mounts "+mapString(v, "path")+" from the node")
			if strings.Contains(mapString(v, "path"), "docker.sock") {
				s.add("docker-socket", k.Line, name, "the Docker socket is mounted into the container")
			}
		}
	case "add", "cap_add":
		if v.Kind == yaml.SequenceNode {
			for _, c := range v.Content {
				if dangerousCaps[strings.ToUpper(strings.TrimPrefix(c.Value, "CAP_"))] {
					s.add("dangerous-capability", c.Line, name, "capability "+c.Value+" is added")
				}
			}
		}
	case "image":
		if parent != nil && v.Kind == yaml.ScalarNode && (mapHas(parent, "name") || mapHas(parent, "ports") || mapHas(parent, "volumes") || mapHas(parent, "command")) {
			img := v.Value
			if img == "" || strings.Contains(img, "$") || reDigestSpec.MatchString(img) {
				return
			}
			base := img[strings.LastIndex(img, "/")+1:]
			if !strings.Contains(base, ":") || strings.HasSuffix(base, ":latest") {
				s.add("unpinned-k8s-image", v.Line, name, img+" has no version tag or uses latest")
			}
		}
	}
}

// ---- GitHub Actions

var untrustedContext = regexp.MustCompile(`\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.(ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|head_commit\.(message|author\.(email|name))|commits\[[^}]*\]\.message|discussion\.(title|body))|github\.head_ref)\s*\}\}`)

func (s *iacScan) workflow(root *yaml.Node) {
	on := mapGet(root, "on")
	if on == nil {
		on = mapGet(root, "true") // YAML 1.1 reads the key "on" as a boolean
	}
	targetEvent := false
	if on != nil {
		switch on.Kind {
		case yaml.ScalarNode:
			targetEvent = on.Value == "pull_request_target"
		case yaml.SequenceNode:
			for _, c := range on.Content {
				targetEvent = targetEvent || c.Value == "pull_request_target"
			}
		case yaml.MappingNode:
			targetEvent = mapHas(on, "pull_request_target")
		}
	}
	jobs := mapGet(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job, steps := jobs.Content[i].Value, mapGet(jobs.Content[i+1], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if run := mapGet(step, "run"); run != nil && run.Kind == yaml.ScalarNode {
				if m := untrustedContext.FindString(run.Value); m != "" {
					s.add("actions-injection", run.Line, job, m+" is expanded into the script before the shell parses it")
				}
			}
			if script := mapGet(mapGet(step, "with"), "script"); script != nil && script.Kind == yaml.ScalarNode && strings.HasPrefix(mapString(step, "uses"), "actions/github-script") {
				if m := untrustedContext.FindString(script.Value); m != "" {
					s.add("actions-injection", script.Line, job, m+" is expanded into the script before it runs")
				}
			}
			if targetEvent && strings.HasPrefix(mapString(step, "uses"), "actions/checkout") {
				ref := mapString(mapGet(step, "with"), "ref")
				if strings.Contains(ref, "github.event.pull_request.head") || strings.Contains(ref, "github.head_ref") {
					s.add("actions-pwn-request", mapGet(mapGet(step, "with"), "ref").Line, job, "a pull_request_target workflow checks out "+ref)
				}
			}
		}
	}
}

// ---- Terraform

var (
	reTFResource = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
	reTFAttr     = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*(?:#.*)?$`)
	reQuoted     = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"$`)
)

type tfBlock struct {
	typ, name  string
	start, end int // 0-based line indexes, inclusive
}

// terraform finds resource blocks by brace matching. Strings and heredocs can hide
// braces, so a block that does not balance is skipped rather than guessed at.
func (s *iacScan) terraform(src string) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		m := reTFResource.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		end := matchBrace(lines, i)
		if end < 0 {
			s.out = append(s.out, unanalyzed(s.root, s.full, "a resource block has unbalanced braces"))
			continue
		}
		s.tfResource(lines, tfBlock{m[1], m[2], i, end})
		i = end
	}
}

func matchBrace(lines []string, start int) int {
	depth := 0
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if j := strings.Index(l, "#"); j >= 0 && !strings.Contains(l[:j], `"`) {
			l = l[:j]
		}
		inStr := false
		for k := 0; k < len(l); k++ {
			switch c := l[k]; {
			case c == '\\' && inStr:
				k++
			case c == '"':
				inStr = !inStr
			case !inStr && c == '{':
				depth++
			case !inStr && c == '}':
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func attrValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if m := reQuoted.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	return raw
}

func (s *iacScan) tfResource(lines []string, b tfBlock) {
	subject := b.typ + "." + b.name
	attrs := map[string]struct {
		val  string
		line int
	}{}
	for i := b.start + 1; i < b.end; i++ {
		if m := reTFAttr.FindStringSubmatch(lines[i]); m != nil {
			if _, dup := attrs[m[1]]; !dup {
				attrs[m[1]] = struct {
					val  string
					line int
				}{attrValue(m[2]), i + 1}
			}
		}
	}
	text := strings.Join(lines[b.start:b.end+1], "\n")

	for name, a := range attrs {
		if secretName.MatchString(name) && !notSecret.MatchString(name) && !strings.HasPrefix(a.val, "var.") && !strings.HasPrefix(a.val, "data.") &&
			!strings.HasPrefix(a.val, "local.") && !strings.HasPrefix(a.val, "aws_") && !strings.HasPrefix(a.val, "random_") &&
			reQuoted.MatchString(strings.TrimSpace(lines[a.line-1][strings.Index(lines[a.line-1], "=")+1:])) && looksLikeSecret(a.val) {
			s.add("tf-secret", a.line, subject, name+" is set to a literal that looks like a secret")
		}
	}
	switch b.typ {
	case "aws_s3_bucket", "aws_s3_bucket_acl":
		if a, ok := attrs["acl"]; ok && (a.val == "public-read" || a.val == "public-read-write") {
			s.add("public-bucket", a.line, subject, "acl is "+a.val)
		}
	case "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster":
		if a, ok := attrs["publicly_accessible"]; ok && a.val == "true" {
			s.add("public-database", a.line, subject, "publicly_accessible is true")
		}
	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		if t := attrs["type"].val; b.typ == "aws_security_group_rule" && t != "ingress" {
			break
		}
		s.tfIngress(subject, lines, b.start, b.end)
	case "aws_security_group":
		for i := b.start + 1; i < b.end; i++ {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "ingress") && strings.Contains(lines[i], "{") {
				if e := matchBrace(lines, i); e > 0 {
					s.tfIngress(subject, lines, i, e)
					i = e
				}
			}
		}
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
		if iamWildcard.MatchString(text) {
			s.add("iam-wildcard", b.start+1, subject, `the policy allows Action "*" on Resource "*"`)
		}
	}
	for name, a := range attrs {
		switch name {
		case "storage_encrypted", "encrypted", "at_rest_encryption_enabled", "kms_encrypted":
			if a.val == "false" {
				s.add("unencrypted-storage", a.line, subject, name+" is false")
			}
		}
	}
}

var iamWildcard = regexp.MustCompile(`(?s)"Effect"\s*[:=]\s*"Allow".*?"Action"\s*[:=]\s*(?:\[\s*)?"\*".*?"Resource"\s*[:=]\s*(?:\[\s*)?"\*"|"Action"\s*[:=]\s*(?:\[\s*)?"\*".*?"Resource"\s*[:=]\s*(?:\[\s*)?"\*".*?"Effect"\s*[:=]\s*"Allow"`)

var reCIDRAny = regexp.MustCompile(`"(0\.0\.0\.0/0|::/0)"`)

// tfIngress flags a rule open to the world on SSH, RDP, or every port.
func (s *iacScan) tfIngress(subject string, lines []string, start, end int) {
	block := strings.Join(lines[start:end+1], "\n")
	if !reCIDRAny.MatchString(block) {
		return
	}
	get := func(key string) (int, bool) {
		m := regexp.MustCompile(`(?m)^\s*` + key + `\s*=\s*"?(-?\d+)"?`).FindStringSubmatch(block)
		if m == nil {
			return 0, false
		}
		n, err := strconv.Atoi(m[1])
		return n, err == nil
	}
	from, okF := get("from_port")
	to, okT := get("to_port")
	if !okF || !okT {
		return
	}
	proto := regexp.MustCompile(`(?m)^\s*(?:ip_)?protocol\s*=\s*"?([^"\s]+)"?`).FindStringSubmatch(block)
	allProtocols := proto != nil && (proto[1] == "-1" || proto[1] == "all")
	covers := func(p int) bool { return from <= p && p <= to }
	var what string
	switch {
	case allProtocols || (from == 0 && (to == 0 || to == 65535)):
		what = "all ports"
	case covers(22):
		what = "SSH (22)"
	case covers(3389):
		what = "RDP (3389)"
	default:
		return
	}
	s.add("open-ingress", start+1, subject, fmt.Sprintf("%s is open to 0.0.0.0/0", what))
}
