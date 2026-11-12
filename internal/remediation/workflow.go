package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type TestPlan struct {
	Commands [][]string `json:"commands"`
}
type Workflow struct {
	Version  int      `json:"version"`
	Branch   string   `json:"branch"`
	Files    []string `json:"files"`
	Tests    int      `json:"tests"`
	Revision string   `json:"revision"`
	Verified bool     `json:"verified"`
}

func ReadTests(r io.Reader) (TestPlan, error) {
	var p TestPlan
	d := json.NewDecoder(io.LimitReader(r, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || len(p.Commands) == 0 || len(p.Commands) > 20 {
		return p, fmt.Errorf("test plan requires 1-20 commands")
	}
	for _, cmd := range p.Commands {
		if len(cmd) == 0 || cmd[0] == "" {
			return p, fmt.Errorf("invalid test command")
		}
	}
	return p, nil
}
func Fix(ctx context.Context, project, branch string, report finding.Report, tests TestPlan) (Workflow, error) {
	out := Workflow{Version: 1, Branch: branch, Files: []string{}}
	if len(tests.Commands) == 0 {
		return out, fmt.Errorf("test plan required")
	}
	git := func(args ...string) ([]byte, error) {
		return external.Run(ctx, "git", append([]string{"-c", "core.fsmonitor=false", "-C", project}, args...)...)
	}
	if _, e := git("check-ref-format", "--branch", branch); e != nil || strings.HasPrefix(branch, "-") {
		return out, fmt.Errorf("invalid branch")
	}
	dirty, e := git("status", "--porcelain")
	if e != nil || len(bytes.TrimSpace(dirty)) > 0 {
		return out, fmt.Errorf("clean project required")
	}
	if _, e := git("show-ref", "--verify", "--quiet", "refs/heads/"+branch); e == nil {
		return out, fmt.Errorf("branch already exists")
	}
	temp, e := os.MkdirTemp("", "securock-fix-*")
	if e != nil {
		return out, e
	}
	_ = os.Remove(temp)
	if _, e = git("worktree", "add", "-b", branch, temp, "HEAD"); e != nil {
		return out, e
	}
	defer func() { _, _ = git("worktree", "remove", "--force", temp) }()
	before, e := sast.Analyze(temp)
	if e != nil {
		return out, e
	}
	seen := map[string]bool{}
	patch := ""
	for _, f := range report.Findings {
		if f.Suppressed != nil || f.Location == nil {
			continue
		}
		if strings.ContainsAny(f.Location.File, "\r\n\t") {
			return out, fmt.Errorf("unsupported patch path")
		}
		key := fmt.Sprint(f.Location.File, ":", f.Location.Line)
		if seen[key] {
			continue
		}
		p, e := Patch(temp, f)
		if e != nil {
			return out, e
		}
		if p != "" {
			patch += p
			seen[key] = true
			if !slices.Contains(out.Files, f.Location.File) {
				out.Files = append(out.Files, f.Location.File)
			}
		}
	}
	if patch == "" {
		return out, fmt.Errorf("no supported fixes")
	}
	fd, e := os.CreateTemp("", "securock-patch-*")
	if e != nil {
		return out, e
	}
	file := fd.Name()
	defer os.Remove(file)
	if _, e = fd.WriteString(patch); e != nil {
		fd.Close()
		return out, e
	}
	if e = fd.Close(); e != nil {
		return out, e
	}
	if _, e = external.Run(ctx, "git", "-C", temp, "apply", "--unidiff-zero", "--check", file); e != nil {
		return out, e
	}
	if _, e = external.Run(ctx, "git", "-C", temp, "apply", "--unidiff-zero", file); e != nil {
		return out, e
	}
	for _, args := range tests.Commands {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		cmd := exec.CommandContext(runCtx, args[0], args[1:]...)
		cmd.Dir = temp
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.WaitDelay = time.Second
		e := cmd.Run()
		cancel()
		if e != nil {
			return out, fmt.Errorf("remediation test %d failed", out.Tests+1)
		}
		out.Tests++
	}
	after, e := sast.Analyze(temp)
	if e != nil {
		return out, e
	}
	for _, f := range after {
		if f.ID == "sast:go/tls-verification-disabled" {
			return out, fmt.Errorf("targeted TLS finding remains")
		}
	}
	if baseline.New(finding.New("sast", before), finding.New("sast", after)).AtLeast(finding.SeverityHigh) > 0 {
		return out, fmt.Errorf("new high findings after remediation")
	}
	changed, e := external.Run(ctx, "git", "-C", temp, "diff", "--name-only", "-z")
	if e != nil {
		return out, e
	}
	for _, name := range bytes.Split(changed, []byte{0}) {
		if len(name) > 0 && !slices.Contains(out.Files, string(name)) {
			return out, fmt.Errorf("tests changed an unrelated tracked file")
		}
	}
	args := append([]string{"-C", temp, "add", "--"}, out.Files...)
	if _, e = external.Run(ctx, "git", args...); e != nil {
		return out, e
	}
	if _, e = external.Run(ctx, "git", "-C", temp, "commit", "-m", "fix: restore tls certificate verification"); e != nil {
		return out, e
	}
	raw, e := external.Run(ctx, "git", "-C", temp, "rev-parse", "HEAD")
	if e != nil {
		return out, e
	}
	out.Revision = strings.TrimSpace(string(raw))
	out.Verified = true
	slices.Sort(out.Files)
	return out, nil
}
