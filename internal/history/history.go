package history

import (
	"bytes"
	"context"
	"fmt"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Options struct {
	Path       string
	Revision   string
	AllRefs    bool
	MaxCommits int
	MaxBlobs   int
}

func Scan(ctx context.Context, o Options) (finding.Report, error) {
	found := []finding.Finding{}
	incomplete := func(message string) (finding.Report, error) {
		found = append(found, finding.Finding{ID: "history:analysis-incomplete", Severity: finding.SeverityHigh, Title: "Git history scan did not complete", Detail: message, Remediation: "Increase explicit scan budgets or repair repository access, then rescan."})
		return finding.New("history", found), fmt.Errorf("history analysis incomplete: %s", message)
	}
	if o.MaxCommits < 1 || o.MaxBlobs < 1 || o.MaxCommits > 100000 || o.MaxBlobs > 1000000 {
		return finding.New("history", nil), fmt.Errorf("invalid history scan budgets")
	}
	git := func(args ...string) ([]byte, error) {
		return external.Run(ctx, "git", append([]string{"-c", "core.fsmonitor=false", "-C", o.Path}, args...)...)
	}
	config := exec.CommandContext(ctx, "git", "-C", o.Path, "config", "--includes", "--get-regexp", `^(extensions\.partialclone|remote\..*\.promisor)$`)
	config.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	if raw, e := config.Output(); e == nil && len(raw) > 0 {
		return incomplete("Partial clone configuration is unsupported; use a fully materialized local clone.")
	} else if e != nil {
		if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return incomplete("Cannot inspect repository clone configuration.")
		}
	}
	shallow, e := git("rev-parse", "--is-shallow-repository")
	if e != nil || (strings.TrimSpace(string(shallow)) != "true" && strings.TrimSpace(string(shallow)) != "false") {
		return incomplete("Cannot inspect repository history coverage.")
	}
	args := []string{"rev-list", "--max-count=" + strconv.Itoa(o.MaxCommits+1)}
	if o.AllRefs {
		args = append(args, "--all")
	} else {
		rev, e := git("rev-parse", "--verify", "--end-of-options", o.Revision+"^{commit}")
		if e != nil {
			return incomplete("Cannot resolve the selected revision.")
		}
		args = append(args, strings.TrimSpace(string(rev)))
	}
	raw, e := git(args...)
	if e != nil {
		return incomplete("Cannot enumerate reachable commits.")
	}
	commits := strings.Fields(string(raw))
	truncated := len(commits) > o.MaxCommits
	if truncated {
		commits = commits[:o.MaxCommits]
	}
	seen := map[string]bool{}
	count := 0
	for _, commit := range commits {
		tree, e := git("ls-tree", "-r", "-z", "--full-tree", commit)
		if e != nil {
			return incomplete("Cannot read a commit tree.")
		}
		for _, entry := range bytes.Split(tree, []byte{0}) {
			if len(entry) == 0 {
				continue
			}
			metadata, path, ok := strings.Cut(string(entry), "\t")
			parts := strings.Fields(metadata)
			if !ok || len(parts) != 3 {
				return incomplete("Invalid Git tree entry.")
			}
			if parts[1] != "blob" || (parts[0] != "100644" && parts[0] != "100755") {
				continue
			}
			oid := parts[2]
			if seen[oid] {
				continue
			}
			seen[oid] = true
			count++
			if count > o.MaxBlobs {
				return incomplete("Blob budget reached; not all reachable content was evaluated.")
			}
			sizeRaw, e := git("cat-file", "-s", oid)
			if e != nil {
				return incomplete("Cannot inspect a blob size.")
			}
			size, e := strconv.ParseInt(strings.TrimSpace(string(sizeRaw)), 10, 64)
			if e != nil {
				return incomplete("Invalid blob size.")
			}
			if size > 512<<10 {
				found = append(found, finding.Finding{ID: "history:content-unchecked", Severity: finding.SeverityInfo, Title: "Historical blob exceeds secret scanner size limit", Subject: commit + ":" + path})
				continue
			}
			content, e := git("cat-file", "blob", oid)
			if e != nil {
				return incomplete("Cannot read historical blob content.")
			}
			if bytes.IndexByte(content[:min(len(content), 8192)], 0) >= 0 {
				continue
			}
			for _, f := range sast.SecretContent(path, content) {
				f.ID = "history:" + strings.TrimPrefix(f.ID, "sast:")
				f.Subject = oid + ":" + path
				f.Detail = "Credential pattern found in a reachable historical blob; value is not shown. Observed at commit " + commit + "."
				f.Location = nil
				found = append(found, f)
			}
		}
	}
	if strings.TrimSpace(string(shallow)) == "true" {
		return incomplete("Shallow clone excludes earlier history.")
	}
	if truncated {
		return incomplete("Commit budget reached; additional reachable commits were not evaluated.")
	}
	return finding.New("history", found), nil
}
