package cli

import (
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/runrecord"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
	"os/exec"
	"strings"
)

func metadataGit(cmd *cobra.Command, path string, args ...string) *exec.Cmd {
	c := exec.CommandContext(cmd.Context(), "git", append([]string{"-c", "core.fsmonitor=false", "-C", path}, args...)...)
	c.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	return c
}
func writeRunRecord(cmd *cobra.Command, opts *options, path, output, scope string, r finding.Report, success bool, policyDigest string) error {
	revision := "unknown"
	dirty := true
	if raw, e := metadataGit(cmd, path, "rev-parse", "HEAD").Output(); e == nil {
		revision = strings.TrimSpace(string(raw))
		check := metadataGit(cmd, path, "config", "--includes", "--get-regexp", `^(extensions\.partialclone|remote\..*\.promisor)$`)
		if _, err := check.Output(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
				raw, e = metadataGit(cmd, path, "status", "--porcelain").Output()
				dirty = e != nil || len(raw) > 0
			}
		}
	}
	config := map[string]string{"policy_digest": policyDigest}
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		switch f.Name {
		case "record", "coverage-output", "output", "format", "no-fail":
			return
		}
		config[f.Name] = f.Value.String()
	})
	files, e := runrecord.SourceFiles(path)
	if e != nil {
		return fmt.Errorf("cannot inventory source files: %w", e)
	}
	engine := opts.toolVersion
	if strings.HasPrefix(engine, "dev") || strings.Contains(engine, "none") || engine == "@" {
		engine, e = runrecord.ExecutableIdentity()
		if e != nil {
			return e
		}
	}
	return runrecord.Write(output, runrecord.New(engine, revision, runrecord.Digest(config), scope, dirty, files, r, success))
}
