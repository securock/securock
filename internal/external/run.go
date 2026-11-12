package external

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type limited struct{ data bytes.Buffer }

func (b *limited) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > 32<<20 {
		return 0, fmt.Errorf("scanner output exceeds limit")
	}
	return b.data.Write(p)
}
func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return RunAt(ctx, "", name, args...)
}
func RunAt(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	var out limited
	c.Stdout = &out
	c.Stderr = io.Discard
	c.WaitDelay = time.Second
	c.Env = append(os.Environ(), "TRIVY_SKIP_VERSION_CHECK=true")
	if name == "git" {
		c.Env = append(c.Env, "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	}
	if c.Run() != nil {
		return nil, fmt.Errorf("%s scanner failed; check installation, configuration, and permissions", name)
	}
	return out.data.Bytes(), nil
}
