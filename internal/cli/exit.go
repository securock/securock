package cli

import (
	"errors"
	"fmt"

	"github.com/securock/securock/internal/finding"
)

const (
	exitOK    = 0
	exitTrust = 1
	exitFail  = 2
)

type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string {
	return e.msg
}

func trustErr(format string, args ...any) error {
	return exitError{code: exitTrust, msg: fmt.Sprintf(format, args...)}
}

func opErr(err error) error {
	if err == nil {
		return nil
	}
	var e exitError
	if errors.As(err, &e) {
		return err
	}
	return exitError{code: exitFail, msg: err.Error()}
}

func asExit(err error, target *exitError) bool {
	return errors.As(err, target)
}

// incompleteErr is the fail-closed result for a source analysis that left files
// unanalyzed. Severity ranks vulnerabilities, not whether the scan finished, so this
// is not gated by --fail-on or --no-fail: an unfinished scan must not read as a pass.
// Accepting the finding with an exception is the explicit way to allow it.
func incompleteErr(report finding.Report) error {
	n := 0
	for _, f := range report.Findings {
		if f.ID == "sast:analysis-incomplete" && f.Suppressed == nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return exitError{code: exitFail, msg: fmt.Sprintf("source analysis incomplete: %d file(s) not analyzed; vulnerabilities in them are unknown, not absent", n)}
}
