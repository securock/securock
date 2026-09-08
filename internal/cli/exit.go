package cli

import (
	"errors"
	"fmt"
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
