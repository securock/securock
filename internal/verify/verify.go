package verify

import (
	"github.com/securock/securock/internal/diff"
	"github.com/securock/securock/pkg/lockfile"
)

func Compare(locked, current lockfile.Document) diff.Result {
	return diff.Compare(locked, current)
}
