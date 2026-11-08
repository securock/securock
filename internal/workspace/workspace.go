// Package workspace finds the projects in a repository that holds more than one, such as
// a monorepo with a lockfile per service.
package workspace

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/securock/securock/internal/ecosystem"
)

// skipped are directories that hold other people's code or build output. A lockfile in
// there belongs to a dependency or an artifact, not to the project.
var skipped = []string{
	"node_modules", "vendor", "target", "dist", "build", "out",
	"venv", "site-packages", "__pycache__", "testdata", "Pods",
}

// Discover returns the directories under root that hold a lockfile securock reads, as
// slash-separated paths relative to root ("." for root itself), sorted. Hidden
// directories and the ones in skipped are not entered, and symbolic links are not followed.
func Discover(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && skip(d.Name()) {
			return filepath.SkipDir
		}
		if len(ecosystem.Detect(path)) == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(found)
	return found, nil
}

func skip(name string) bool {
	return strings.HasPrefix(name, ".") || slices.Contains(skipped, name)
}
