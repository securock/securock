package core

import (
	"os"
	"path/filepath"
)

type Dependency struct {
	Ecosystem  string
	Resolver   string
	Registry   string
	Artifact   string
	Requested  string
	Resolved   string
	SourceKind string
	Name       string
	Version    string
	Filename   string
	Digest     string
}

const (
	SourceRegistry  = "registry"
	SourceWorkspace = "workspace"
	SourceGit       = "git"
	SourceFile      = "file"
	SourceURL       = "url"
)

type Ecosystem interface {
	Name() string
	OSVEcosystem() string
	Detect(path string) bool
	Dependencies(path string) ([]Dependency, error)
}

func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func Join(root, name string) string {
	return filepath.Join(root, name)
}

func Identity(dep Dependency) string {
	id := dep.Ecosystem + ":" + dep.Name
	if dep.Version != "" {
		id += "@" + dep.Version
	}
	if dep.Filename != "" {
		id += "#" + dep.Filename
	}
	return id
}
