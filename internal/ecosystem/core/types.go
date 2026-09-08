package core

import (
	"os"
	"path/filepath"
)

type Dependency struct {
	Ecosystem string
	Resolver  string
	Registry  string
	Name      string
	Version   string
	Filename  string
	Digest    string
}

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
