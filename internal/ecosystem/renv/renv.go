package renv

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "renv.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "renv" }

func (Ecosystem) OSVEcosystem() string { return "CRAN" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock renvLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	repos := map[string]string{}
	for _, repo := range lock.R.Repositories {
		repos[repo.Name] = repo.URL
	}

	names := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		names = append(names, key)
	}
	sort.Strings(names)

	var deps []core.Dependency
	for _, key := range names {
		pkg := lock.Packages[key]
		name := pkg.Package
		if name == "" {
			name = key
		}
		if pkg.Version == "" {
			continue
		}
		// pkg.Hash is an MD5 of the package DESCRIPTION, not of a downloadable artifact,
		// so it is not recorded as a digest.
		dep := core.Dependency{
			Ecosystem:  "cran",
			Resolver:   "renv",
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    pkg.Version,
		}
		switch strings.ToLower(pkg.Source) {
		case "repository", "bioconductor":
			// Only CRAN itself is proven public. Bioconductor, Posit Package Manager and
			// private mirrors carry different or unproven package sets, so they get no
			// registry and are never sent to OSV as CRAN.
			if pkg.Repository == "CRAN" {
				dep.Registry = cranOrigin(repos["CRAN"])
			}
		case "github", "gitlab", "bitbucket", "git":
			dep.SourceKind = core.SourceGit
			dep.Artifact = core.RemoteLocation(remote(pkg))
			dep.Resolved = pkg.RemoteSha
		case "local":
			dep.SourceKind = core.SourceFile
		default:
			dep.SourceKind = core.SourceURL
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

// cranOrigin returns the origin of a repository URL only when it is one of the two public
// CRAN hosts; anything else is not provably CRAN.
func cranOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "cloud.r-project.org", "cran.r-project.org":
		return u.Scheme + "://" + u.Host
	}
	return ""
}

func remote(pkg renvPackage) string {
	if pkg.RemoteURL != "" {
		return pkg.RemoteURL
	}
	if pkg.RemoteUsername == "" || pkg.RemoteRepo == "" {
		return ""
	}
	host := pkg.RemoteHost
	switch strings.ToLower(pkg.Source) {
	case "github":
		if host == "" || host == "api.github.com" {
			host = "github.com"
		}
	case "gitlab":
		if host == "" {
			host = "gitlab.com"
		}
	case "bitbucket":
		if host == "" {
			host = "bitbucket.org"
		}
	}
	if host == "" {
		return ""
	}
	return "https://" + host + "/" + pkg.RemoteUsername + "/" + pkg.RemoteRepo
}

type renvLock struct {
	R struct {
		Repositories []struct {
			Name string `json:"Name"`
			URL  string `json:"URL"`
		} `json:"Repositories"`
	} `json:"R"`
	Packages map[string]renvPackage `json:"Packages"`
}

type renvPackage struct {
	Package        string `json:"Package"`
	Version        string `json:"Version"`
	Source         string `json:"Source"`
	Repository     string `json:"Repository"`
	RemoteHost     string `json:"RemoteHost"`
	RemoteURL      string `json:"RemoteUrl"`
	RemoteUsername string `json:"RemoteUsername"`
	RemoteRepo     string `json:"RemoteRepo"`
	RemoteSha      string `json:"RemoteSha"`
}
