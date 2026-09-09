package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func TestPrivacyMatrix(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantN   int
		wantAll lockfile.VulnState
	}{
		{
			name: "npm public registry",
			files: map[string]string{
				"package-lock.json": `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/react": {
      "version": "19.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
      "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
    }
  }
}`,
			},
			wantN:   1,
			wantAll: lockfile.VulnChecked,
		},
		{
			name: "npm private registry",
			files: map[string]string{
				"package-lock.json": `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@company/internal-auth": {
      "version": "1.0.0",
      "resolved": "https://npm.company.example/@company/internal-auth/-/internal-auth-1.0.0.tgz"
    }
  }
}`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "npm unknown registry",
			files: map[string]string{
				"package-lock.json": `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/secret-sdk": { "version": "1.0.0" }
  }
}`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "npm file and git",
			files: map[string]string{
				"package-lock.json": `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/local-pkg": { "version": "0.0.1", "resolved": "file:packages/local-pkg" },
    "node_modules/from-git": { "version": "1.0.0", "resolved": "git+https://github.com/example/from-git.git#deadbeef" }
  }
}`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "yarn workspace",
			files: map[string]string{
				"yarn.lock": `__metadata:
  version: 8
"local-pkg@workspace:packages/local-pkg":
  version: 0.0.1
  resolution: "local-pkg@workspace:packages/local-pkg"
`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "yarn private scope",
			files: map[string]string{
				"yarn.lock": `__metadata:
  version: 8
"@company/internal-auth@npm:1.0.0":
  version: 1.0.0
  resolution: "@company/internal-auth@npm:1.0.0"
`,
				".yarnrc.yml": "npmRegistryServer: https://registry.npmjs.org\nnpmScopes:\n  company:\n    npmRegistryServer: https://npm.company.example\n",
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "pdm private index",
			files: map[string]string{
				"pdm.lock": `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", url = "https://pypi.company.example/packages/secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "nuget private feed",
			files: map[string]string{
				"packages.lock.json": `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Secret.Sdk": { "type": "Direct", "resolved": "1.0.0", "contentHash": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
    }
  }
}`,
				"nuget.config": `<?xml version="1.0"?><configuration><packageSources><add key="company" value="https://nuget.company.example/v3/index.json" /></packageSources></configuration>`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "hex organization",
			files: map[string]string{
				"mix.lock": `%{
  "secret": {:hex, :secret, "1.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "acme", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
}
`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "poetry private source",
			files: map[string]string{
				"poetry.lock": `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]

[package.source]
type = "legacy"
url = "https://pypi.company.example/simple"
`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
		{
			name: "composer private repository",
			files: map[string]string{
				"composer.lock": `{
  "packages": [
    {
      "name": "company/secret-sdk",
      "version": "1.0.0",
      "notification-url": "https://composer.company.example/downloads/",
      "dist": { "type": "zip", "url": "https://api.github.com/repos/company/secret-sdk/zipball/abc", "shasum": "" }
    }
  ]
}`,
			},
			wantN:   0,
			wantAll: lockfile.VulnUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("APPDATA", home)
			t.Setenv("npm_config_registry", "")
			t.Setenv("NPM_CONFIG_REGISTRY", "")

			dir := t.TempDir()
			for name, raw := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(raw), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			client := &countingOSV{}
			result, err := scanner.Scan(context.Background(), scanner.Options{
				Path:     dir,
				Policy:   policy.Default(),
				Client:   client,
				Evidence: fakeEvidence{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if client.n != tc.wantN {
				t.Fatalf("queried %d, want %d", client.n, tc.wantN)
			}
			if len(result.Document.Artifacts) == 0 {
				t.Fatal("no artifacts")
			}
			for _, art := range result.Document.Artifacts {
				if art.Evidence.Vulnerabilities.State != tc.wantAll {
					t.Fatalf("%s state = %s, want %s", art.Subject.Name, art.Evidence.Vulnerabilities.State, tc.wantAll)
				}
			}
		})
	}
}
