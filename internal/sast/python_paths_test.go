package sast_test

import (
	"slices"
	"strings"
	"testing"
)

func TestPythonAbsoluteRelativePathGuard(t *testing.T) {
	for _, tt := range []struct {
		name, base, middle string
		want               []string
	}{
		{"relative directory", "Path('./assets')", "", nil},
		{"relative basename", "Path('assets')", "", nil},
		{"imported constant", "Path(settings.ROOT)", "", nil},
		{"nested module constant", "Path(pkg.settings.ROOT)", "", nil},
		{"absolute directory", "Path('/srv/assets')", "", []string{"sast:py/path-traversal"}},
		{"unknown directory", "Path(request.args['root'])", "", []string{"sast:py/path-traversal"}},
		{"windows drive prefix", "Path('C:')", "", []string{"sast:py/path-traversal"}},
		{"single letter prefix", "Path('C')", "", []string{"sast:py/path-traversal"}},
		{"base reassigned", "Path('./assets')", "base = Path(request.args['root'])\n    ", []string{"sast:py/path-traversal"}},
		{"resolved path reassigned", "Path('./assets')", "target = other\n    ", []string{"sast:py/path-traversal"}},
		{"resolved path changed in branch", "Path('./assets')", "if other:\n        target = other\n    ", []string{"sast:py/path-traversal"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from pathlib import Path\nfrom flask import request\nimport settings\nimport pkg.settings\ndef route(other):\n    other = Path(request.args['alternate'])\n    base = " + tt.base + "\n    target = (base / request.args['file']).resolve()\n    " + tt.middle + "if not str(target).startswith(str(base)):\n        return\n    target.read_text()\n"
			if got := analyze(t, map[string]string{"app.py": src, "settings.py": "ROOT = './assets'\n", "pkg/settings.py": "ROOT = './assets'\n"}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonPathProofInvalidation(t *testing.T) {
	src := `from flask import request
from pathlib import Path
import settings
def route():
    root = settings.ROOT
    base = Path(root)
    target = (base / request.args['file']).resolve()
    if not str(target).startswith(str(base)):
        return
    target.read_text()
`
	for _, tt := range []struct{ name, extra, change string }{
		{"constant written through module", "import settings\ndef update(value):\n    settings.ROOT = value\n", ""},
		{"constant written through module alias", "import settings\nconfig = settings\ndef update(value):\n    config.ROOT = value\n", ""},
		{"constant written in defining module", "", "\ndef update(value):\n    global ROOT\n    ROOT = value\n"},
		{"string builtin shadowed", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app := src
			if tt.name == "string builtin shadowed" {
				app = strings.Replace(src, "def route():", "def route():\n    str = lambda value: 'assets'", 1)
			}
			files := map[string]string{"app.py": app, "settings.py": "ROOT = './assets'\n" + tt.change, "updates.py": tt.extra}
			if got := analyze(t, files); !slices.Equal(got, []string{"sast:py/path-traversal"}) {
				t.Fatalf("got %v, want path traversal", got)
			}
		})
	}
}

func TestPythonConstantReturningGuard(t *testing.T) {
	for _, tt := range []struct {
		condition string
		want      []string
	}{
		{"True", nil},
		{"False", []string{"sast:py/path-traversal"}},
		{"request.args['stop']", []string{"sast:py/path-traversal"}},
	} {
		t.Run(tt.condition, func(t *testing.T) {
			src := "from flask import request\ndef route():\n    if " + tt.condition + ":\n        return\n    open(request.args['file'])\n"
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
