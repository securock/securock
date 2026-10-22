package typosquat

import (
	"slices"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		eco, name  string
		wantTarget string
	}{
		{"npm", "reakt-dom", "react-dom"},
		{"npm", "lodahs", "lodash"},
		{"npm", "expresss", "express"},
		{"npm", "expres", "express"},
		{"npm", "lo-dash", "lodash"},
		{"npm", "Lodash", ""},
		{"npm", "lodash", ""},
		{"npm", "react-dom", ""},
		{"npm", "@evil/lodash", ""},
		{"npm", "my-internal-package", ""},
		{"npm", "ms", ""},
		{"npm", "mz", ""},
		{"pypi", "reqeusts", "requests"},
		// A real but different package: the heuristic cannot tell, which is why this is a signal.
		{"pypi", "request", "requests"},
		{"pypi", "numpyy", "numpy"},
		{"pypi", "python_dateutil", ""},
		{"pypi", "python-dateutils", "python-dateutil"},
		{"pypi", "Pillow", ""},
		{"pypi", "pyyaml", ""},
		{"cargo", "serdee", ""},
		{"go", "lodahs", ""},
	}
	for _, tt := range tests {
		t.Run(tt.eco+"/"+tt.name, func(t *testing.T) {
			got, ok := Check(tt.eco, tt.name)
			if ok != (tt.wantTarget != "") || got != tt.wantTarget {
				t.Fatalf("Check(%q, %q) = %q, %v; want %q", tt.eco, tt.name, got, ok, tt.wantTarget)
			}
		})
	}
}

func TestPopularListsAreSortedAndUnique(t *testing.T) {
	for name, list := range map[string][]string{"npm": npmPopular, "pypi": pypiPopular} {
		if !slices.IsSorted(list) {
			t.Errorf("%s list must be sorted for binary search", name)
		}
		if len(slices.Compact(slices.Clone(list))) != len(list) {
			t.Errorf("%s list has duplicates", name)
		}
		for _, p := range list {
			if p != normalize(name, p) {
				t.Errorf("%s: %q is not in normalized form %q", name, p, normalize(name, p))
			}
		}
	}
}

func TestPopularNamesAreNeverFlagged(t *testing.T) {
	for _, p := range npmPopular {
		if target, ok := Check("npm", p); ok {
			t.Errorf("npm %q is popular but flagged as %q", p, target)
		}
	}
	for _, p := range pypiPopular {
		if target, ok := Check("pypi", p); ok {
			t.Errorf("pypi %q is popular but flagged as %q", p, target)
		}
	}
}

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"lodash", "lodash", 0},
		{"lodash", "lodahs", 1},
		{"lodash", "lodas", 1},
		{"lodash", "lodashh", 1},
		{"lodash", "lodesh", 1},
		{"lodash", "ladesh", 2},
		{"abc", "abcdef", 2},
		{"", "a", 1},
	}
	for _, tt := range tests {
		if got := distance(tt.a, tt.b); got != tt.want {
			t.Errorf("distance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
