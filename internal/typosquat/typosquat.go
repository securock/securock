// Package typosquat flags package names that look like a misspelling of a popular
// package. It is a heuristic over a built-in list and needs no network access.
package typosquat

import (
	"slices"
	"strings"
)

// Check reports the popular package that name appears to imitate. Only npm and PyPI are
// covered. A name that is itself popular, or an npm scoped name (whose scope has an owner),
// is never flagged.
func Check(ecosystem, name string) (target string, ok bool) {
	var popular []string
	switch ecosystem {
	case "npm":
		if strings.HasPrefix(name, "@") {
			return "", false
		}
		popular = npmPopular
	case "pypi":
		popular = pypiPopular
	default:
		return "", false
	}

	n := normalize(ecosystem, name)
	if _, exact := slices.BinarySearch(popular, n); exact {
		return "", false
	}
	squashed := squash(n)
	for _, p := range popular {
		if squash(p) == squashed {
			return p, true
		}
	}
	for _, p := range popular {
		if len(p) >= minLength && distance(n, p) == 1 {
			return p, true
		}
	}
	return "", false
}

// minLength keeps short names out of the edit-distance check: a single typo in a short
// name usually lands on another legitimate package.
const minLength = 5

func normalize(ecosystem, name string) string {
	name = strings.ToLower(name)
	if ecosystem != "pypi" {
		return name
	}
	// PEP 503: runs of - _ . are equivalent.
	var b strings.Builder
	dash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			dash = true
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

func squash(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' {
			return -1
		}
		return r
	}, s)
}

// distance is the optimal-string-alignment edit distance: insertions, deletions,
// substitutions, and swaps of adjacent characters each cost one.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if d := len(ra) - len(rb); d > 1 || d < -1 {
		return 2
	}
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(rb)]
}
