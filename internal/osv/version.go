package osv

import (
	"strconv"
	"strings"
)

// compareVersions orders two versions as registries write them: dotted numbers, with a
// pre-release suffix (1.0.0-rc.1, 2.0rc1, 1.0.0a2) ordering before the release. It is not
// a full semver, PEP 440, or Maven implementation. ok is false when either side does not
// start with a number, in which case the caller must not guess.
func compareVersions(a, b string) (cmp int, ok bool) {
	ca, pa, oka := splitVersion(a)
	cb, pb, okb := splitVersion(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < max(len(ca), len(cb)); i++ {
		var x, y int
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case pa == pb:
		return 0, true
	case pa == "":
		return 1, true
	case pb == "":
		return -1, true
	case pa < pb:
		return -1, true
	default:
		return 1, true
	}
}

// splitVersion separates the leading dotted number from what follows it. Build metadata
// after + is dropped, and a ".post" or ".patch" style suffix counts as part of the release.
func splitVersion(v string) (core []int, pre string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	i := 0
	for i < len(v) {
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		if start == i {
			break
		}
		n, err := strconv.Atoi(v[start:i])
		if err != nil {
			return nil, "", false
		}
		core = append(core, n)
		if i < len(v) && v[i] == '.' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	if len(core) == 0 {
		return nil, "", false
	}
	pre = strings.ToLower(strings.TrimLeft(v[i:], ".-_"))
	if strings.HasPrefix(pre, "post") || strings.HasPrefix(pre, "patch") {
		pre = ""
	}
	return core, pre, true
}
