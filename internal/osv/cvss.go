package osv

import (
	"math"
	"strings"
)

// cvss3Score computes the base score of a CVSS v3.0 or v3.1 vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". ok is false for any other version
// (v2 and v4 vectors are not computed) or a malformed vector.
func cvss3Score(vector string) (score float64, ok bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, found := strings.Cut(p, ":")
		if !found {
			return 0, false
		}
		m[k] = v
	}

	scopeChanged := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	av, ok1 := pick(m["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := pick(m["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	ui, ok3 := pick(m["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	priv := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		priv = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok4 := pick(m["PR"], priv)
	impact := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := pick(m["C"], impact)
	i, ok6 := pick(m["I"], impact)
	a, ok7 := pick(m["A"], impact)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impactScore float64
	if scopeChanged {
		impactScore = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impactScore = 6.42 * iss
	}
	if impactScore <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	if scopeChanged {
		return roundUp(math.Min(1.08*(impactScore+exploitability), 10)), true
	}
	return roundUp(math.Min(impactScore+exploitability, 10)), true
}

func pick(key string, table map[string]float64) (float64, bool) {
	v, ok := table[key]
	return v, ok
}

// roundUp is the CVSS v3.1 round-up to one decimal place, which avoids floating point
// artifacts such as 4.000000000000001 becoming 4.1.
func roundUp(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// severityOf maps a CVSS score to the severity names securock uses. A zero score has no
// severity.
func severityOf(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}
