package sast

import (
	"fmt"
	"math/rand"
	"reflect"
)

// Expose the conversion boundary to external tests without adding a public API.
var SequenceIndexForTest = sequenceIndex

// CheckTaintAccumulator folds random atoms and taint sets with merge and with
// taintAcc and returns a description of the first difference, or "" if there is
// none. The sets repeat identities, come unsorted and carry duplicates, which is
// what merge has to cope with.
func CheckTaintAccumulator(seed int64, rounds int) string {
	rng := rand.New(rand.NewSource(seed))
	flows := []*flow{nil, {pos: 1, msg: "a"}, {pos: 2, msg: "b"}, {pos: 3, msg: "c", prev: &flow{pos: 1, msg: "a"}}}
	pick := func(s ...string) string { return s[rng.Intn(len(s))] }
	randAtom := func() atom {
		return atom{
			key:       pick("s1", "s2", "s3", "p"),
			param:     rng.Intn(3) - 1,
			field:     pick("", "", "x", "y"),
			path:      pick("", "", "f", "f.g", "h"),
			kinds:     kind(1 << rng.Intn(4)),
			flow:      flows[rng.Intn(len(flows))],
			xpathSafe: rng.Intn(2) == 0,
		}
	}
	randSet := func() taintSet {
		var t taintSet
		for range rng.Intn(5) {
			t = append(t, randAtom())
		}
		return t
	}
	for round := range rounds {
		var want taintSet
		var got taintAcc
		var steps []string
		for range 1 + rng.Intn(8) {
			if rng.Intn(2) == 0 {
				a := randAtom()
				want = merge(want, taintSet{a})
				got.addAtom(a)
				steps = append(steps, fmt.Sprintf("atom %+v", a))
			} else {
				b := randSet()
				want = merge(want, b)
				got.add(b)
				steps = append(steps, fmt.Sprintf("set %+v", b))
			}
			if !reflect.DeepEqual(want, got.out) && !got.merged && !got.exact {
				return fmt.Sprintf("round %d: unmerged accumulator differs: %v", round, steps)
			}
		}
		if res := got.result(); !reflect.DeepEqual(want, res) {
			return fmt.Sprintf("round %d: want %+v, got %+v after %v", round, want, res, steps)
		}
	}
	return ""
}
