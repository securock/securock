package sast

import "go/token"

// Recursive summaries can revisit the same call site indefinitely. A trace is
// a representative explanation, so retain each repeated step only once.
func addFlow(base *flow, pos token.Pos, msg string) *flow {
	for f := base; f != nil; f = f.prev {
		if f.pos == pos && f.msg == msg {
			return base
		}
	}
	return &flow{pos: pos, msg: msg, prev: base}
}

func flowLess(a, b *flow) bool {
	if a == b {
		return false
	}
	length := func(f *flow) int {
		n := 0
		for ; f != nil; f = f.prev {
			n++
		}
		return n
	}
	x, y := length(a), length(b)
	if x != y {
		return x < y
	}
	for a != nil && b != nil {
		if a.pos != b.pos {
			return a.pos < b.pos
		}
		if a.msg != b.msg {
			return a.msg < b.msg
		}
		a, b = a.prev, b.prev
	}
	return false
}
