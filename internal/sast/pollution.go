package sast

// checkPollution flags obj[a][b] = v where the first key comes from the request: with
// a = "__proto__" the write lands on Object.prototype and changes every object in the
// process. A single-level obj[a] = v only changes obj itself.
func (r *irRun) checkPollution(lhs *expr, st istate) {
	if r.spec.name != "js" || lhs.kind != exprIndex || lhs.x == nil || lhs.x.kind != exprIndex || len(lhs.x.args) == 0 {
		return
	}
	for _, at := range r.eval(lhs.x.args[0], st) {
		if hit := at.kinds & kProto; hit != 0 {
			r.reachSink(lhs.pos, "obj[key][key] = value", hit, at, nil)
		}
	}
}
