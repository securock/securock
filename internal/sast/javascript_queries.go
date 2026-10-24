package sast

import "strings"

// An explicit $where field identifies MongoDB query syntax even when the
// collection handle's local name is not in the receiver-name fallback table.
// Ordinary fields on an unknown .find receiver are not database evidence.
func (r *irRun) checkJavaScriptWhere(e *expr, args []taintSet, st istate) {
	if r.spec.name != "js" || e.x == nil || e.x.kind != exprMember || len(args) == 0 {
		return
	}
	s, ok := r.spec.sinks["?."+e.x.name]
	if !ok || s.kind != kNoSQL {
		return
	}
	var query taintSet
	field := fieldPart("$where")
	for _, at := range args[0] {
		if at.path == field || strings.HasPrefix(at.path, field+".") {
			query = merge(query, taintSet{at})
		}
	}
	if len(query) > 0 {
		r.checkSink(e, "."+e.x.name, sink{kind: kNoSQLStr, args: []int{0}}, []taintSet{query}, nil, st)
	}
}
