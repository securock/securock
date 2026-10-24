package sast

import (
	"slices"
	"strconv"
	"strings"
)

const sequenceField = "\x00sequence"
const sequenceTextPrefix = "\x00sequence-text:"
const maxSequenceElements = 64

func sequenceLength(n int) taintSet { return taintSet{{key: strconv.Itoa(n)}} }

func sequenceTextField(index int) string { return sequenceTextPrefix + strconv.Itoa(index) }

func (r *irRun) sequenceText(e *expr) taintSet {
	if text, ok := r.strOf(e); ok {
		return taintSet{{key: text}}
	}
	return nil
}

func (s istate) invalidateSequenceText(name, field string) {
	if field == "" {
		for k := range s {
			if k.name == name && strings.HasPrefix(k.field, sequenceTextPrefix) {
				delete(s, k)
			}
		}
	} else if index, err := strconv.Atoi(strings.Split(strings.TrimPrefix(field, "."), ".")[0]); err == nil {
		delete(s, ikey{name, sequenceTextField(index)})
	}
}

func (r *irRun) assignSequenceText(lhs, rhs *expr, st istate) {
	if lhs.kind != exprIndex || lhs.x.kind != exprName || len(lhs.args) != 1 {
		return
	}
	name := lhs.x.name
	size, known := st.sequenceSize(name)
	index, constant := r.constInt(lhs.args[0])
	if i, valid := sequenceIndex(index, size, r.spec.name == "py"); known && constant && valid {
		st[ikey{name, sequenceTextField(i)}] = r.sequenceText(rhs)
	}
}

func (s istate) sequenceSize(name string) (int, bool) {
	t := s[ikey{name, sequenceField}]
	if len(t) != 1 {
		return 0, false
	}
	n, err := strconv.Atoi(t[0].key)
	return n, err == nil && n >= 0 && n <= maxSequenceElements
}

func (s istate) hasSequence(name string) bool {
	_, ok := s[ikey{name, sequenceField}]
	return ok
}

// An escaping call can retain one list inside another. Treat those references
// as may-alias rather than taking a snapshot that misses a later mutation.
func (s istate) linkSequences(names []string) {
	var peers []string
	for _, name := range names {
		peers = append(peers, s.aliases(name)...)
	}
	slices.Sort(peers)
	peers = slices.Compact(peers)
	for _, a := range peers {
		for _, b := range peers {
			if a != b {
				s[ikey{a, aliasPrefix + b}] = taintSet{{key: "alias", refName: b}}
			}
		}
	}
}

// Unknown mutations can change every position. Retain all element taint, but
// stop projecting onto indices until a new local sequence is constructed.
func (s istate) forgetSequence(name string, extra taintSet) {
	if !s.hasSequence(name) {
		return
	}
	t := merge(s.read(name, "").scalar(), extra.scalar())
	s.writeLocal(name, "", t, false)
	s[ikey{name, sequenceField}] = taintSet{{key: "unknown"}}
}

func (r *irRun) sequenceValue(e *expr, st istate) bool {
	if e == nil {
		return false
	}
	if e.kind == exprCond {
		return r.sequenceValue(e.args[0], st) || r.sequenceValue(e.args[1], st)
	}
	name, field, ok := r.pathOf(e)
	return ok && field == "" && st.hasSequence(name)
}

func (r *irRun) localSequenceAssignment(s *stmt) bool {
	if s.aug || len(s.lhs) != 1 || s.rhs == nil || s.lhs[0].kind != exprName {
		return false
	}
	_, field, ok := r.pathOf(s.lhs[0])
	return ok && field == ""
}

func (r *irRun) initSequence(s *stmt, st istate) {
	if !r.localSequenceAssignment(s) {
		return
	}
	name := s.lhs[0].name
	if r.sequenceValue(s.rhs, st) {
		st[ikey{name, sequenceField}] = taintSet{{key: "unknown"}}
		for _, peer := range st.aliases(name) {
			st.forgetSequence(peer, nil)
		}
		return
	}
	delete(st, ikey{name, sequenceField})
	if parts, known := r.pythonRouteSplit(s.rhs, st); known {
		st[ikey{name, sequenceField}] = sequenceLength(len(parts))
		for i, text := range parts {
			st[ikey{name, sequenceTextField(i)}] = taintSet{{key: text}}
		}
		return
	}
	if s.rhs.kind == exprSequence && len(s.rhs.args) <= maxSequenceElements {
		st[ikey{name, sequenceField}] = sequenceLength(len(s.rhs.args))
		for i, value := range s.rhs.args {
			st[ikey{name, sequenceTextField(i)}] = r.sequenceText(value)
		}
		for _, value := range s.rhs.args {
			if value.kind == exprName && st.hasSequence(value.name) {
				st.linkSequences([]string{name, value.name})
				for _, peer := range st.aliases(name) {
					st.forgetSequence(peer, nil)
				}
			}
		}
	}
	if r.spec.name == "java" && s.rhs.kind == exprNew {
		ty := r.typeOf(s.rhs, st)
		if (ty == "java.util.ArrayList" || ty == "java.util.LinkedList") && len(s.rhs.args) == 0 {
			st[ikey{name, sequenceField}] = sequenceLength(0)
		}
	}
}

func sequenceIndex(index int64, size int, negative bool) (int, bool) {
	if negative && index < 0 {
		index += int64(size)
	}
	return int(index), index >= 0 && index < int64(size)
}

func (r *irRun) readSequence(e *expr, st istate) (taintSet, bool) {
	if e.kind != exprIndex || len(e.args) != 1 || e.x.kind != exprName || !st.hasSequence(e.x.name) {
		return nil, false
	}
	name := e.x.name
	size, known := st.sequenceSize(name)
	index, constant := r.constInt(e.args[0])
	if i, valid := sequenceIndex(index, size, r.spec.name == "py"); known && constant && valid {
		return st.read(name, fieldPart(strconv.Itoa(i))), true
	}
	return st.read(name, "").scalar(), true
}

// Model a bounded, unescaped local list. Aliases, unknown calls and unsupported
// mutations fall back to whole-object taint, never to an assumed safe element.
func (r *irRun) sequenceCall(e *expr, args []taintSet, st istate) (taintSet, bool) {
	fn := e.x
	if fn.kind != exprMember || fn.x.kind != exprName {
		return nil, false
	}
	name := fn.x.name
	size, known := st.sequenceSize(name)
	if !known || len(st.aliases(name)) != 1 {
		return nil, false
	}
	for _, kw := range e.kw {
		if kw != "" {
			return nil, false
		}
	}
	for _, arg := range e.args {
		if r.sequenceValue(arg, st) {
			return nil, false
		}
	}
	py, java := r.spec.name == "py", r.spec.name == "java"
	var values []taintSet
	var texts []taintSet
	for i := 0; i < size; i++ {
		values = append(values, st.read(name, fieldPart(strconv.Itoa(i))))
		texts = append(texts, st[ikey{name, sequenceTextField(i)}])
	}
	index := func(a int) (int, bool) {
		if a >= len(e.args) {
			return 0, false
		}
		v, ok := r.constInt(e.args[a])
		i, valid := sequenceIndex(v, size, py)
		return i, ok && valid
	}
	var result taintSet
	switch {
	case java && fn.name == "get" && len(args) == 1:
		if i, ok := index(0); ok {
			return values[i], true
		}
		return nil, false
	case (py && fn.name == "append" || java && fn.name == "add") && len(args) == 1:
		if size == maxSequenceElements {
			return nil, false
		}
		values = append(values, args[0])
		texts = append(texts, r.sequenceText(e.args[0]))
	case (py && fn.name == "insert" || java && fn.name == "add") && len(args) == 2:
		v, ok := r.constInt(e.args[0])
		if !ok || size == maxSequenceElements {
			return nil, false
		}
		if py {
			if v < 0 {
				v += int64(size)
			}
			v = min(int64(size), max(0, v))
		}
		if v < 0 || v > int64(size) {
			return nil, false
		}
		values = slices.Insert(values, int(v), args[1])
		texts = slices.Insert(texts, int(v), r.sequenceText(e.args[1]))
	case java && fn.name == "set" && len(args) == 2:
		i, ok := index(0)
		if !ok {
			return nil, false
		}
		result, values[i] = values[i], args[1]
		texts[i] = r.sequenceText(e.args[1])
	case py && fn.name == "pop" && len(args) <= 1, java && fn.name == "remove" && len(args) == 1:
		i, ok := size-1, size > 0
		if len(args) > 0 {
			// Java remove(Object) is not remove(int). Only an integer literal is
			// unambiguously the indexed overload without full overload resolution.
			if java && e.args[0].kind != exprNum {
				return nil, false
			}
			i, ok = index(0)
		}
		if !ok {
			return nil, false
		}
		result = values[i]
		values = slices.Delete(values, i, i+1)
		texts = slices.Delete(texts, i, i+1)
	case (py || java) && fn.name == "clear" && len(args) == 0:
		values = nil
		texts = nil
	default:
		return nil, false
	}
	var contents taintSet
	for i, v := range values {
		contents = merge(contents, v.atField(fieldPart(strconv.Itoa(i))))
	}
	st.writeLocal(name, "", contents, false)
	st[ikey{name, sequenceField}] = sequenceLength(len(values))
	for i, text := range texts {
		st[ikey{name, sequenceTextField(i)}] = text
	}
	return result, true
}

func (r *irRun) escapeSequences(e *expr, args []taintSet, recv *expr, st istate) {
	var names []string
	for _, value := range append([]*expr{recv}, e.args...) {
		if value == nil {
			continue
		}
		if name, field, ok := r.pathOf(value); ok && field == "" {
			if st.hasSequence(name) {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return
	}
	var extra taintSet
	for _, arg := range args {
		extra = merge(extra, arg.scalar())
	}
	st.linkSequences(names)
	for _, name := range names {
		for _, peer := range st.aliases(name) {
			st.forgetSequence(peer, extra)
		}
	}
}
