package sast

import (
	"fmt"
	"go/ast"
	"go/types"
)

const aliasPrefix = "\x00a:"
const originField = "\x00origin"

// Alias edges are may-alias relationships. Writes through them are weak: when
// branches disagree about identity, overwriting one object cannot clean another.
func (s state) aliases(obj types.Object) []types.Object {
	out := []types.Object{obj}
	for k, t := range s {
		if k.obj == obj && len(t) > 0 && t[0].ref != nil {
			out = append(out, t[0].ref)
		}
	}
	return out
}

func (s state) bind(obj, other types.Object) {
	if obj == other {
		return
	}
	var peers []types.Object
	var origins taintSet
	if other != nil {
		peers = s.aliases(other)
	}
	if other != nil {
		origins = s[vkey{other, originField}]
	}
	for k, t := range s {
		if len(t) > 0 && t[0].ref != nil && (k.obj == obj || t[0].ref == obj) {
			delete(s, k)
		}
	}
	delete(s, vkey{obj, originField})
	if len(origins) > 0 {
		s[vkey{obj, originField}] = origins
	}
	for _, p := range peers {
		if p == obj {
			continue
		}
		s[vkey{obj, aliasPrefix + fmt.Sprint(p.Pos()) + p.Name()}] = taintSet{{key: "alias", ref: p}}
		s[vkey{p, aliasPrefix + fmt.Sprint(obj.Pos()) + obj.Name()}] = taintSet{{key: "alias", ref: obj}}
	}
}

func (s istate) aliases(name string) []string {
	out := []string{name}
	for k, t := range s {
		if k.name == name && len(t) > 0 && t[0].refName != "" {
			out = append(out, t[0].refName)
		}
	}
	return out
}

func (s istate) bind(name, other string) {
	if name == other {
		return
	}
	var peers []string
	var origins taintSet
	if other != "" {
		peers = s.aliases(other)
	}
	if other != "" {
		origins = s[ikey{other, originField}]
	}
	for k, t := range s {
		if len(t) > 0 && t[0].refName != "" && (k.name == name || t[0].refName == name) {
			delete(s, k)
		}
	}
	delete(s, ikey{name, originField})
	if len(origins) > 0 {
		s[ikey{name, originField}] = origins
	}
	for _, p := range peers {
		if p == name {
			continue
		}
		s[ikey{name, aliasPrefix + p}] = taintSet{{key: "alias", refName: p}}
		s[ikey{p, aliasPrefix + name}] = taintSet{{key: "alias", refName: name}}
	}
}

func (a *analyzer) bindAssignment(lhs, rhs ast.Expr, st state) {
	id, ok := unparen(lhs).(*ast.Ident)
	if !ok {
		return
	}
	obj, _, _, ok := a.pathOf(id)
	if !ok {
		return
	}
	var other types.Object
	switch typeUnder(a.info.TypeOf(rhs)).(type) {
	case *types.Pointer, *types.Map, *types.Slice:
		if o, f, _, ok := a.pathOf(addrOperand(rhs)); ok && f == "" {
			other = o
		}
	}
	st.bind(obj, other)
}

func origin(param int) taintSet { return taintSet{{key: fmt.Sprintf("origin%d", param), param: param}} }

func (a *analyzer) recordEffects(obj types.Object, field string, t taintSet, st state) {
	for _, peer := range st.aliases(obj) {
		for _, o := range st[vkey{peer, originField}] {
			a.ctx.effect(o.param, field, t)
		}
	}
}

func (r *irRun) recordEffects(name, field string, t taintSet, st istate) {
	for _, peer := range st.aliases(name) {
		for _, o := range st[ikey{peer, originField}] {
			r.ctx.effect(o.param, field, t)
		}
	}
}
