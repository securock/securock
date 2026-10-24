package sast

import (
	"path/filepath"
	"strings"
)

// checkTemplateRender reports request data passed to a template render whose
// template prints that variable without HTML escaping. Template engines escape
// by default, so a plain render of request data is safe; what is not safe is a
// value the template marks safe, or one printed inside a script element, where
// HTML escaping does not make the value safe JavaScript.
func (r *irRun) checkTemplateRender(c *expr, qname string, args []taintSet, st istate) {
	if r.spec.name != "py" {
		return
	}
	nameArg := 0
	switch qname {
	case "flask.render_template":
	case "django.shortcuts.render":
		nameArg = 1
	default:
		return
	}
	if nameArg >= len(c.args) {
		return
	}
	name, ok := r.strOf(c.args[nameArg])
	if !ok || name == "" {
		// A non-constant template name is reported by the render_template
		// code-injection sink; there is no template to inspect here.
		return
	}
	tpl := r.proj.template(r.mod, name)
	if tpl == nil {
		return
	}
	for i := range c.args {
		if i == nameArg || i >= len(c.kw) || c.kw[i] == "" {
			continue
		}
		if !tpl.rawHTML[c.kw[i]] && !tpl.rawScript[c.kw[i]] {
			continue
		}
		for _, at := range args[i] {
			if hit := at.kinds & kXSS; hit != 0 {
				r.reachSink(c.pos, "the raw template output of "+c.kw[i], hit, at, nil)
			}
		}
	}
}

// template resolves a render_template name against the module's templates
// directory, Flask's default layout: a template name is always inside that one
// folder, never outside it.
func (p *project) template(m *module, name string) *templateOutputs {
	if p == nil || m == nil || p.templates == nil {
		return nil
	}
	rel := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(m.path)), "templates", filepath.FromSlash(name)))
	if strings.Contains(rel, "..") {
		return nil
	}
	return p.templates[rel]
}
