package sast

// Sinks and sources that were missing when the analyzers were run against real
// vulnerable applications (NodeGoat, DVWA, railsgoat, pygoat, WebGoat).

func init() {
	// ---- JavaScript
	js := jsSpec
	js.misuse["autoescape"] = []misuse{md(ruleEscape, "autoescape is false, so template output is not HTML-escaped", map[int][]string{0: {"=false"}})}
	js.builtins["autoescape"] = true
	js.misuse["noent"] = []misuse{md(ruleXXE, "noent substitutes external entities", map[int][]string{0: {"=true"}})}
	js.builtins["noent"] = true

	// ---- Python
	py := pySpec
	py.sinks["getattr"] = sink{kind: kCode, args: []int{1}}
	py.sinks["setattr"] = sink{kind: kCode, args: []int{1}}
	py.builtins["getattr"] = true
	py.builtins["setattr"] = true
	feat := []string{"feature_external_ges", "feature_external_pes", "external-general-entities", "external-parameter-entities"}
	py.misuse["?.setFeature"] = []misuse{md(ruleXXE, "external entities are enabled on the parser", map[int][]string{0: feat, 1: {"=true"}})}
	py.misuse["jinja2.Environment"] = []misuse{kwm(ruleEscape, "autoescape=False", map[string]string{"autoescape": "false"})}
	py.misuse["jinja2.Template"] = []misuse{kwm(ruleEscape, "autoescape=False", map[string]string{"autoescape": "false"})}
	py.sourceRoots["view_args"] = map[string]string{"*": "request path parameter"}

	// ---- Java
	jv := javaSpec
	jv.sinks["java.lang.Class.forName"] = sink{kind: kCode, args: []int{0}}
	jv.simpleTypes["Class"] = "java.lang.Class"
	for _, m := range []string{"queryParam", "pathVariable", "queryParams"} {
		jv.sourceMethods[m] = "request parameter"
	}

	// ---- PHP
	ph := phpSpec
	ph.nameSinks = map[string]kind{"html": kXSS, "output": kXSS}
	for _, f := range []string{"call_user_func", "call_user_func_array", "forward_static_call"} {
		ph.sinks[f] = sink{kind: kCode, args: []int{0}}
	}

	// ---- Ruby
	rb := rubySpec
	for _, m := range []string{"try", "__send__", "const_get", "safe_constantize", "instance_variable_get", "method"} {
		rb.sinks["?."+m] = sink{kind: kCode, args: []int{0}}
	}
	rb.sinks["?.safe_constantize"] = sink{kind: kCode, args: []int{-1}}

	addBuiltins()
}
