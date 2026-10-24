package sast

// Sinks and sources that were missing when the analyzers were run against real
// vulnerable applications (NodeGoat, DVWA, railsgoat, pygoat, WebGoat).

func init() {
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		ensureSets(sp)
	}
	// ---- JavaScript
	js := jsSpec
	js.misuse["autoescape"] = []misuse{md(ruleEscape, "autoescape is false, so template output is not HTML-escaped", map[int][]string{0: {"=false"}})}
	js.builtins["autoescape"] = true
	js.misuse["errorhandler"] = []misuse{bare(ruleDebug, "the errorhandler middleware sends stack traces to the client")}
	js.builtins["errorhandler"] = true
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
	for _, f := range []string{"normalvariate", "gauss", "betavariate", "expovariate", "gammavariate", "lognormvariate", "vonmisesvariate",
		"paretovariate", "weibullvariate", "triangular", "randbytes", "binomialvariate"} {
		py.weakRNG["random."+f] = true
	}
	// JSON and template responses are not HTML built from the value.
	for _, f := range []string{"flask.jsonify", "flask.render_template", "django.shortcuts.render", "django.http.JsonResponse"} {
		py.sanitizers[f] = kXSS
	}
	// Rendering a template whose file name is request data executes that file's
	// content as a Jinja template; a template is always a developer-written
	// constant. Raw output of request data inside an escaped template is checked
	// separately against the template file.
	py.sinks["flask.render_template"] = sink{kind: kCode, args: []int{0}}
	py.sinks["django.shortcuts.render"] = sink{kind: kCode, args: []int{1}}
	py.assignRoots = map[string]kind{"session": kRand | kTrust, "mysession": kRand | kTrust}
	py.sinks["codecs.open"] = sink{kind: kPath, args: []int{0}}
	py.sinks["io.open"] = sink{kind: kPath, args: []int{0}}
	py.sinks["os.open"] = sink{kind: kPath, args: []int{0}}
	for _, m := range []string{"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "touch", "iterdir"} {
		py.sinks["?."+m] = sink{kind: kPath, args: []int{-1}}
	}
	py.sinks["lxml.etree.XPath"] = sink{kind: kXPath, args: []int{0}}
	py.sinks["lxml.etree.ETXPath"] = sink{kind: kXPath, args: []int{0}}
	for _, m := range []string{"findall", "iterfind", "findtext", "find"} {
		py.sinks["?."+m] = sink{kind: kXPath, args: []int{0}, recv: []string{"root", "tree", "doc", "xml", "et", "element", "elem", "node"}}
	}
	py.sourceRoots["view_args"] = map[string]string{"*": "request path parameter"}

	// ---- Java
	jv := javaSpec
	jv.pkgRoots = map[string]bool{"java": true, "javax": true, "jakarta": true, "org": true, "com": true, "net": true, "io": true}
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

	// ---- random values and trust boundaries
	js.sinks["?.cookie"] = sink{kind: kRand, args: []int{1}, recv: []string{"res", "response", "reply", "ctx"}}
	py.sinks["?.set_cookie"] = sink{kind: kRand, args: []int{1}}
	ph.sinks["setcookie"] = sink{kind: kRand, args: []int{1}}
	for _, pkg := range []string{"javax", "jakarta"} {
		jv.sinks[pkg+".servlet.http.Cookie"] = sink{kind: kRand, args: []int{1}}
		jv.sinks[pkg+".servlet.http.HttpSession.setAttribute"] = sink{kind: kTrust, args: []int{0, 1}}
		jv.sinks[pkg+".servlet.http.HttpSession.putValue"] = sink{kind: kTrust, args: []int{0, 1}}
		jv.returns[pkg+".servlet.http.HttpServletRequest.getSession"] = pkg + ".servlet.http.HttpSession"
		jv.simpleTypes["HttpSession"] = pkg + ".servlet.http.HttpSession"
	}
	jv.simpleTypes["Cookie"] = "javax.servlet.http.Cookie"

	addBuiltins()
}
