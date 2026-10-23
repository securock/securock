package sast

// Checks added after running the analyzer over Juice Shop's code-fix variants: Angular
// sources, weak URL allowlists, directory listings, mass assignment and LLM prompts.

func init() {
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		ensureSets(sp)
		if sp.misuse == nil {
			sp.misuse = map[string][]misuse{}
		}
	}
	weak := []misuse{bare(ruleWeakAllowlist, "the URL is accepted when it merely contains or starts with an allowed one")}
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, rubySpec} {
		sp.misuse["weakAllowlist"] = weak
		sp.builtins["weakAllowlist"] = true
	}

	// ---- JavaScript / TypeScript
	js := jsSpec
	// Angular: ActivatedRoute.snapshot.queryParams.q, this.route.snapshot.paramMap.get(...)
	for _, root := range []string{"route", "activatedRoute", "activeRoute", "router"} {
		js.sourceRoots[root] = map[string]string{
			"snapshot": "request query", "queryParams": "request query", "queryParamMap": "request query",
			"params": "request path parameter", "paramMap": "request path parameter", "fragment": "request query",
		}
	}
	js.misuse["serve-index"] = []misuse{bare(ruleDirListing, "serveIndex lists the files of a directory to anyone who asks")}
	js.misuse["serveIndex"] = []misuse{bare(ruleDirListing, "serveIndex lists the files of a directory to anyone who asks")}
	js.builtins["serveIndex"] = true
	for _, m := range []string{"create", "update", "updateOne", "updateMany", "build", "upsert", "bulkCreate", "findOneAndUpdate", "insertOne", "insertMany", "save"} {
		js.sinks["?."+m] = mergeSink(js.sinks["?."+m], sink{kind: kMass, args: []int{0}, recvUpper: true, direct: true})
	}
	// A string literal as the JWT secret: jwt.sign(payload, 'secret'), jwt.verify(t, 'secret').
	for _, m := range []string{"jsonwebtoken.sign", "jsonwebtoken.verify"} {
		js.misuse[m] = append(js.misuse[m], misuse{rule: ruleHardKey, detail: "the signing key is a string literal", literal: map[int]bool{1: true}})
	}
	// Headless browsers fetch and render whatever they are given: puppeteer and playwright
	// pages, wkhtmltopdf and PhantomJS.
	pages := []string{"page", "tab", "frame", "mainFrame", "newPage"}
	for _, m := range []string{"goto", "setContent", "open"} {
		js.sinks["?."+m] = mergeSink(js.sinks["?."+m], sink{kind: kSSRF, args: []int{0}, recv: pages})
	}
	js.sinks["?.evaluate"] = mergeSink(js.sinks["?.evaluate"], sink{kind: kCode, args: []int{0}, recv: pages})
	for _, m := range []string{"wkhtmltopdf", "wkhtmltoimage"} {
		js.sinks[m] = sink{kind: kSSRF, args: []int{0}}
		js.builtins[m] = true
	}
	// An LLM system prompt that includes request data: system: "...", {role: "system", content: x}
	js.sinks["llmPrompt"] = sink{kind: kPrompt, args: []int{0}}
	js.builtins["llmPrompt"] = true

	// ---- Ruby
	rb := rubySpec
	for _, m := range []string{"create", "create!", "update", "update!", "update_attributes", "new", "assign_attributes", "update_all"} {
		rb.sinks["?."+m] = mergeSink(rb.sinks["?."+m], sink{kind: kMass, args: []int{0}, recvUpper: true, direct: true})
	}

	jvMarker := javaSpec
	jvMarker.misuse["corsAnyOrigin"] = []misuse{bare(ruleCORS, "@CrossOrigin allows any origin together with credentials")}
	jvMarker.builtins["corsAnyOrigin"] = true
	pySpec.misuse["csrfUnprotected"] = []misuse{bare(ruleCSRF, "this view is exempt from CSRF protection")}
	pySpec.builtins["csrfUnprotected"] = true

	// ---- Python
	py := pySpec
	py.sinks["llmPrompt"] = sink{kind: kPrompt, args: []int{0}}
	py.sinks["?.create"] = mergeSink(py.sinks["?.create"], sink{kind: kPrompt, kw: []string{"system", "system_prompt", "instructions"}})
	py.sinks["?.generate_content"] = sink{kind: kPrompt, kw: []string{"system_instruction"}}
	py.builtins["llmPrompt"] = true

	addBuiltins()
}
