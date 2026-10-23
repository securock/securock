package sast

// Log injection, CORS, predictable randomness, TOCTOU and XXE tables.

func init() {
	logRecv := []string{"logger", "log", "logging", "LOG", "LOGGER", "_logger", "app", "winston", "pino", "bunyan", "Rails", "console"}
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		ensureSets(sp)
	}

	// ---- JavaScript
	js := jsSpec
	for _, m := range []string{"log", "info", "warn", "error", "debug"} {
		js.sinks["console."+m] = sink{kind: kLog, args: []int{0}, rest: true}
		js.sinks["?."+m] = mergeSink(js.sinks["?."+m], sink{kind: kLog, args: []int{0}, rest: true, recv: logRecv})
	}
	for _, m := range []string{"setHeader", "header", "set", "append", "add", "writeHead"} {
		js.sinks["?."+m] = mergeSink(js.sinks["?."+m], sink{kind: kCORS, args: []int{1}, recv: []string{"res", "response", "reply", "ctx"},
			when: map[int][]string{0: {"access-control-allow-origin"}}})
	}
	js.sinks["corsConfig"] = sink{kind: kCORS, args: []int{0}, when: map[int][]string{1: {"=true"}}}
	js.sinks["mongoWhere"] = sink{kind: kNoSQLStr, args: []int{0}}
	js.misuse["corsConfig"] = []misuse{md(ruleCORS, "origin: true reflects every origin while credentials: true is on", map[int][]string{0: {"=true"}, 1: {"=true"}})}
	js.sanitizers["?.replace"] = kLog
	js.sanitizers["?.replaceAll"] = kLog
	js.sanitizers["JSON.stringify"] = kLog
	js.weakRNG["Math.random"] = true
	for _, f := range []string{"existsSync", "accessSync", "statSync", "lstatSync", "exists", "access", "stat", "lstat"} {
		js.fsCheck["fs."+f] = true
	}
	for _, f := range []string{"unlinkSync", "unlink", "writeFileSync", "writeFile", "rmSync", "rm", "renameSync", "rename", "createWriteStream", "appendFileSync", "chmodSync"} {
		js.fsUse["fs."+f] = true
	}
	js.builtins["Math"] = true
	js.builtins["console"] = true

	// ---- Python
	py := pySpec
	for _, m := range []string{"info", "warning", "error", "debug", "critical", "exception"} {
		py.sinks["logging."+m] = sink{kind: kLog, args: []int{0}, rest: true}
		py.sinks["?."+m] = mergeSink(py.sinks["?."+m], sink{kind: kLog, args: []int{0}, rest: true, recv: logRecv})
	}
	py.sinks["?.add_header"] = sink{kind: kCORS, args: []int{1}, when: map[int][]string{0: {"access-control-allow-origin"}}}
	py.misuse["flask_cors.CORS"] = []misuse{kwm(ruleCORS, "supports_credentials with a wildcard origin", map[string]string{"supports_credentials": "true", "origins": "*"})}
	py.sanitizers["?.replace"] = kLog
	py.sanitizers["json.dumps"] = kLog
	py.sanitizers["repr"] = kLog
	for _, f := range []string{"random", "randint", "choice", "choices", "randrange", "getrandbits", "sample", "shuffle", "uniform"} {
		py.weakRNG["random."+f] = true
	}
	for _, f := range []string{"os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.islink", "os.path.lexists", "os.access", "os.stat"} {
		py.fsCheck[f] = true
	}
	for _, f := range []string{"os.remove", "os.unlink", "os.rename", "os.rmdir", "shutil.rmtree", "shutil.move", "os.chmod"} {
		py.fsUse[f] = true
	}

	// ---- Java
	jv := javaSpec
	for _, m := range []string{"info", "warn", "error", "debug", "trace", "fatal"} {
		jv.sinks["?."+m] = mergeSink(jv.sinks["?."+m], sink{kind: kLog, args: []int{0}, rest: true, recv: logRecv})
	}
	for _, m := range []string{"setHeader", "addHeader"} {
		jv.sinks["?."+m] = mergeSink(jv.sinks["?."+m], sink{kind: kCORS, args: []int{1}, when: map[int][]string{0: {"access-control-allow-origin"}}})
	}
	jv.sanitizers["?.replace"] = kLog
	jv.sanitizers["?.replaceAll"] = kLog
	jv.sanitizers["org.owasp.encoder.Encode.forJava"] = kLog
	jv.weakRNG["java.util.Random"] = true
	jv.weakRNG["java.lang.Math.random"] = true
	for k, v := range map[string]string{"DocumentBuilderFactory": "javax.xml.parsers.DocumentBuilderFactory", "SAXParserFactory": "javax.xml.parsers.SAXParserFactory",
		"XMLInputFactory": "javax.xml.stream.XMLInputFactory", "TransformerFactory": "javax.xml.transform.TransformerFactory", "Random": "java.util.Random"} {
		jv.simpleTypes[k] = v
	}
	for _, f := range []string{"javax.xml.parsers.DocumentBuilderFactory.newInstance", "javax.xml.parsers.SAXParserFactory.newInstance",
		"javax.xml.stream.XMLInputFactory.newInstance", "javax.xml.stream.XMLInputFactory.newFactory", "javax.xml.transform.TransformerFactory.newInstance"} {
		jv.xxeFactories[f] = true
	}
	for _, f := range []string{"java.io.File.exists", "java.io.File.isFile", "java.io.File.canWrite", "java.io.File.canRead", "java.io.File.isDirectory", "java.nio.file.Files.exists", "java.nio.file.Files.isRegularFile"} {
		jv.fsCheck[f] = true
	}
	for _, f := range []string{"java.io.File.delete", "java.io.File.renameTo", "java.nio.file.Files.delete", "java.nio.file.Files.deleteIfExists", "java.nio.file.Files.write", "java.nio.file.Files.move", "java.nio.file.Files.copy"} {
		jv.fsUse[f] = true
	}

	// ---- PHP
	ph := phpSpec
	ph.sinks["error_log"] = sink{kind: kLog, args: []int{0}}
	for _, m := range []string{"info", "warning", "error", "debug", "notice"} {
		ph.sinks["?."+m] = sink{kind: kLog, args: []int{0}, recv: logRecv}
	}
	for _, f := range []string{"rand", "mt_rand", "uniqid", "lcg_value", "shuffle", "str_shuffle", "array_rand", "mt_getrandmax"} {
		ph.weakRNG[f] = true
	}
	for _, f := range []string{"file_exists", "is_file", "is_writable", "is_readable", "is_dir", "is_link"} {
		ph.fsCheck[f] = true
	}
	for _, f := range []string{"unlink", "rename", "file_put_contents", "rmdir", "chmod", "copy"} {
		ph.fsUse[f] = true
	}
	ph.misuse["?.loadXML"] = []misuse{md(ruleXXE, "LIBXML_NOENT substitutes external entities", map[int][]string{1: {"libxml_noent"}})}
	ph.misuse["?.load"] = []misuse{md(ruleXXE, "LIBXML_NOENT substitutes external entities", map[int][]string{1: {"libxml_noent"}})}
	ph.misuse["simplexml_load_string"] = []misuse{md(ruleXXE, "LIBXML_NOENT substitutes external entities", map[int][]string{2: {"libxml_noent"}})}
	ph.misuse["simplexml_load_file"] = []misuse{md(ruleXXE, "LIBXML_NOENT substitutes external entities", map[int][]string{2: {"libxml_noent"}})}
	ph.misuse["libxml_disable_entity_loader"] = []misuse{md(ruleXXE, "the entity loader is switched back on", map[int][]string{0: {"=false"}})}

	// ---- Ruby
	rb := rubySpec
	for _, m := range []string{"info", "warn", "error", "debug", "fatal"} {
		rb.sinks["?."+m] = mergeSink(rb.sinks["?."+m], sink{kind: kLog, args: []int{0}, recv: logRecv})
	}
	rb.sanitizers["?.gsub"] = kLog
	rb.sanitizers["?.inspect"] = kLog
	rb.sanitizers["?.dump"] = kLog
	rb.sanitizers["?.delete"] = kLog
	for _, f := range []string{"rand", "Random.rand", "Random.new", "Kernel.rand", "Array.shuffle"} {
		rb.weakRNG[f] = true
	}
	for _, f := range []string{"File.exist?", "File.file?", "File.directory?", "File.readable?", "File.writable?", "File.symlink?"} {
		rb.fsCheck[f] = true
	}
	for _, f := range []string{"File.delete", "File.rename", "File.write", "File.chmod", "FileUtils.rm", "FileUtils.rm_f", "FileUtils.rm_rf", "FileUtils.mv"} {
		rb.fsUse[f] = true
	}
	rb.misuse["Nokogiri.XML"] = []misuse{md(ruleXXE, "the NOENT option substitutes external entities", map[int][]string{3: {"noent"}})}

	addBuiltins()
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		for _, set := range []map[string]bool{sp.weakRNG, sp.fsCheck, sp.fsUse} {
			for k := range set {
				first, _, _ := cut(k)
				sp.builtins[first] = true
			}
		}
	}
}

func cut(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// ensureSets makes the optional tables exist, whichever init runs first.
func ensureSets(sp *langSpec) {
	if sp.sinks == nil {
		sp.sinks = map[string]sink{}
	}
	if sp.sanitizers == nil {
		sp.sanitizers = map[string]kind{}
	}
	if sp.builtins == nil {
		sp.builtins = map[string]bool{}
	}
	if sp.misuse == nil {
		sp.misuse = map[string][]misuse{}
	}
	if sp.assignMisuse == nil {
		sp.assignMisuse = map[string]assignMisuse{}
	}
	if sp.simpleTypes == nil {
		sp.simpleTypes = map[string]string{}
	}
	if sp.sourceRoots == nil {
		sp.sourceRoots = map[string]map[string]string{}
	}
	if sp.sourcePrefixes == nil {
		sp.sourcePrefixes = map[string]string{}
	}
	if sp.sourceMethods == nil {
		sp.sourceMethods = map[string]string{}
	}
	if sp.returns == nil {
		sp.returns = map[string]string{}
	}
	if sp.weakRNG == nil {
		sp.weakRNG = map[string]bool{}
	}
	if sp.fsCheck == nil {
		sp.fsCheck = map[string]bool{}
	}
	if sp.fsUse == nil {
		sp.fsUse = map[string]bool{}
	}
	if sp.xxeFactories == nil {
		sp.xxeFactories = map[string]bool{}
	}
}
