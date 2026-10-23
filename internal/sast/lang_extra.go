package sast

import "strings"

// Detections added on top of the per-language base models: weak crypto and certificate
// checks, debug flags, XML/LDAP/XPath/regex injection, and framework escape hatches.

func md(r rule, detail string, args map[int][]string) misuse {
	return misuse{rule: r, detail: detail, args: args}
}

func kwm(r rule, detail string, kw map[string]string) misuse {
	return misuse{rule: r, detail: detail, kw: kw}
}

func bare(r rule, detail string) misuse { return misuse{rule: r, detail: detail, bare: true} }

var (
	weakHash   = []string{"=md5", "=sha1", "=sha-1", "=md2", "=md4"}
	weakCipher = []string{"des", "rc4", "rc2", "blowfish", "ecb", "=aes"}
	worldBits  = []string{"777", "666", "776", "766"}
)

func init() {
	finishSpec := func(sp *langSpec) {
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
	}
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		finishSpec(sp)
	}

	// ---- Python
	py := pySpec
	for _, f := range append([]string{"request"}, pyHTTPFns...) {
		for _, lib := range []string{"requests", "httpx"} {
			py.misuse[lib+"."+f] = append(py.misuse[lib+"."+f], kwm(ruleTLS, "certificate verification is turned off", map[string]string{"verify": "false"}))
		}
	}
	py.misuse["requests.Session"] = nil
	for _, h := range []string{"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new", "Cryptodome.Hash.MD5.new"} {
		py.misuse[h] = []misuse{bare(ruleWeakCrypto, "this hash is broken for collision resistance")}
	}
	py.misuse["hashlib.new"] = []misuse{md(ruleWeakCrypto, "this hash is broken for collision resistance", map[int][]string{0: weakHash})}
	for _, c := range []string{"DES", "ARC4", "ARC2", "Blowfish"} {
		py.misuse["Crypto.Cipher."+c+".new"] = []misuse{bare(ruleWeakCrypto, c+" is a weak cipher")}
		py.misuse["Cryptodome.Cipher."+c+".new"] = []misuse{bare(ruleWeakCrypto, c+" is a weak cipher")}
	}
	py.misuse["ssl._create_unverified_context"] = []misuse{bare(ruleTLS, "the context does not verify certificates")}
	py.misuse["?.run"] = []misuse{kwm(ruleDebug, "the development server is started with debug=True", map[string]string{"debug": "true"})}
	py.misuse["jwt.decode"] = []misuse{kwm(ruleJWT, "verify=False skips signature verification", map[string]string{"verify": "false"})}
	py.misuse["tempfile.mktemp"] = []misuse{bare(ruleTempFile, "mktemp returns a name another process can claim first")}
	py.misuse["os.chmod"] = []misuse{md(ruleWorldWritable, "the mode makes the file writable by everyone", map[int][]string{1: worldBits})}
	py.misuse["?.set_cookie"] = []misuse{
		kwm(ruleCookie, "secure=False", map[string]string{"secure": "false"}),
		kwm(ruleCookie, "httponly=False", map[string]string{"httponly": "false"}),
	}
	py.misuse["lxml.etree.XMLParser"] = []misuse{kwm(ruleXXE, "resolve_entities is enabled", map[string]string{"resolve_entities": "true"})}
	py.misuse["xml.sax.make_parser"] = nil
	py.assignMisuse["verify_mode"] = assignMisuse{rule: ruleTLS, detail: "verify_mode is CERT_NONE", vals: []string{"cert_none"}}
	py.assignMisuse["check_hostname"] = assignMisuse{rule: ruleTLS, detail: "check_hostname is False", vals: []string{"=false"}}
	py.assignMisuse["DEBUG"] = assignMisuse{rule: ruleDebug, detail: "DEBUG is True in the settings", vals: []string{"=true"}, file: "settings"}
	py.sinks["?.xpath"] = sink{kind: kXPath, args: []int{0}}
	py.sinks["?.search_s"] = sink{kind: kLDAP, args: []int{1, 2}}
	py.sinks["?.search"] = sink{kind: kLDAP, args: []int{1}, recv: []string{"conn", "ldap", "connection", "ldap_conn", "l"}}
	py.sinks["re.compile"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.match"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.search"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.fullmatch"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.sub"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.findall"] = sink{kind: kRegex, args: []int{0}}
	py.sinks["re.split"] = sink{kind: kRegex, args: []int{0}}
	py.sanitizers["re.escape"] = kRegex
	py.sanitizers["ldap.filter.escape_filter_chars"] = kLDAP
	py.sanitizers["ldap3.utils.conv.escape_filter_chars"] = kLDAP

	// ---- JavaScript and TypeScript
	js := jsSpec
	js.misuse["crypto.createHash"] = []misuse{md(ruleWeakCrypto, "this hash is broken for collision resistance", map[int][]string{0: weakHash})}
	js.misuse["crypto.createCipher"] = []misuse{bare(ruleWeakCrypto, "createCipher derives a weak key and is removed from Node")}
	js.misuse["crypto.createCipheriv"] = []misuse{md(ruleWeakCrypto, "this cipher or mode is weak", map[int][]string{0: {"des", "rc4", "ecb", "bf-"}})}
	js.misuse["rejectUnauthorized"] = []misuse{md(ruleTLS, "rejectUnauthorized is false, so any certificate is accepted", map[int][]string{0: {"=false"}})}
	js.misuse["jsonwebtoken.decode"] = []misuse{bare(ruleJWT, "jwt.decode does not check the signature; use jwt.verify")}
	js.misuse["jwt.decode"] = []misuse{bare(ruleJWT, "jwt.decode does not check the signature; use jwt.verify")}
	js.misuse["jsonwebtoken.verify"] = []misuse{md(ruleJWT, "the algorithm none accepts unsigned tokens", map[int][]string{2: {"none"}})}
	js.assignMisuse["NODE_TLS_REJECT_UNAUTHORIZED"] = assignMisuse{rule: ruleTLS, detail: "NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate checks for the whole process", vals: []string{"=0"}}
	js.sinks["RegExp"] = sink{kind: kRegex, args: []int{0}}
	js.sinks["xpath.select"] = sink{kind: kXPath, args: []int{0}}
	js.sinks["xpath.evaluate"] = sink{kind: kXPath, args: []int{0}}
	js.sinks["xpath.parse"] = sink{kind: kXPath, args: []int{0}}
	js.sinks["?.search"] = sink{kind: kLDAP, args: []int{1}, recv: []string{"client", "ldap", "ldapClient", "ldapjs"}}
	for _, m := range []string{"html", "append", "prepend", "after", "before", "replaceWith", "wrap"} {
		js.sinks["?."+m] = sink{kind: kXSS, args: []int{0}, recv: []string{"$", "jQuery"}}
	}
	for _, m := range []string{"bypassSecurityTrustHtml", "bypassSecurityTrustScript", "bypassSecurityTrustUrl", "bypassSecurityTrustResourceUrl", "bypassSecurityTrustStyle"} {
		js.sinks["?."+m] = sink{kind: kXSS, args: []int{0}}
	}
	js.assignSinks["srcdoc"] = kXSS
	js.sanitizers["lodash.escapeRegExp"] = kRegex
	js.sanitizers["escape-string-regexp"] = kRegex
	js.sanitizers["_.escapeRegExp"] = kRegex
	js.builtins["RegExp"] = true
	js.builtins["rejectUnauthorized"] = true

	// ---- Java
	jv := javaSpec
	for k, v := range map[string]string{
		"MessageDigest": "java.security.MessageDigest", "Cipher": "javax.crypto.Cipher", "Pattern": "java.util.regex.Pattern",
		"XPath": "javax.xml.xpath.XPath", "SSLContext": "javax.net.ssl.SSLContext",
	} {
		jv.simpleTypes[k] = v
	}
	jv.misuse["java.security.MessageDigest.getInstance"] = []misuse{md(ruleWeakCrypto, "this hash is broken for collision resistance", map[int][]string{0: weakHash})}
	jv.misuse["javax.crypto.Cipher.getInstance"] = []misuse{md(ruleWeakCrypto, "this cipher or mode is weak (AES alone means ECB)", map[int][]string{0: weakCipher})}
	jv.misuse["?.setHostnameVerifier"] = []misuse{bare(ruleTLS, "a custom hostname verifier usually accepts everything")}
	jv.misuse["?.setDefaultHostnameVerifier"] = []misuse{bare(ruleTLS, "a custom hostname verifier usually accepts everything")}
	jv.misuse["?.setSecure"] = []misuse{md(ruleCookie, "the cookie is not marked Secure", map[int][]string{0: {"=false"}})}
	jv.misuse["?.setHttpOnly"] = []misuse{md(ruleCookie, "the cookie is not marked HttpOnly", map[int][]string{0: {"=false"}})}
	jv.misuse["?.setFeature"] = []misuse{md(ruleXXE, "external general entities are enabled", map[int][]string{0: {"external-general-entities"}, 1: {"=true"}})}
	jv.sinks["java.util.regex.Pattern.compile"] = sink{kind: kRegex, args: []int{0}}
	jv.sinks["?.search"] = sink{kind: kLDAP, args: []int{0, 1}, recv: []string{"ctx", "context", "dirContext", "ldapTemplate", "initialDirContext"}}
	jv.sinks["?.evaluate"] = sink{kind: kXPath, args: []int{0}, recv: []string{"xpath", "xPath", "xp"}}
	jv.sinks["javax.xml.xpath.XPath.compile"] = sink{kind: kXPath, args: []int{0}}
	jv.sanitizers["org.owasp.esapi.Encoder.encodeForLDAP"] = kLDAP
	jv.sanitizers["java.util.regex.Pattern.quote"] = kRegex

	// ---- PHP
	ph := phpSpec
	ph.misuse["curl_setopt"] = []misuse{
		md(ruleTLS, "CURLOPT_SSL_VERIFYPEER is false", map[int][]string{1: {"curlopt_ssl_verifypeer"}, 2: {"=false", "=0"}}),
		md(ruleTLS, "CURLOPT_SSL_VERIFYHOST is off", map[int][]string{1: {"curlopt_ssl_verifyhost"}, 2: {"=false", "=0"}}),
	}
	ph.misuse["extract"] = []misuse{md(ruleExtract, "extract() lets a request overwrite any variable", map[int][]string{0: {"=_get", "=_post", "=_request", "=_cookie"}})}
	ph.misuse["openssl_encrypt"] = []misuse{md(ruleWeakCrypto, "this cipher or mode is weak", map[int][]string{1: {"des", "rc4", "ecb"}})}
	ph.misuse["mcrypt_encrypt"] = []misuse{bare(ruleWeakCrypto, "mcrypt is abandoned and removed from PHP")}
	ph.misuse["ini_set"] = []misuse{md(ruleDebug, "display_errors prints internals to the user", map[int][]string{0: {"=display_errors"}, 1: {"=1", "=on", "=true"}})}
	ph.misuse["chmod"] = []misuse{md(ruleWorldWritable, "the mode makes the file writable by everyone", map[int][]string{1: worldBits})}
	ph.sinks["ldap_search"] = sink{kind: kLDAP, args: []int{1, 2}}
	ph.sinks["ldap_list"] = sink{kind: kLDAP, args: []int{1, 2}}
	ph.sinks["ldap_read"] = sink{kind: kLDAP, args: []int{1, 2}}
	ph.sinks["?.xpath"] = sink{kind: kXPath, args: []int{0}}
	ph.sinks["?.evaluate"] = sink{kind: kXPath, args: []int{0}, recv: []string{"xpath", "domxpath"}}
	ph.sinks["preg_match"] = sink{kind: kRegex, args: []int{0}}
	ph.sinks["preg_match_all"] = sink{kind: kRegex, args: []int{0}}
	ph.sinks["preg_replace"] = sink{kind: kRegex, args: []int{0}}
	ph.sinks["preg_split"] = sink{kind: kRegex, args: []int{0}}
	ph.sanitizers["preg_quote"] = kRegex
	ph.sanitizers["ldap_escape"] = kLDAP

	// ---- Ruby
	rb := rubySpec
	for _, h := range []string{"MD5", "SHA1"} {
		for _, m := range []string{"hexdigest", "digest", "base64digest", "new"} {
			rb.misuse["Digest."+h+"."+m] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
			rb.misuse["OpenSSL.Digest."+h+"."+m] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
		}
	}
	rb.misuse["OpenSSL.Cipher.new"] = []misuse{md(ruleWeakCrypto, "this cipher or mode is weak", map[int][]string{0: {"des", "rc4", "ecb"}})}
	rb.misuse["?.permit!"] = []misuse{bare(ruleMassAssign, "permit! accepts every parameter")}
	rb.misuse["skip_before_action"] = []misuse{md(ruleCSRF, "verify_authenticity_token is skipped", map[int][]string{0: {"verify_authenticity_token"}})}
	rb.misuse["File.chmod"] = []misuse{md(ruleWorldWritable, "the mode makes the file writable by everyone", map[int][]string{0: worldBits})}
	rb.assignMisuse["verify_mode"] = assignMisuse{rule: ruleTLS, detail: "verify_mode is VERIFY_NONE", vals: []string{"verify_none"}}
	rb.assignMisuse["consider_all_requests_local"] = assignMisuse{rule: ruleDebug, detail: "full error pages are shown to every client", vals: []string{"=true"}}
	rb.sinks["?.xpath"] = sink{kind: kXPath, args: []int{0}}
	rb.sinks["?.at_xpath"] = sink{kind: kXPath, args: []int{0}}
	rb.sinks["Regexp.new"] = sink{kind: kRegex, args: []int{0}}
	rb.sinks["?.search"] = sink{kind: kLDAP, args: []int{0}, recv: []string{"ldap"}}
	rb.sanitizers["Regexp.escape"] = kRegex
	rb.sanitizers["Net.LDAP.Filter.escape"] = kLDAP

	// Names a rule table mentions without a qualifier must resolve as globals.
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		for k := range sp.misuse {
			if !strings.HasPrefix(k, "?.") {
				first, _, _ := strings.Cut(k, ".")
				sp.builtins[first] = true
			}
		}
		for k := range sp.sanitizers {
			if !strings.HasPrefix(k, "?.") {
				first, _, _ := strings.Cut(k, ".")
				sp.builtins[first] = true
			}
		}
		for k := range sp.sinks {
			if !strings.HasPrefix(k, "?.") {
				first, _, _ := strings.Cut(k, ".")
				sp.builtins[first] = true
			}
		}
	}
}
