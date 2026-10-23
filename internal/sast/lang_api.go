package sast

import "regexp"

// Weak and dangerous API uses found missing when the analyzers were compared with
// Semgrep's published test cases: they need no taint, only the call and its arguments.

var passwordish = regexp.MustCompile(`(?i)(pass|pwd|secret|token)`)

func init() {
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		ensureSets(sp)
	}
	cookieFlags := []string{"secure", "httponly"}
	weakTLS := []string{"=ssl", "=sslv2", "=sslv3", "=tlsv1", "=tlsv1.0", "=tlsv1.1"}

	// ---- Python
	py := pySpec
	py.misuse["?.set_cookie"] = append(py.misuse["?.set_cookie"], misuse{rule: ruleCookie, detail: "the cookie is set without Secure and HttpOnly", missingKw: cookieFlags})
	py.misuse["ssl.wrap_socket"] = []misuse{bare(ruleTLS, "ssl.wrap_socket is deprecated and does not verify the server by default")}
	py.misuse["ssl.wrap_socket.version"] = nil
	for _, v := range []string{"protocol_sslv2", "protocol_sslv3", "protocol_tlsv1", "protocol_tlsv1_1"} {
		py.misuse["ssl.SSLContext"] = append(py.misuse["ssl.SSLContext"], md(ruleTLS, "a protocol version with known attacks", map[int][]string{0: {v}}))
		py.misuse["ssl.wrap_socket"] = append(py.misuse["ssl.wrap_socket"], kwm(ruleTLS, "a protocol version with known attacks", map[string]string{"ssl_version": "ssl." + v}))
	}
	for _, v := range []string{"sslv2_method", "sslv3_method", "tlsv1_method", "tlsv1_1_method"} {
		py.misuse["OpenSSL.SSL.Context"] = append(py.misuse["OpenSSL.SSL.Context"], md(ruleTLS, "a protocol version with known attacks", map[int][]string{0: {v}}))
	}
	for _, c := range []string{"Blowfish", "ARC4", "IDEA", "CAST5", "SEED", "TripleDES", "Camellia"} {
		py.misuse["cryptography.hazmat.primitives.ciphers.algorithms."+c] = []misuse{bare(ruleCipherMisuse, c+" is a weak cipher")}
		py.misuse["algorithms."+c] = []misuse{bare(ruleCipherMisuse, c+" is a weak cipher")}
	}
	py.misuse["cryptography.hazmat.primitives.ciphers.modes.ECB"] = []misuse{bare(ruleCipherMisuse, "ECB leaks patterns in the plaintext")}
	py.misuse["modes.ECB"] = []misuse{bare(ruleCipherMisuse, "ECB leaks patterns in the plaintext")}
	for _, h := range []string{"MD5", "SHA1", "MD2", "MD4"} {
		py.misuse["cryptography.hazmat.primitives.hashes."+h] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
		py.misuse["hashes."+h] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
	}
	py.sinks["asyncio.subprocess.create_subprocess_shell"] = sink{kind: kCmd, args: []int{0}}
	py.sinks["asyncio.create_subprocess_shell"] = sink{kind: kCmd, args: []int{0}}
	py.sinks["?.subprocess_shell"] = sink{kind: kCmd, args: []int{1}}

	// ---- PHP
	ph := phpSpec
	ph.misuse["md5"] = []misuse{{rule: ruleWeakCrypto, detail: "MD5 is not a password hash", argRe: map[int]*regexp.Regexp{0: passwordish}}}
	ph.misuse["sha1"] = []misuse{{rule: ruleWeakCrypto, detail: "SHA-1 is not a password hash", argRe: map[int]*regexp.Regexp{0: passwordish}}}
	ph.misuse["crypt"] = []misuse{bare(ruleWeakCrypto, "crypt() without a strong salt and algorithm is weak")}
	ph.misuse["hash"] = []misuse{md(ruleWeakCrypto, "this hash is broken for collision resistance", map[int][]string{0: {"=md5", "=sha1", "=md4", "=md2"}})}
	ph.misuse["ldap_bind"] = []misuse{{rule: ruleWeakCrypto, detail: "an LDAP bind without a password is an anonymous bind", argc: 1}, md(ruleWeakCrypto, "an LDAP bind with a null password is an anonymous bind", map[int][]string{2: {"=null"}})}
	ph.sinks["wp_remote_get"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["wp_remote_post"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["wp_remote_request"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["wp_remote_head"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["wp_safe_remote_get"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["wp_safe_remote_post"] = sink{kind: kSSRF, args: []int{0}}
	ph.sinks["curl_setopt"] = sink{kind: kSSRF, args: []int{2}, when: map[int][]string{1: {"=curlopt_url"}}}
	for _, f := range []string{"file_get_contents", "fopen", "readfile", "file"} {
		s := ph.sinks[f]
		s.kind |= kSSRF
		s.directFor |= kSSRF
		ph.sinks[f] = s
	}
	ph.misuse["setcookie"] = []misuse{{rule: ruleCookie, detail: "the cookie is set without the Secure and HttpOnly flags", argc: 2}}

	// ---- Ruby
	rb := rubySpec
	rb.misuse["JWT.decode"] = []misuse{md(ruleJWT, "the token's signature is not verified", map[int][]string{2: {"=false"}})}
	rb.assignMisuse["force_ssl"] = assignMisuse{rule: ruleHTTPS, detail: "force_ssl is false", vals: []string{"=false"}}
	rb.assignMisuse["cookies_serializer"] = assignMisuse{rule: ruleDeserCfg, detail: "the cookie serializer can instantiate arbitrary objects", vals: []string{"marshal", "hybrid"}}
	rb.sinks["Process.spawn"] = sink{kind: kCmd, args: []int{0}}
	rb.sinks["Process.exec"] = sink{kind: kCmd, args: []int{0}}
	rb.sinks["CSV.load"] = sink{kind: kDeser, args: []int{0}}
	rb.sinks["Oj.object_load"] = sink{kind: kDeser, args: []int{0}}
	rb.sinks["sqlOption"] = sink{kind: kSQL, args: []int{0}, strArg: true}
	rb.builtins["sqlOption"] = true
	rb.builtins["cookieFlag"] = true
	rb.misuse["cookieFlag"] = []misuse{bare(ruleCookie, "a session cookie option turns a protection off")}

	// ---- Java
	jv := javaSpec
	jv.misuse["javax.net.ssl.SSLContext.getInstance"] = []misuse{md(ruleTLS, "this protocol version has known attacks", map[int][]string{0: weakTLS})}
	jv.misuse["javax.crypto.NullCipher"] = []misuse{bare(ruleCipherMisuse, "NullCipher does not encrypt")}
	for _, m := range []string{"md5", "md5Hex", "getMd5Digest", "sha1", "sha1Hex", "getSha1Digest", "shaHex", "sha"} {
		jv.misuse["org.apache.commons.codec.digest.DigestUtils."+m] = []misuse{bare(ruleWeakCrypto, "MD5 and SHA-1 are broken for collision resistance")}
	}
	// JWT libraries (jjwt, java-jwt) and Spring Security configuration.
	jv.misuse["?.setSigningKey"] = []misuse{{rule: ruleHardKey, detail: "the signing key is a string literal", literal: map[int]bool{0: true}}}
	jv.misuse["?.signWith"] = append(jv.misuse["?.signWith"], md(ruleJWT, "the algorithm none issues unsigned tokens", map[int][]string{0: {"none"}}), md(ruleJWT, "the algorithm none issues unsigned tokens", map[int][]string{1: {"none"}}))
	jv.misuse["?.parseClaimsJwt"] = []misuse{bare(ruleJWT, "parseClaimsJwt accepts tokens that carry no signature")}
	jv.misuse["?.parsePlaintextJwt"] = []misuse{bare(ruleJWT, "parsePlaintextJwt accepts tokens that carry no signature")}
	jv.misuse["com.auth0.jwt.JWT.decode"] = []misuse{bare(ruleJWT, "JWT.decode does not verify the signature; use a verifier")}
	jv.misuse["com.auth0.jwt.algorithms.Algorithm.none"] = []misuse{bare(ruleJWT, "the algorithm none issues unsigned tokens")}
	jv.misuse["?.disable"] = []misuse{
		{rule: ruleCSRF, detail: "csrf().disable() turns off CSRF protection", recvCall: "csrf"},
		{rule: ruleCSRF, detail: "CSRF protection is disabled", recv: []string{"csrf"}},
	}
	jv.misuse["?.permitAll"] = []misuse{{rule: rulePermitAll, detail: "anyRequest().permitAll() leaves every endpoint open", recvCall: "anyRequest"}}
	jv.simpleTypes["JWT"] = "com.auth0.jwt.JWT"
	jv.simpleTypes["Algorithm"] = "com.auth0.jwt.algorithms.Algorithm"
	jv.cookieCtors = map[string]bool{"javax.servlet.http.Cookie": true, "jakarta.servlet.http.Cookie": true}
	jv.simpleTypes["NullCipher"] = "javax.crypto.NullCipher"
	jv.simpleTypes["SSLContext"] = "javax.net.ssl.SSLContext"

	// ---- JavaScript
	js := jsSpec
	js.builtins["cookieFlag"] = true
	js.misuse["cookieFlag"] = []misuse{bare(ruleCookie, "a cookie option turns a protection off")}

	addBuiltins()
}
