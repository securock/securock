package sast

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math"
	"regexp"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// weakCrypto maps a weak primitive to the reason it should not be used for security.
var weakCrypto = map[string]string{
	"crypto/md5.New":                "MD5 is broken for collision resistance",
	"crypto/md5.Sum":                "MD5 is broken for collision resistance",
	"crypto/sha1.New":               "SHA-1 is broken for collision resistance",
	"crypto/sha1.Sum":               "SHA-1 is broken for collision resistance",
	"crypto/des.NewCipher":          "DES has a 56-bit key",
	"crypto/des.NewTripleDESCipher": "3DES is deprecated and has a 64-bit block",
	"crypto/rc4.NewCipher":          "RC4 has known biases and is prohibited by RFC 7465",
}

// goModeArg maps a call to the index of its file-mode argument.
var goModeArg = map[string]int{
	"os.Chmod": 1, "os.Mkdir": 1, "os.MkdirAll": 1, "os.WriteFile": 2, "os.OpenFile": 2, "io/ioutil.WriteFile": 2,
}

var secretName = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_?key|access_?key|auth_?token|private_?key|client_?secret|token)`)

// notSecret names that contain a secret-looking word but describe something else.
var notSecret = regexp.MustCompile(`(?i)(header|path|file|url|uri|name|field|prefix|type|env|param|label|format|endpoint|placeholder|expired|invalid|missing|error|err|msg|message|hint)`)

var (
	ruleWeakCrypto = rule{"sast:go/weak-crypto", "CWE-327", "Weak cryptographic primitive",
		"Use SHA-256 or better for hashing and AES-GCM or ChaCha20-Poly1305 for encryption; use bcrypt, scrypt or argon2 for passwords.", finding.SeverityMedium}
	ruleTLS = rule{"sast:go/tls-verification-disabled", "CWE-295", "TLS certificate verification disabled",
		"Remove InsecureSkipVerify and trust the right CA through RootCAs instead.", finding.SeverityMedium}
	ruleSecret = rule{"sast:go/hardcoded-secret", "CWE-798", "Hard-coded credential",
		"Load the secret from the environment or a secret manager and rotate the exposed value.", finding.SeverityMedium}
)

type reporter struct {
	fset *token.FileSet
	rel  func(token.Pos) string
	fn   string
	out  []finding.Finding
}

func (r *reporter) add(pos token.Pos, ru rule, detail string) {
	p := r.fset.Position(pos)
	file := r.rel(pos)
	r.out = append(r.out, finding.Finding{
		ID:          ru.id,
		Severity:    ru.sev,
		Title:       ru.title + " (" + ru.cwe + ")",
		Detail:      detail,
		Subject:     file + "#" + r.fn,
		Remediation: ru.fix,
		Location:    &finding.Location{File: file, Line: p.Line, Column: p.Column},
	})
}

const skipVerifyDetail = "InsecureSkipVerify is true, so any certificate is accepted and connections can be intercepted"

func astRules(fset *token.FileSet, p *pkg, rel func(token.Pos) string) []finding.Finding {
	r := &reporter{fset: fset, rel: rel}
	for _, f := range p.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			r.fn = declName(fd)
			checked := map[types.Object]bool{}
			reported := map[token.Pos]bool{}
			weak := func(pos token.Pos, name string) {
				if !reported[pos] {
					reported[pos] = true
					r.add(pos, ruleInsecureRandom, name+" is predictable and is used to make a "+secretWord(r.fn))
				}
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					name := ""
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok {
							if pn, ok := p.info.Uses[id].(*types.PkgName); ok {
								name = pn.Imported().Path() + "." + sel.Sel.Name
							}
						}
					}
					if strings.HasPrefix(name, "math/rand.") || strings.HasPrefix(name, "math/rand/v2.") {
						if secretish.MatchString(r.fn) {
							weak(n.Pos(), shortName(name))
						}
					}
					if len(n.Args) > 0 {
						if id, ok := n.Args[0].(*ast.Ident); ok {
							if obj := p.info.Uses[id]; obj != nil {
								switch name {
								case "os.Stat", "os.Lstat", "syscall.Access":
									checked[obj] = true
								case "os.Remove", "os.RemoveAll", "os.Rename", "os.WriteFile", "os.OpenFile", "os.Create", "os.Chmod", "io/ioutil.WriteFile":
									if checked[obj] {
										r.add(n.Pos(), ruleToctou, shortName(name)+" acts on a path that was checked earlier in this function")
									}
								}
							}
						}
					}
					if idx, ok := goModeArg[name]; ok && idx < len(n.Args) {
						if tv := p.info.Types[n.Args[idx]]; tv.Value != nil && tv.Value.Kind() == constant.Int {
							if v, exact := constant.Int64Val(tv.Value); exact && v&0o002 != 0 {
								r.add(n.Pos(), ruleWorldWritable, fmt.Sprintf("%s is called with mode %#o, writable by everyone", shortName(name), v))
							}
						}
					}
					if why, ok := weakCrypto[name]; ok {
						r.add(n.Pos(), ruleWeakCrypto, why+" ("+shortName(name)+")")
					}
				case *ast.KeyValueExpr:
					if k, ok := n.Key.(*ast.Ident); ok {
						if k.Name == "MinVersion" {
							if tv := p.info.Types[n.Value]; tv.Value != nil && tv.Value.Kind() == constant.Int {
								if v, exact := constant.Int64Val(tv.Value); exact && v > 0 && v < 0x0303 {
									r.add(n.Pos(), ruleTLS, "MinVersion allows TLS older than 1.2, which has known attacks")
								}
							}
						}
						if k.Name == "InsecureSkipVerify" && isTrue(p.info, n.Value) {
							r.add(n.Pos(), ruleTLS, skipVerifyDetail)
						}
						r.checkSecret(k.Name, n.Value, n.Pos(), p.info)
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, l := range n.Lhs {
							if id, ok := l.(*ast.Ident); ok && secretish.MatchString(id.Name) {
								ast.Inspect(n.Rhs[i], func(x ast.Node) bool {
									if c, ok := x.(*ast.CallExpr); ok {
										if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
											if pid, ok := sel.X.(*ast.Ident); ok {
												if pn, ok := p.info.Uses[pid].(*types.PkgName); ok && strings.HasPrefix(pn.Imported().Path(), "math/rand") {
													weak(c.Pos(), shortName(pn.Imported().Path()+"."+sel.Sel.Name))
												}
											}
										}
									}
									return true
								})
							}
						}
					}
					if len(n.Lhs) != len(n.Rhs) {
						return true
					}
					for i, l := range n.Lhs {
						name := ""
						switch l := l.(type) {
						case *ast.Ident:
							name = l.Name
						case *ast.SelectorExpr:
							name = l.Sel.Name
						}
						if name == "InsecureSkipVerify" && isTrue(p.info, n.Rhs[i]) {
							r.add(n.Pos(), ruleTLS, skipVerifyDetail)
						}
						if name != "" {
							r.checkSecret(name, n.Rhs[i], n.Pos(), p.info)
						}
					}
				}
				return true
			})
		}
	}
	return r.out
}

func isTrue(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && constant.BoolVal(tv.Value)
}

func (r *reporter) checkSecret(name string, value ast.Expr, pos token.Pos, info *types.Info) {
	if !secretName.MatchString(name) || notSecret.MatchString(name) {
		return
	}
	tv, ok := info.Types[value]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return
	}
	if looksLikeSecret(constant.StringVal(tv.Value)) {
		r.add(pos, ruleSecret, fmt.Sprintf("%s is assigned a literal that looks like a secret", name))
	}
}

// looksLikeSecret filters placeholders and prose: a credential is a single token with
// enough entropy that it is unlikely to be a word or a template.
func looksLikeSecret(s string) bool {
	if len(s) < 12 || len(s) > 256 || strings.ContainsAny(s, " \t\n{}<>$%") {
		return false
	}
	low := strings.ToLower(s)
	for _, p := range []string{"example", "changeme", "placeholder", "xxxx", "your", "test", "dummy", "sample"} {
		if strings.Contains(low, p) {
			return false
		}
	}
	return entropy(s) >= 3.2
}

func entropy(s string) float64 {
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
