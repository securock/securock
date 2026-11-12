package sast

import (
	"go/ast"
	"go/constant"
	"go/token"
	"net/url"
	"strings"
)

// fixedEncodedURL recognizes a fixed destination followed by one escaped component.
// Escaping alone cannot validate the destination: the constant prefix must already
// put the component after the authority. This proof applies only at a URL sink,
// so stripping the prefix later does not turn the component into trusted data.
func (a *analyzer) fixedEncodedURL(e ast.Expr) bool {
	b, ok := unparen(e).(*ast.BinaryExpr)
	if !ok || b.Op != token.ADD {
		return false
	}
	prefix := a.info.Types[b.X].Value
	if prefix == nil || prefix.Kind() != constant.String {
		return false
	}
	call, ok := unparen(b.Y).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	name, _ := a.calleeName(call.Fun)
	if name != "net/url.QueryEscape" && name != "net/url.PathEscape" {
		return false
	}
	text := constant.StringVal(prefix)
	if strings.ContainsAny(text, "\\\r\n\t ") {
		return false
	}
	u, err := url.Parse(text)
	if err != nil {
		return false
	}
	if u.Scheme == "" && u.Host == "" {
		return strings.HasPrefix(text, "/") && !strings.HasPrefix(text, "//")
	}
	return (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" &&
		(u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "")
}
