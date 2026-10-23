package sast

import (
	"regexp"
	"sort"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// kind is a class of injection. A tainted value carries the set of kinds it can still
// trigger, so a sanitizer that only neutralizes one class (HTML escaping does nothing
// against SQL injection) clears only that bit.
type kind uint32

const (
	kSQL kind = 1 << iota
	kCmd
	kPath
	kSSRF
	kXSS
	kRedirect
	kCode
	kDeser
	kXPath
	kLDAP
	kRegex

	kLast = kRegex
	kAll  = kSQL | kCmd | kPath | kSSRF | kXSS | kRedirect | kCode | kDeser | kXPath | kLDAP | kRegex
)

type rule struct {
	id    string
	cwe   string
	title string
	fix   string
	sev   finding.Severity
}

var taintRules = map[kind]rule{
	kSQL:      {"sast:go/sql-injection", "CWE-89", "SQL injection", "Pass untrusted values as query parameters (placeholders) instead of building the SQL string.", finding.SeverityHigh},
	kCmd:      {"sast:go/command-injection", "CWE-78", "OS command injection", "Do not build commands from untrusted input; use a fixed executable with validated arguments and avoid shells.", finding.SeverityHigh},
	kPath:     {"sast:go/path-traversal", "CWE-22", "Path traversal", "Reduce the input to a bare file name, validate it against an allowlist, or resolve the path and check that it stays inside the intended directory.", finding.SeverityHigh},
	kSSRF:     {"sast:go/ssrf", "CWE-918", "Server-side request forgery", "Validate the destination against an allowlist of hosts before making the request.", finding.SeverityMedium},
	kXSS:      {"sast:go/xss", "CWE-79", "Cross-site scripting", "Escape the value for its output context (HTML-encode it, or use a template engine that escapes by default) before writing it to the response.", finding.SeverityMedium},
	kRedirect: {"sast:go/open-redirect", "CWE-601", "Open redirect", "Only redirect to relative paths or to destinations on an allowlist.", finding.SeverityMedium},
	kCode:     {"sast:go/code-injection", "CWE-94", "Code injection", "Never evaluate untrusted input as code; parse it as data instead.", finding.SeverityCritical},
	kXPath:    {"sast:go/xpath-injection", "CWE-643", "XPath injection", "Use a parameterized XPath API, or validate the value against a strict allowlist before building the expression.", finding.SeverityHigh},
	kLDAP:     {"sast:go/ldap-injection", "CWE-90", "LDAP injection", "Escape the value for use in an LDAP filter, or build the filter with a library that does.", finding.SeverityHigh},
	kRegex:    {"sast:go/regex-injection", "CWE-1333", "Regular expression built from untrusted input", "Escape the value with the language's regex-quoting function, or match it as a literal string.", finding.SeverityMedium},
	kDeser:    {"sast:go/insecure-deserialization", "CWE-502", "Insecure deserialization", "Do not deserialize untrusted data with a format that can instantiate arbitrary types; use JSON or a schema-validated format.", finding.SeverityHigh},
}

// ruleFor is the rule for a kind, with its id in the namespace of the analyzed language.
func ruleFor(k kind, lang string) rule {
	r := taintRules[k]
	r.id = strings.Replace(r.id, "go/", lang+"/", 1)
	return r
}

// sink is a call whose listed arguments must not carry untrusted data of the given kind.
type sink struct {
	kind kind
	args []int // -1 stands for the receiver
	// rest also covers every argument after the last listed one.
	rest bool
	// shellFrom, when positive, makes the arguments from that index dangerous too if the
	// executable named by args[0] is a constant shell (sh -c <tainted>).
	shellFrom int
	// writer limits the sink to calls whose first argument is an http.ResponseWriter.
	writer bool
	// kwTrue limits the sink to calls passing this keyword argument as true, such as
	// subprocess.run(cmd, shell=True): without it no shell parses the string.
	kwTrue string
	// recv limits a method-name sink ("?.send") to receivers whose variable has one of
	// these names, so res.send(x) is a response but socket.send(x) is not.
	recv []string
	// strArg skips arguments that are hashes or arrays: Ruby's where(name: x) is
	// parameterized, where("name = '#{x}'") is not.
	strArg bool
	// solo limits the sink to calls with exactly one argument: Ruby's system("ls", x)
	// runs ls directly, only system("ls #{x}") goes through a shell.
	solo bool
}

var sinks = map[string]sink{
	"(*database/sql.DB).Query":                      {kind: kSQL, args: []int{0}},
	"(*database/sql.DB).QueryRow":                   {kind: kSQL, args: []int{0}},
	"(*database/sql.DB).Exec":                       {kind: kSQL, args: []int{0}},
	"(*database/sql.DB).Prepare":                    {kind: kSQL, args: []int{0}},
	"(*database/sql.DB).QueryContext":               {kind: kSQL, args: []int{1}},
	"(*database/sql.DB).QueryRowContext":            {kind: kSQL, args: []int{1}},
	"(*database/sql.DB).ExecContext":                {kind: kSQL, args: []int{1}},
	"(*database/sql.DB).PrepareContext":             {kind: kSQL, args: []int{1}},
	"(*database/sql.Tx).Query":                      {kind: kSQL, args: []int{0}},
	"(*database/sql.Tx).QueryRow":                   {kind: kSQL, args: []int{0}},
	"(*database/sql.Tx).Exec":                       {kind: kSQL, args: []int{0}},
	"(*database/sql.Tx).Prepare":                    {kind: kSQL, args: []int{0}},
	"(*database/sql.Tx).QueryContext":               {kind: kSQL, args: []int{1}},
	"(*database/sql.Tx).QueryRowContext":            {kind: kSQL, args: []int{1}},
	"(*database/sql.Tx).ExecContext":                {kind: kSQL, args: []int{1}},
	"(*database/sql.Tx).PrepareContext":             {kind: kSQL, args: []int{1}},
	"(*database/sql.Conn).QueryContext":             {kind: kSQL, args: []int{1}},
	"(*database/sql.Conn).QueryRowContext":          {kind: kSQL, args: []int{1}},
	"(*database/sql.Conn).ExecContext":              {kind: kSQL, args: []int{1}},
	"(*database/sql.Conn).PrepareContext":           {kind: kSQL, args: []int{1}},
	"(*github.com/jmoiron/sqlx.DB).Queryx":          {kind: kSQL, args: []int{0}},
	"(*github.com/jmoiron/sqlx.DB).Exec":            {kind: kSQL, args: []int{0}},
	"(*github.com/jmoiron/sqlx.DB).MustExec":        {kind: kSQL, args: []int{0}},
	"(*github.com/jmoiron/sqlx.DB).Get":             {kind: kSQL, args: []int{1}},
	"(*github.com/jmoiron/sqlx.DB).Select":          {kind: kSQL, args: []int{1}},
	"(*github.com/jmoiron/sqlx.Tx).Queryx":          {kind: kSQL, args: []int{0}},
	"(*github.com/jmoiron/sqlx.Tx).Exec":            {kind: kSQL, args: []int{0}},
	"(*github.com/jmoiron/sqlx.Tx).Get":             {kind: kSQL, args: []int{1}},
	"(*github.com/jmoiron/sqlx.Tx).Select":          {kind: kSQL, args: []int{1}},
	"(*gorm.io/gorm.DB).Raw":                        {kind: kSQL, args: []int{0}},
	"(*gorm.io/gorm.DB).Exec":                       {kind: kSQL, args: []int{0}},
	"(*gorm.io/gorm.DB).Order":                      {kind: kSQL, args: []int{0}},
	"(*github.com/jackc/pgx.Conn).Query":            {kind: kSQL, args: []int{1}},
	"(*github.com/jackc/pgx.Conn).QueryRow":         {kind: kSQL, args: []int{1}},
	"(*github.com/jackc/pgx.Conn).Exec":             {kind: kSQL, args: []int{1}},
	"(*github.com/jackc/pgx/pgxpool.Pool).Query":    {kind: kSQL, args: []int{1}},
	"(*github.com/jackc/pgx/pgxpool.Pool).QueryRow": {kind: kSQL, args: []int{1}},
	"(*github.com/jackc/pgx/pgxpool.Pool).Exec":     {kind: kSQL, args: []int{1}},

	"os/exec.Command":        {kind: kCmd, args: []int{0}, shellFrom: 1},
	"os/exec.CommandContext": {kind: kCmd, args: []int{1}, shellFrom: 2},
	"syscall.Exec":           {kind: kCmd, args: []int{0}},
	"os.StartProcess":        {kind: kCmd, args: []int{0}},

	"os.Open":             {kind: kPath, args: []int{0}},
	"os.OpenFile":         {kind: kPath, args: []int{0}},
	"os.ReadFile":         {kind: kPath, args: []int{0}},
	"os.ReadDir":          {kind: kPath, args: []int{0}},
	"os.WriteFile":        {kind: kPath, args: []int{0}},
	"os.Create":           {kind: kPath, args: []int{0}},
	"os.Remove":           {kind: kPath, args: []int{0}},
	"os.RemoveAll":        {kind: kPath, args: []int{0}},
	"os.Mkdir":            {kind: kPath, args: []int{0}},
	"os.MkdirAll":         {kind: kPath, args: []int{0}},
	"os.Rename":           {kind: kPath, args: []int{0, 1}},
	"os.Truncate":         {kind: kPath, args: []int{0}},
	"io/ioutil.ReadFile":  {kind: kPath, args: []int{0}},
	"io/ioutil.WriteFile": {kind: kPath, args: []int{0}},
	"io/ioutil.ReadDir":   {kind: kPath, args: []int{0}},
	"net/http.ServeFile":  {kind: kPath, args: []int{2}},

	"net/http.Get":                   {kind: kSSRF, args: []int{0}},
	"net/http.Head":                  {kind: kSSRF, args: []int{0}},
	"net/http.Post":                  {kind: kSSRF, args: []int{0}},
	"net/http.PostForm":              {kind: kSSRF, args: []int{0}},
	"net/http.NewRequest":            {kind: kSSRF, args: []int{1}},
	"net/http.NewRequestWithContext": {kind: kSSRF, args: []int{2}},
	"(*net/http.Client).Get":         {kind: kSSRF, args: []int{0}},
	"(*net/http.Client).Head":        {kind: kSSRF, args: []int{0}},
	"(*net/http.Client).Post":        {kind: kSSRF, args: []int{0}},
	"(*net/http.Client).PostForm":    {kind: kSSRF, args: []int{0}},
	"net.Dial":                       {kind: kSSRF, args: []int{1}},
	"net.DialTimeout":                {kind: kSSRF, args: []int{1}},

	"(net/http.ResponseWriter).Write": {kind: kXSS, args: []int{0}},
	"io.WriteString":                  {kind: kXSS, args: []int{1}, writer: true},
	"fmt.Fprint":                      {kind: kXSS, args: []int{1}, rest: true, writer: true},
	"fmt.Fprintf":                     {kind: kXSS, args: []int{1}, rest: true, writer: true},
	"fmt.Fprintln":                    {kind: kXSS, args: []int{1}, rest: true, writer: true},
	"html/template.HTML":              {kind: kXSS, args: []int{0}},
	"html/template.JS":                {kind: kXSS, args: []int{0}},
	"html/template.HTMLAttr":          {kind: kXSS, args: []int{0}},
	"html/template.URL":               {kind: kXSS, args: []int{0}},

	"net/http.Redirect": {kind: kRedirect, args: []int{2}},
}

// sanitizers return their input with the listed kinds neutralized. Numeric and boolean
// results are cleared everywhere by type instead (an int cannot carry a payload).
var sanitizers = map[string]kind{
	"html.EscapeString":              kXSS,
	"html/template.HTMLEscapeString": kXSS,
	"html/template.JSEscapeString":   kXSS,
	"html/template.HTMLEscaper":      kXSS,
	"net/url.QueryEscape":            kXSS | kPath | kRedirect | kSSRF,
	"net/url.PathEscape":             kXSS | kPath | kRedirect | kSSRF,
	"path/filepath.Base":             kPath,
	"path.Base":                      kPath,

	// Parsed values are structured data, not text that can carry a payload.
	"net.ParseIP":           kAll,
	"net/netip.ParseAddr":   kAll,
	"net/netip.ParsePrefix": kAll,
	"time.Parse":            kAll,

	// A digest reveals nothing of its input that could act as a payload.
	"crypto/sha256.Sum256":     kAll,
	"crypto/sha256.Sum224":     kAll,
	"crypto/sha512.Sum512":     kAll,
	"crypto/sha512.Sum384":     kAll,
	"crypto/sha512.Sum512_224": kAll,
	"crypto/sha512.Sum512_256": kAll,
	"crypto/sha1.Sum":          kAll,
	"crypto/md5.Sum":           kAll,
}

// sourceCalls return data controlled by the caller of the program.
var sourceCalls = map[string]string{
	"(*net/http.Request).FormValue":                    "HTTP request parameter",
	"(*net/http.Request).PostFormValue":                "HTTP request parameter",
	"(*net/http.Request).Cookie":                       "HTTP cookie",
	"(*net/http.Request).UserAgent":                    "HTTP User-Agent header",
	"(*net/http.Request).Referer":                      "HTTP Referer header",
	"(*net/http.Request).PathValue":                    "HTTP path parameter",
	"(*github.com/gin-gonic/gin.Context).Query":        "HTTP request parameter",
	"(*github.com/gin-gonic/gin.Context).DefaultQuery": "HTTP request parameter",
	"(*github.com/gin-gonic/gin.Context).Param":        "HTTP path parameter",
	"(*github.com/gin-gonic/gin.Context).PostForm":     "HTTP request parameter",
	"(*github.com/gin-gonic/gin.Context).GetHeader":    "HTTP request header",
	"(*github.com/gin-gonic/gin.Context).Cookie":       "HTTP cookie",
	"(github.com/labstack/echo.Context).QueryParam":    "HTTP request parameter",
	"(github.com/labstack/echo.Context).Param":         "HTTP path parameter",
	"(github.com/labstack/echo.Context).FormValue":     "HTTP request parameter",
	"(*github.com/gofiber/fiber.Ctx).Params":           "HTTP path parameter",
	"(*github.com/gofiber/fiber.Ctx).Query":            "HTTP request parameter",
	"(*github.com/gofiber/fiber.Ctx).FormValue":        "HTTP request parameter",
	"github.com/go-chi/chi.URLParam":                   "HTTP path parameter",
	"github.com/gorilla/mux.Vars":                      "HTTP path parameter",
}

var sourceVars = map[string]string{
	"os.Args": "command-line arguments",
}

// requestFields are the fields of net/http.Request that hold attacker-controlled data.
var requestFields = map[string]string{
	"URL":           "request URL",
	"Body":          "request body",
	"Form":          "request form",
	"PostForm":      "request form",
	"Header":        "request header",
	"Host":          "request Host header",
	"RequestURI":    "request URI",
	"MultipartForm": "request form",
	"Trailer":       "request trailer",
}

// fill describes a call that writes untrusted data into one of its arguments.
type fill struct {
	to   int    // argument index that receives the data (a pointer or value to merge into)
	from int    // argument index it comes from, or fromRecv, or fromSource
	src  string // description when from == fromSource
}

const (
	fromRecv   = -1
	fromSource = -2
	toRecv     = -3
)

var fills = map[string]fill{
	"encoding/json.Unmarshal":                             {to: 1, from: 0},
	"encoding/xml.Unmarshal":                              {to: 1, from: 0},
	"(*encoding/json.Decoder).Decode":                     {to: 0, from: fromRecv},
	"(*encoding/xml.Decoder).Decode":                      {to: 0, from: fromRecv},
	"(*strings.Builder).WriteString":                      {to: toRecv, from: 0},
	"(*strings.Builder).Write":                            {to: toRecv, from: 0},
	"(*bytes.Buffer).WriteString":                         {to: toRecv, from: 0},
	"(*bytes.Buffer).Write":                               {to: toRecv, from: 0},
	"(net/url.Values).Add":                                {to: toRecv, from: 1},
	"(net/url.Values).Set":                                {to: toRecv, from: 1},
	"(*github.com/gin-gonic/gin.Context).ShouldBindJSON":  {to: 0, from: fromSource, src: "HTTP request body"},
	"(*github.com/gin-gonic/gin.Context).BindJSON":        {to: 0, from: fromSource, src: "HTTP request body"},
	"(*github.com/gin-gonic/gin.Context).ShouldBind":      {to: 0, from: fromSource, src: "HTTP request body"},
	"(*github.com/gin-gonic/gin.Context).Bind":            {to: 0, from: fromSource, src: "HTTP request body"},
	"(*github.com/gin-gonic/gin.Context).ShouldBindQuery": {to: 0, from: fromSource, src: "HTTP request parameter"},
	"(github.com/labstack/echo.Context).Bind":             {to: 0, from: fromSource, src: "HTTP request body"},
}

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "/bin/sh": true,
	"/bin/bash": true, "/usr/bin/env": true, "cmd": true, "cmd.exe": true,
	"powershell": true, "powershell.exe": true, "pwsh": true,
}

// majorVersion strips "/v2"-style module suffixes so rules match any major version.
var majorVersion = regexp.MustCompile(`/v[0-9]+([/.)])`)

func normalize(name string) string {
	return majorVersion.ReplaceAllString(name, "$1")
}

// modeledPackages are the third-party packages the rule tables mention, derived from the
// tables so the two cannot drift apart.
var modeledPackages = func() []string {
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimPrefix(name, "(")
		name = strings.TrimPrefix(name, "*")
		if i := strings.Index(name, ")"); i >= 0 {
			name = name[:i]
		}
		i := strings.LastIndex(name, ".")
		if i < 0 {
			return
		}
		if first, _, _ := strings.Cut(name, "/"); strings.Contains(first, ".") {
			seen[name[:i]] = true
		}
	}
	for n := range sinks {
		add(n)
	}
	for n := range sourceCalls {
		add(n)
	}
	for n := range fills {
		add(n)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}()
