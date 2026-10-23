package sast

import (
	"regexp"
	"strings"
)

// C# (ASP.NET Core and the .NET base library). Types are named by their simple name, as
// they usually are after a using directive; simpleTypes gives each its full name.

func csSimpleTypes() map[string]string {
	m := map[string]string{}
	add := func(ns string, names ...string) {
		for _, n := range names {
			m[n] = ns + "." + n
		}
	}
	add("System.Data.SqlClient", "SqlCommand", "SqlConnection", "SqlDataAdapter")
	add("System.Data.SQLite", "SQLiteCommand", "SQLiteDataAdapter")
	add("MySql.Data.MySqlClient", "MySqlDataAdapter")
	add("System.Data.OleDb", "OleDbDataAdapter")
	add("Microsoft.Data.SqlClient", "SqlCommand")
	add("Microsoft.Data.Sqlite", "SqliteCommand")
	add("MySql.Data.MySqlClient", "MySqlCommand")
	add("Npgsql", "NpgsqlCommand")
	add("System.Data.OleDb", "OleDbCommand")
	add("System.Data.Odbc", "OdbcCommand")
	add("System.Diagnostics", "Process", "ProcessStartInfo")
	add("System.IO", "File", "Directory", "FileStream", "StreamReader", "StreamWriter", "Path")
	add("System.Net.Http", "HttpClient", "HttpRequestMessage")
	add("System.Net", "WebClient", "WebRequest", "WebUtility")
	add("System.Runtime.Serialization.Formatters.Binary", "BinaryFormatter")
	add("System.Xml", "XmlDocument", "XmlReaderSettings")
	add("System.Security.Cryptography", "MD5", "SHA1", "DES", "TripleDES", "RC2", "MD5CryptoServiceProvider", "SHA1CryptoServiceProvider", "SHA1Managed", "DESCryptoServiceProvider")
	add("System.Text.RegularExpressions", "Regex")
	add("System", "Random", "Activator", "Type", "Convert", "Uri")
	add("System.Web", "HttpUtility")
	add("System.DirectoryServices", "DirectorySearcher")
	return m
}

var csSpec = &langSpec{
	name: "cs",
	sinks: map[string]sink{
		"System.Data.SqlClient.SqlCommand":        {kind: kSQL, args: []int{0}},
		"Microsoft.Data.SqlClient.SqlCommand":     {kind: kSQL, args: []int{0}},
		"System.Data.SqlClient.SqlDataAdapter":    {kind: kSQL, args: []int{0}},
		"System.Data.SQLite.SQLiteCommand":        {kind: kSQL, args: []int{0}},
		"System.Data.SQLite.SQLiteDataAdapter":    {kind: kSQL, args: []int{0}},
		"MySql.Data.MySqlClient.MySqlDataAdapter": {kind: kSQL, args: []int{0}},
		"System.Data.OleDb.OleDbDataAdapter":      {kind: kSQL, args: []int{0}},
		"Microsoft.Data.Sqlite.SqliteCommand":     {kind: kSQL, args: []int{0}},
		"MySql.Data.MySqlClient.MySqlCommand":     {kind: kSQL, args: []int{0}},
		"Npgsql.NpgsqlCommand":                    {kind: kSQL, args: []int{0}},
		"System.Data.OleDb.OleDbCommand":          {kind: kSQL, args: []int{0}},
		"System.Data.Odbc.OdbcCommand":            {kind: kSQL, args: []int{0}},
		"?.FromSqlRaw":                            {kind: kSQL, args: []int{0}},
		"?.ExecuteSqlRaw":                         {kind: kSQL, args: []int{0}},
		"?.ExecuteSqlRawAsync":                    {kind: kSQL, args: []int{0}},
		"?.SqlQuery":                              {kind: kSQL, args: []int{0}},
		"?.SqlQueryRaw":                           {kind: kSQL, args: []int{0}},
		"?.ExecuteSqlCommand":                     {kind: kSQL, args: []int{0}},
		"?.Query":                                 {kind: kSQL, args: []int{0}, recv: []string{"connection", "conn", "db", "_conn", "_db", "_connection", "dbConnection"}},
		"?.QueryAsync":                            {kind: kSQL, args: []int{0}, recv: []string{"connection", "conn", "db", "_conn", "_db", "_connection", "dbConnection"}},
		"?.Execute":                               {kind: kSQL, args: []int{0}, recv: []string{"connection", "conn", "db", "_conn", "_db", "_connection", "dbConnection"}},
		"?.ExecuteAsync":                          {kind: kSQL, args: []int{0}, recv: []string{"connection", "conn", "db", "_conn", "_db", "_connection", "dbConnection"}},

		"System.Diagnostics.Process.Start":    {kind: kCmd, args: []int{0, 1}},
		"System.Diagnostics.ProcessStartInfo": {kind: kCmd, args: []int{0, 1}},

		"System.IO.File.ReadAllText": {kind: kPath, args: []int{0}}, "System.IO.File.ReadAllBytes": {kind: kPath, args: []int{0}},
		"System.IO.File.ReadAllLines": {kind: kPath, args: []int{0}}, "System.IO.File.WriteAllText": {kind: kPath, args: []int{0}},
		"System.IO.File.WriteAllBytes": {kind: kPath, args: []int{0}}, "System.IO.File.AppendAllText": {kind: kPath, args: []int{0}},
		"System.IO.File.Delete": {kind: kPath, args: []int{0}}, "System.IO.File.Open": {kind: kPath, args: []int{0}},
		"System.IO.File.OpenRead": {kind: kPath, args: []int{0}}, "System.IO.File.OpenWrite": {kind: kPath, args: []int{0}},
		"System.IO.File.Create": {kind: kPath, args: []int{0}}, "System.IO.File.Copy": {kind: kPath, args: []int{0, 1}},
		"System.IO.File.Move": {kind: kPath, args: []int{0, 1}}, "System.IO.File.Exists": {kind: kPath, args: []int{0}},
		"System.IO.Directory.Delete": {kind: kPath, args: []int{0}}, "System.IO.Directory.GetFiles": {kind: kPath, args: []int{0}},
		"System.IO.Directory.CreateDirectory": {kind: kPath, args: []int{0}},
		"System.IO.FileStream":                {kind: kPath, args: []int{0}}, "System.IO.StreamReader": {kind: kPath, args: []int{0}},
		"System.IO.StreamWriter": {kind: kPath, args: []int{0}},
		"?.PhysicalFile":         {kind: kPath, args: []int{0}},

		"?.GetAsync": {kind: kSSRF, args: []int{0}}, "?.GetStringAsync": {kind: kSSRF, args: []int{0}},
		"?.GetStreamAsync": {kind: kSSRF, args: []int{0}}, "?.GetByteArrayAsync": {kind: kSSRF, args: []int{0}},
		"?.PostAsync": {kind: kSSRF, args: []int{0}}, "?.PutAsync": {kind: kSSRF, args: []int{0}}, "?.DeleteAsync": {kind: kSSRF, args: []int{0}},
		"?.DownloadString": {kind: kSSRF, args: []int{0}}, "?.DownloadStringAsync": {kind: kSSRF, args: []int{0}},
		"?.DownloadFile": {kind: kSSRF, args: []int{0}}, "?.DownloadData": {kind: kSSRF, args: []int{0}},
		"System.Net.WebRequest.Create":       {kind: kSSRF, args: []int{0}},
		"System.Net.Http.HttpRequestMessage": {kind: kSSRF, args: []int{1}},

		"?.WriteAsync":                         {kind: kXSS, args: []int{0}, recv: []string{"Response", "response", "context"}},
		"Microsoft.AspNetCore.Html.HtmlString": {kind: kXSS, args: []int{0}},
		"HtmlString":                           {kind: kXSS, args: []int{0}},
		"?.Raw":                                {kind: kXSS, args: []int{0}, recv: []string{"Html"}},

		"Redirect": {kind: kRedirect, args: []int{0}}, "RedirectPermanent": {kind: kRedirect, args: []int{0}},
		"?.Redirect":     {kind: kRedirect, args: []int{0}, recv: []string{"Response", "response"}},
		"RedirectResult": {kind: kRedirect, args: []int{0}},

		"System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize": {kind: kDeser, args: []int{0}},
		"?.DeserializeObject": {kind: kDeser, args: []int{0}, recv: []string{"TypedJson"}},

		"System.Type.GetType":                        {kind: kCode, args: []int{0}},
		"System.Activator.CreateInstance":            {kind: kCode, args: []int{0}},
		"?.EvaluateAsync":                            {kind: kCode, args: []int{0}, recv: []string{"CSharpScript"}},
		"System.Text.RegularExpressions.Regex":       {kind: kRegex, args: []int{0}},
		"System.DirectoryServices.DirectorySearcher": {kind: kLDAP, args: []int{0}},
		"?.SelectNodes":                              {kind: kXPath, args: []int{0}}, "?.SelectSingleNode": {kind: kXPath, args: []int{0}},
		"?.LogInformation": {kind: kLog, args: []int{0}, rest: true, recv: []string{"logger", "_logger", "log", "_log"}},
		"?.LogWarning":     {kind: kLog, args: []int{0}, rest: true, recv: []string{"logger", "_logger", "log", "_log"}},
		"?.LogError":       {kind: kLog, args: []int{0}, rest: true, recv: []string{"logger", "_logger", "log", "_log"}},
		"?.LogDebug":       {kind: kLog, args: []int{0}, rest: true, recv: []string{"logger", "_logger", "log", "_log"}},
	},
	sanitizers: map[string]kind{
		"System.Convert.ToInt32": kAll, "System.Convert.ToInt64": kAll, "System.Convert.ToDouble": kAll, "System.Convert.ToBoolean": kAll,
		"int.Parse": kAll, "int.TryParse": kAll, "long.Parse": kAll, "Guid.Parse": kAll, "System.Guid.Parse": kAll, "bool.Parse": kAll,
		"System.Net.WebUtility.HtmlEncode": kXSS, "System.Web.HttpUtility.HtmlEncode": kXSS, "?.Encode": kXSS,
		"System.Net.WebUtility.UrlEncode": kXSS | kPath | kRedirect | kSSRF, "System.Uri.EscapeDataString": kXSS | kPath | kRedirect | kSSRF,
		"System.IO.Path.GetFileName": kPath, "System.Text.RegularExpressions.Regex.Escape": kRegex,
		"LocalRedirect": kRedirect,
	},
	sourceRoots: map[string]map[string]string{
		"Request": {"Query": "request query", "Form": "request body", "Headers": "request header", "Cookies": "request cookie",
			"Path": "request path", "QueryString": "request query", "Body": "request body", "RouteValues": "request path parameter",
			"Host": "request host", "PathBase": "request path", "ContentType": "request header"},
		"HttpContext": {"Request": "request data"},
		"context":     {"Request": "request data"},
	},
	sourceMethods: map[string]string{"ReadAsStringAsync": "request body", "ReadToEndAsync": "request body", "ReadFormAsync": "request body"},
	self:          map[string]bool{"this": true},
	shells:        map[string]bool{"sh": true, "bash": true, "cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true},
	mutators:      map[string]bool{"Add": true, "Append": true, "Insert": true, "AddRange": true, "Push": true, "Enqueue": true},
	weakRNG:       map[string]bool{"System.Random": true},
	assignSinks:   map[string]kind{"CommandText": kSQL, "Arguments": kCmd, "FileName": kCmd, "Filter": kLDAP},
	builtins:      map[string]bool{"Redirect": true, "RedirectPermanent": true, "HtmlString": true, "RedirectResult": true, "LocalRedirect": true, "string": true, "int": true},
	simpleTypes:   csSimpleTypes(),
	pkgRoots:      map[string]bool{"System": true, "Microsoft": true},
}

func init() {
	frontends["cs"] = &frontend{spec: csSpec, lower: lowerCSharp}
	ensureSets(csSpec)
	for _, h := range []string{"MD5", "SHA1", "MD5CryptoServiceProvider", "SHA1CryptoServiceProvider", "SHA1Managed"} {
		csSpec.misuse["System.Security.Cryptography."+h+".Create"] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
		csSpec.misuse["System.Security.Cryptography."+h] = []misuse{bare(ruleWeakCrypto, h+" is broken for collision resistance")}
	}
	for _, c := range []string{"DES", "TripleDES", "RC2", "DESCryptoServiceProvider"} {
		csSpec.misuse["System.Security.Cryptography."+c+".Create"] = []misuse{bare(ruleCipherMisuse, c+" is a weak cipher")}
		csSpec.misuse["System.Security.Cryptography."+c] = []misuse{bare(ruleCipherMisuse, c+" is a weak cipher")}
	}
	csSpec.sourceVarMembers = map[string]*regexp.Regexp{}
	webField := regexp.MustCompile(`^(txt|tb|ddl|hdn|hid|lst|cbo|chk|rb|rdo|ctl|input|field)[A-Z_0-9]`)
	for _, m := range []string{"Text", "Value", "SelectedValue", "SelectedItem"} {
		csSpec.sourceVarMembers[m] = webField
	}
	csSpec.sourceRoots["Request"]["Params"] = "request parameter"
	csSpec.sourceRoots["Request"]["ServerVariables"] = "request header"
	csSpec.sourceRoots["Request"]["RawUrl"] = "request URL"
	csSpec.sinks["?.Write"] = sink{kind: kXSS, args: []int{0}, recv: []string{"Response"}}
	csSpec.sinks["?.MapPath"] = sink{kind: kPath, args: []int{0}, recv: []string{"Server"}}
	csSpec.sinks["?.Transfer"] = sink{kind: kRedirect, args: []int{0}, recv: []string{"Server"}}
	csSpec.assignMisuse["Mode"] = assignMisuse{rule: ruleCipherMisuse, detail: "ECB leaks patterns in the plaintext", vals: []string{"ecb"}}
	csSpec.assignMisuse["DtdProcessing"] = assignMisuse{rule: ruleXXE, detail: "DTD processing is enabled", vals: []string{"parse"}}
	csSpec.assignMisuse["HttpOnly"] = assignMisuse{rule: ruleCookie, detail: "HttpOnly is false", vals: []string{"=false"}}
	csSpec.assignMisuse["Secure"] = assignMisuse{rule: ruleCookie, detail: "Secure is false", vals: []string{"=false"}}
	csSpec.assignMisuse["RequireHttpsMetadata"] = assignMisuse{rule: ruleTLS, detail: "RequireHttpsMetadata is false", vals: []string{"=false"}}
	csSpec.assignMisuse["ValidateIssuerSigningKey"] = assignMisuse{rule: ruleJWT, detail: "the signing key is not validated", vals: []string{"=false"}}
	csSpec.assignMisuse["ValidateLifetime"] = assignMisuse{rule: ruleJWT, detail: "token lifetime is not validated", vals: []string{"=false"}}
	csSpec.assignMisuse["RequireSignedTokens"] = assignMisuse{rule: ruleJWT, detail: "unsigned tokens are accepted", vals: []string{"=false"}}
	csSpec.builtins["Redirect"] = true
	// ASP.NET Core configuration.
	csSpec.misuse["?.AllowCredentials"] = []misuse{
		{rule: ruleCORS, detail: "AllowAnyOrigin().AllowCredentials() lets any website send credentialed requests", recvCall: "AllowAnyOrigin"},
		{rule: ruleCORS, detail: "SetIsOriginAllowed(_ => true) accepts every origin together with credentials", recvCall: "SetIsOriginAllowed"},
	}
	csSpec.misuse["?.AllowAnyOrigin"] = []misuse{{rule: ruleCORS, detail: "AllowAnyOrigin after AllowCredentials accepts every origin with credentials", recvCall: "AllowCredentials"}}
	csSpec.assignMisuse["SecurePolicy"] = assignMisuse{rule: ruleCookie, detail: "the cookie may be sent over plain HTTP", vals: []string{"none"}}
	csSpec.assignMisuse["SameSite"] = assignMisuse{rule: ruleCookie, detail: "SameSite=None sends the cookie on cross-site requests", vals: []string{"none"}}
	csSpec.assignMisuse["ValidateAudience"] = assignMisuse{rule: ruleJWT, detail: "the token audience is not validated", vals: []string{"=false"}}
	csSpec.assignMisuse["ValidateIssuer"] = assignMisuse{rule: ruleJWT, detail: "the token issuer is not validated", vals: []string{"=false"}}
	for _, cb := range []string{"ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback", "RemoteCertificateValidationCallback"} {
		csSpec.assignMisuse[cb] = assignMisuse{rule: ruleTLS, detail: "the certificate check always succeeds", vals: []string{"lambda:true", "dangerousacceptany"}}
	}
	csSpec.misuse["?.UseDeveloperExceptionPage"] = []misuse{bare(ruleDebug, "the developer exception page shows stack traces and source to anyone")}
	csSpec.misuse["?.UseDatabaseErrorPage"] = []misuse{bare(ruleDebug, "the database error page shows queries and schema to anyone")}
	csSpec.misuse["csrfUnprotected"] = []misuse{bare(ruleCSRF, "this action changes state without [ValidateAntiForgeryToken]")}
	csSpec.builtins["csrfUnprotected"] = true
	csSpec.misuse["weakAllowlist"] = []misuse{bare(ruleWeakAllowlist, "the URL is accepted when it merely contains or starts with an allowed one")}
	csSpec.builtins["weakAllowlist"] = true
	addBuiltins()
}

type csLower struct {
	*lowering
	class string
	// mvc is set inside a Controller (not ControllerBase or an [ApiController]) whose class
	// has no antiforgery attribute, where a state-changing action needs its own.
	mvc bool
}

var csUnsafeVerbs = map[string]bool{"HttpPost": true, "HttpPut": true, "HttpDelete": true, "HttpPatch": true}

// missingAntiforgery reports an MVC action that changes state without an antiforgery check.
func (c *csLower) missingAntiforgery(m *node) bool {
	if !c.mvc {
		return false
	}
	verb, token := false, false
	for _, al := range c.named(m) {
		if c.kind(al) != "attribute_list" {
			continue
		}
		for _, a := range c.named(al) {
			name := c.text(c.field(a, "name"))
			if csUnsafeVerbs[name] {
				verb = true
			}
			if strings.Contains(name, "AntiForgery") || strings.Contains(name, "Antiforgery") {
				token = true
			}
		}
	}
	return verb && !token
}

var reGlobalAntiforgery = regexp.MustCompile(`Filters\s*\.\s*Add\s*\(\s*new\s+(?:Auto)?ValidateAntiforgeryToken(?:Attribute)?\s*\(|AutoValidateAntiforgeryTokenAttribute`)

func lowerCSharp(l *lowering) *module {
	c := &csLower{lowering: l}
	l.mod.globalCSRF = reGlobalAntiforgery.Match(l.src)
	c.members(l.named(l.root))
	return l.mod
}

// members walks namespaces and type declarations down to the methods.
func (c *csLower) members(ns []*node) {
	for _, n := range ns {
		switch c.kind(n) {
		case "namespace_declaration", "file_scoped_namespace_declaration":
			c.members(c.named(c.field(n, "body")))
			c.members(c.namedAfter(n))
		case "declaration_list":
			c.members(c.named(n))
		case "using_directive":
			c.usingDirective(n)
		case "class_declaration", "struct_declaration", "record_declaration", "interface_declaration":
			c.classDecl(n)
		case "global_statement":
			c.mod.top = append(c.mod.top, c.stmts(c.named(n))...)
		}
	}
}

// namedAfter returns the named children that follow the name of a file-scoped namespace.
func (c *csLower) namedAfter(n *node) []*node {
	var out []*node
	seen := false
	for _, ch := range c.named(n) {
		if seen {
			out = append(out, ch)
		}
		if ch == c.field(n, "name") {
			seen = true
		}
	}
	return out
}

func (c *csLower) usingDirective(n *node) {
	name := strings.TrimSpace(c.text(n))
	name = strings.TrimSuffix(strings.TrimPrefix(name, "using"), ";")
	if i := strings.Index(name, "="); i > 0 {
		alias := strings.TrimSpace(name[:i])
		c.mod.imports[alias] = strings.TrimSpace(name[i+1:])
	}
}

func (c *csLower) classDecl(n *node) {
	name := c.text(c.field(n, "name"))
	prev, prevMVC := c.class, c.mvc
	c.class = name
	defer func() { c.class, c.mvc = prev, prevMVC }()
	controller := false
	c.mvc = false
	classToken, apiController := false, false
	for _, al := range c.named(n) {
		if c.kind(al) == "attribute_list" {
			for _, a := range c.named(al) {
				t := c.text(c.field(a, "name"))
				if strings.Contains(t, "AntiForgery") || strings.Contains(t, "Antiforgery") {
					classToken = true
				}
				if t == "ApiController" {
					apiController = true
				}
			}
		}
	}
	for _, ch := range c.named(n) {
		if c.kind(ch) == "base_list" {
			for _, b := range c.named(ch) {
				t := c.text(b)
				c.mod.supers[name] = append(c.mod.supers[name], t)
				if strings.HasSuffix(t, "Controller") || strings.HasSuffix(t, "ControllerBase") || strings.HasSuffix(t, "PageModel") {
					controller = true
				}
			}
		}
	}
	for _, ch := range c.named(n) {
		if c.kind(ch) == "base_list" {
			for _, b := range c.named(ch) {
				if c.text(b) == "Controller" {
					c.mvc = !classToken && !apiController
				}
			}
		}
	}
	for _, m := range c.named(c.field(n, "body")) {
		switch c.kind(m) {
		case "field_declaration", "property_declaration":
			c.fieldDecl(name, m)
		case "method_declaration", "constructor_declaration", "local_function_statement":
			c.method(m, name, controller)
		case "class_declaration", "struct_declaration", "record_declaration":
			c.classDecl(m)
		}
	}
}

func (c *csLower) fieldDecl(class string, m *node) {
	var ty, name string
	if vd := c.firstOfKind(m, "variable_declaration"); vd != nil {
		ty = c.typeName(c.field(vd, "type"))
		if d := c.firstOfKind(vd, "variable_declarator"); d != nil {
			name = c.text(c.field(d, "name"))
		}
	} else {
		ty = c.typeName(c.field(m, "type"))
		name = c.text(c.field(m, "name"))
	}
	if ty == "" || name == "" {
		return
	}
	if c.mod.fields[class] == nil {
		c.mod.fields[class] = map[string]string{}
	}
	c.mod.fields[class][name] = ty
	// const string K = "..." and static readonly string K = "...": a constant other code reads.
	if d := c.firstOfKind(c.firstOfKind(m, "variable_declaration"), "variable_declarator"); d != nil {
		mods := ""
		for _, ch := range c.named(m) {
			if c.kind(ch) == "modifier" {
				mods += " " + c.text(ch)
			}
		}
		if v := c.firstOfKind(d, "string_literal"); v != nil && (strings.Contains(mods, "const") || strings.Contains(mods, "readonly")) {
			id := c.mk(exprName, d)
			id.name = name
			c.mod.top = append(c.mod.top, &stmt{kind: stmtAssign, pos: c.pos(d), lhs: []*expr{id}, rhs: c.expr(v)})
		}
	}
}

func (c *csLower) firstOfKind(n *node, kind string) *node {
	for _, ch := range c.named(n) {
		if c.kind(ch) == kind {
			return ch
		}
	}
	return nil
}

func (c *csLower) typeName(n *node) string {
	if n == nil {
		return ""
	}
	s := c.text(n)
	if i := strings.IndexAny(s, "<[?"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

var csRequestAttrs = map[string]string{
	"FromQuery": "request query", "FromBody": "request body", "FromForm": "request body", "FromRoute": "request path parameter",
	"FromHeader": "request header", "FromServices": "",
}

func (c *csLower) method(m *node, class string, controller bool) {
	f := &funcIR{name: c.text(c.field(m, "name")), class: class, pos: c.pos(m)}
	if c.kind(m) == "constructor_declaration" {
		f.name = "<init>"
	}
	action := false
	for _, al := range c.named(m) {
		if c.kind(al) == "attribute_list" {
			for _, a := range c.named(al) {
				if strings.HasPrefix(c.text(c.field(a, "name")), "Http") || c.text(c.field(a, "name")) == "Route" {
					action = true
				}
			}
		}
	}
	if ps := c.field(m, "parameters"); ps != nil {
		for _, p := range c.named(ps) {
			if c.kind(p) != "parameter" {
				continue
			}
			pr := param{name: c.text(c.field(p, "name")), ty: c.typeName(c.field(p, "type"))}
			for _, al := range c.named(p) {
				if c.kind(al) == "attribute_list" {
					for _, a := range c.named(al) {
						if d, ok := csRequestAttrs[c.text(c.field(a, "name"))]; ok && d != "" {
							pr.source = d
						}
					}
				}
			}
			if pr.source == "" && controller && action && !isNumericType(csPrimitive(pr.ty)) && pr.ty != "CancellationToken" {
				pr.source = "request parameter"
			}
			f.params = append(f.params, pr)
		}
	}
	body := c.field(m, "body")
	if body == nil {
		ab := c.firstOfKind(m, "arrow_expression_clause")
		if ab == nil {
			return // an interface or abstract method has nothing to analyze
		}
		if cs := c.named(ab); len(cs) > 0 {
			f.body = []*stmt{{kind: stmtReturn, pos: c.pos(ab), rhs: c.expr(cs[0])}}
		}
	} else {
		f.body = c.block(body)
	}
	if c.missingAntiforgery(m) {
		f.body = append([]*stmt{synthCall(c.lowering, m, "csrfUnprotected")}, f.body...)
	}
	c.mod.funcs = append(c.mod.funcs, f)
}

func csPrimitive(t string) string {
	switch t {
	case "int", "long", "short", "byte", "uint", "ulong", "double", "float", "decimal", "bool", "Guid", "DateTime":
		return t
	}
	return t
}

func (c *csLower) block(n *node) []*stmt {
	if n == nil {
		return nil
	}
	if c.kind(n) == "block" {
		return c.stmts(c.named(n))
	}
	return c.stmt(n)
}

func (c *csLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, c.stmt(n)...)
	}
	return out
}

func (c *csLower) declarators(n *node) []*stmt {
	var out []*stmt
	vd := n
	if c.kind(n) == "local_declaration_statement" {
		vd = c.firstOfKind(n, "variable_declaration")
	}
	if vd == nil {
		return nil
	}
	ty := c.typeName(c.field(vd, "type"))
	for _, d := range c.named(vd) {
		if c.kind(d) != "variable_declarator" {
			continue
		}
		name := c.mk(exprName, d)
		name.name = c.text(c.field(d, "name"))
		if ty != "var" && c.kind(c.field(vd, "type")) != "implicit_type" {
			name.ty = ty
		}
		var val *node
		for _, ch := range c.named(d) {
			if ch != c.field(d, "name") {
				val = ch
			}
		}
		if val == nil {
			if name.ty != "" {
				out = append(out, &stmt{kind: stmtAssign, pos: c.pos(d), lhs: []*expr{name}})
			}
			continue
		}
		out = append(out, &stmt{kind: stmtAssign, pos: c.pos(d), lhs: []*expr{name}, rhs: c.expr(val)})
	}
	return out
}

func (c *csLower) stmt(n *node) []*stmt {
	switch k := c.kind(n); k {
	case "expression_statement":
		var out []*stmt
		for _, e := range c.named(n) {
			if c.kind(e) == "assignment_expression" {
				out = append(out, c.assignment(e))
			} else {
				out = append(out, &stmt{kind: stmtExpr, pos: c.pos(e), rhs: c.expr(e)})
			}
		}
		return out
	case "local_declaration_statement":
		return c.declarators(n)
	case "return_statement":
		s := &stmt{kind: stmtReturn, pos: c.pos(n)}
		if cs := c.named(n); len(cs) > 0 {
			s.rhs = c.expr(cs[0])
		}
		return []*stmt{s}
	case "throw_statement":
		return []*stmt{{kind: stmtJump, pos: c.pos(n)}}
	case "break_statement", "continue_statement":
		return []*stmt{{kind: stmtJump, pos: c.pos(n), loop: true}}
	case "if_statement":
		s := &stmt{kind: stmtIf, pos: c.pos(n), cond: c.expr(c.field(n, "condition")), then: c.block(c.field(n, "consequence"))}
		if alt := c.field(n, "alternative"); alt != nil {
			s.els = c.block(alt)
		}
		return []*stmt{s}
	case "foreach_statement":
		name := c.mk(exprName, n)
		name.name = c.text(c.field(n, "left"))
		if t := c.field(n, "type"); t != nil && c.kind(t) != "implicit_type" {
			name.ty = c.typeName(t)
		}
		return []*stmt{{kind: stmtLoop, pos: c.pos(n), lhs: []*expr{name}, rhs: c.expr(c.field(n, "right")), then: c.block(c.field(n, "body"))}}
	case "for_statement":
		var out []*stmt
		if init := c.field(n, "initializer"); init != nil && c.kind(init) == "variable_declaration" {
			out = append(out, c.declarators(init)...)
		}
		return append(out, &stmt{kind: stmtBranch, pos: c.pos(n), arms: [][]*stmt{c.block(c.field(n, "body"))}})
	case "while_statement", "do_statement":
		return []*stmt{{kind: stmtBranch, pos: c.pos(n), arms: [][]*stmt{c.block(c.field(n, "body"))}}}
	case "block", "checked_statement", "unsafe_statement", "lock_statement", "labeled_statement":
		var inner []*stmt
		for _, ch := range c.named(n) {
			inner = append(inner, c.stmt(ch)...)
		}
		return []*stmt{{kind: stmtBranch, pos: c.pos(n), arms: [][]*stmt{inner}}}
	case "using_statement":
		var pre []*stmt
		for _, ch := range c.named(n) {
			if c.kind(ch) == "variable_declaration" {
				pre = append(pre, c.declarators(ch)...)
			}
		}
		return append(pre, &stmt{kind: stmtBranch, pos: c.pos(n), arms: [][]*stmt{c.block(c.field(n, "body"))}})
	case "try_statement":
		s := &stmt{kind: stmtBranch, pos: c.pos(n)}
		s.arms = append(s.arms, c.block(c.field(n, "body")))
		for _, ch := range c.named(n) {
			switch c.kind(ch) {
			case "catch_clause":
				s.arms = append(s.arms, c.block(c.field(ch, "body")))
			case "finally_clause":
				for _, cc := range c.named(ch) {
					s.arms = append(s.arms, c.block(cc))
				}
			}
		}
		return []*stmt{s}
	case "switch_statement":
		s := &stmt{kind: stmtBranch, pos: c.pos(n)}
		for _, sec := range c.named(c.field(n, "body")) {
			var arm []*stmt
			for _, ch := range c.named(sec) {
				if !strings.HasSuffix(c.kind(ch), "_pattern") && c.kind(ch) != "constant_pattern" {
					arm = append(arm, c.stmt(ch)...)
				}
			}
			s.arms = append(s.arms, arm)
		}
		return []*stmt{s}
	case "local_function_statement":
		c.method(n, c.class, false)
	}
	return nil
}

func (c *csLower) assignment(n *node) *stmt {
	s := &stmt{kind: stmtAssign, pos: c.pos(n), rhs: c.expr(c.field(n, "right"))}
	s.lhs = []*expr{c.expr(c.field(n, "left"))}
	if l, r := c.field(n, "left"), c.field(n, "right"); l != nil && r != nil {
		s.aug = strings.TrimSpace(string(c.src[l.EndByte():r.StartByte()])) != "="
	}
	return s
}

func (c *csLower) args(n *node, into *expr) {
	for _, a := range c.named(n) {
		x := a
		if c.kind(a) == "argument" {
			cs := c.named(a)
			if len(cs) == 0 {
				continue
			}
			x = cs[len(cs)-1]
		}
		into.args = append(into.args, c.expr(x))
		into.kw = append(into.kw, "")
	}
}

func (c *csLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := c.kind(n); k {
	case "identifier", "this_expression", "base_expression", "predefined_type":
		e := c.mk(exprName, n)
		e.name = c.text(n)
		if k == "this_expression" {
			e.name = "this"
		}
		return e
	case "member_access_expression", "conditional_access_expression":
		if k == "conditional_access_expression" {
			// Request.Cookies?["k"] and obj?.Name
			cs := c.named(n)
			if len(cs) >= 2 {
				if eb := cs[1]; c.kind(eb) == "element_binding_expression" {
					m := c.mk(exprIndex, n)
					m.x = c.expr(cs[0])
					for _, a := range c.named(eb) {
						m.args = append(m.args, c.expr(c.lastNamed(a)))
					}
					return c.constKeyAsMember(m)
				}
				if mb := cs[1]; c.kind(mb) == "member_binding_expression" {
					m := c.mk(exprMember, n)
					m.x, m.name = c.expr(cs[0]), strings.TrimPrefix(c.text(mb), ".")
					return m
				}
				return c.other(n, c.expr(cs[0]), c.expr(cs[1]))
			}
		}
		e := c.mk(exprMember, n)
		e.x = c.expr(c.field(n, "expression"))
		e.name = c.text(c.field(n, "name"))
		return e
	case "element_access_expression":
		e := c.mk(exprIndex, n)
		e.x = c.expr(c.field(n, "expression"))
		if sub := c.field(n, "subscript"); sub != nil {
			for _, a := range c.named(sub) {
				e.args = append(e.args, c.expr(c.lastNamed(a)))
			}
		}
		return c.constKeyAsMember(e)
	case "invocation_expression":
		return c.invoke(n)
	case "object_creation_expression":
		e := c.mk(exprNew, n)
		t := c.mk(exprName, n)
		t.name = c.typeName(c.field(n, "type"))
		e.x = t
		if as := c.field(n, "arguments"); as != nil {
			c.args(as, e)
		}
		if init := c.field(n, "initializer"); init != nil {
			// new Foo { Name = a }: the initializer's values flow into the object.
			for _, a := range c.named(init) {
				if c.kind(a) == "assignment_expression" {
					e.args = append(e.args, c.expr(c.field(a, "right")))
					e.kw = append(e.kw, "")
				}
			}
		}
		return e
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		e := c.mk(exprStr, n)
		var b strings.Builder
		for _, ch := range c.named(n) {
			if strings.HasSuffix(c.kind(ch), "_content") {
				b.WriteString(c.text(ch))
			}
		}
		e.str = b.String()
		if k == "verbatim_string_literal" {
			e.str = strings.Trim(strings.TrimPrefix(c.text(n), "@"), `"`)
		}
		return e
	case "interpolated_string_expression", "interpolated_verbatim_string_expression":
		e := c.mk(exprConcat, n)
		hasSub := false
		for _, ch := range c.named(n) {
			if c.kind(ch) == "interpolation" {
				hasSub = true
				for _, x := range c.named(ch) {
					if c.kind(x) != "interpolation_brace" && c.kind(x) != "interpolation_alignment_clause" && c.kind(x) != "interpolation_format_clause" {
						e.args = append(e.args, c.expr(x))
					}
				}
			}
		}
		if !hasSub {
			s := c.mk(exprStr, n)
			return s
		}
		return e
	case "integer_literal", "real_literal", "boolean_literal", "null_literal", "character_literal":
		e := c.mk(exprNum, n)
		e.str = c.text(n)
		return e
	case "binary_expression":
		l, r := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
		lft, rgt := c.field(n, "left"), c.field(n, "right")
		op := ""
		if lft != nil && rgt != nil {
			op = strings.TrimSpace(string(c.src[lft.EndByte():rgt.StartByte()]))
		}
		switch op {
		case "+":
			e := c.mk(exprConcat, n)
			e.args = []*expr{l, r}
			return e
		case "&&":
			e := c.mk(exprAnd, n)
			e.args = []*expr{l, r}
			return e
		case "||", "??":
			e := c.mk(exprOr, n)
			e.args = []*expr{l, r}
			return e
		case "==", "!=", "<", ">", "<=", ">=":
			return c.bin(n, op, l, r)
		case "-", "*", "/", "%":
			return c.bin(n, op, l, r)
		}
		return c.other(n, l, r)
	case "prefix_unary_expression":
		cs := c.named(n)
		if strings.HasPrefix(strings.TrimSpace(c.text(n)), "!") && len(cs) > 0 {
			e := c.mk(exprNot, n)
			e.x = c.expr(cs[0])
			return e
		}
		if len(cs) > 0 {
			return c.other(n, c.expr(cs[0]))
		}
	case "parenthesized_expression", "await_expression", "cast_expression", "checked_expression", "postfix_unary_expression", "suppress_nullable_warning_expression":
		cs := c.named(n)
		if k == "cast_expression" {
			if v := c.field(n, "value"); v != nil {
				if t := c.text(c.field(n, "type")); isNumericType(csPrimitive(t)) {
					return c.mk(exprNum, n)
				}
				return c.expr(v)
			}
		}
		if len(cs) > 0 {
			return c.expr(cs[len(cs)-1])
		}
	case "conditional_expression":
		return c.cond(n, c.expr(c.field(n, "condition")), c.expr(c.field(n, "consequence")), c.expr(c.field(n, "alternative")))
	case "assignment_expression":
		return c.expr(c.field(n, "right"))
	case "lambda_expression", "anonymous_method_expression":
		e := c.mk(exprLambda, n)
		f := &funcIR{pos: c.pos(n)}
		if ps := c.field(n, "parameters"); ps != nil {
			for _, p := range c.named(ps) {
				f.params = append(f.params, param{name: c.text(c.field(p, "name"))})
				if c.kind(p) == "identifier" {
					f.params[len(f.params)-1].name = c.text(p)
				}
			}
		}
		if b := c.field(n, "body"); b != nil {
			if c.kind(b) == "block" {
				f.body = c.block(b)
			} else {
				f.body = []*stmt{{kind: stmtReturn, pos: c.pos(b), rhs: c.expr(b)}}
			}
		}
		e.fn = f
		return e
	}
	e := c.mk(exprOther, n)
	for _, ch := range c.named(n) {
		if x := c.expr(ch); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

func (c *csLower) lastNamed(n *node) *node {
	cs := c.named(n)
	if len(cs) == 0 {
		return n
	}
	return cs[len(cs)-1]
}

// constKeyAsMember reads Request.Query["id"] as the member Query.id.
func (c *csLower) constKeyAsMember(e *expr) *expr {
	if len(e.args) == 1 && e.args[0].kind == exprStr {
		m := &expr{kind: exprMember, pos: e.pos, x: e.x, name: e.args[0].str}
		return m
	}
	return e
}

func (c *csLower) invoke(n *node) *expr {
	fn := c.field(n, "function")
	e := c.mk(exprCall, n)
	e.x = c.expr(fn)
	if e.x == nil {
		e.x = c.mk(exprOther, n)
	}
	if as := c.field(n, "arguments"); as != nil {
		c.args(as, e)
	}
	// allowed.Contains(x) and Url.IsLocalUrl(x): membership and validation checks.
	if e.x.kind == exprMember {
		switch e.x.name {
		case "Contains", "StartsWith":
			if len(e.args) == 1 {
				in := c.mk(exprIn, n)
				if e.x.name == "StartsWith" {
					in.x, in.args = e.args[0], []*expr{e.x.x}
				} else {
					in.x, in.args = e.x.x, []*expr{e.args[0]}
				}
				if as := c.named(c.field(n, "arguments")); len(as) == 1 {
					return withWeakAllow(in, c.weakAllow(c.pos(n), c.text(fn), c.text(as[0])))
				}
				return in
			}
		case "IsLocalUrl":
			if len(e.args) == 1 {
				return guardOf(c.pos(n), e.args[0])
			}
		case "Format", "Concat", "Join":
			if e.x.x != nil && e.x.x.kind == exprName && (e.x.x.name == "string" || e.x.x.name == "String") {
				cc := c.mk(exprConcat, n)
				cc.args = e.args
				return cc
			}
		}
	}
	return e
}
