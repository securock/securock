package dashboard

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/lifecycle"
	"github.com/securock/securock/internal/runrecord"
	"html/template"
	"io"
	"slices"
	"strings"
)

//go:embed page.html
var page string

//go:embed dashboard.js
var script string

type Trend struct {
	Label string
	High  int
	Total int
	Width int
}
type view struct {
	Entries    []lifecycle.Entry
	New        int
	Active     int
	Resolved   int
	Unobserved int
	Overdue    int
	Gaps       int
	AsOf       string
	Engine     string
	Revision   string
	Owners     []string
	Trends     []Trend
	Script     template.JS
	CSP        string
}

func Render(w io.Writer, r lifecycle.Registry, runs []runrecord.Record, asOf string) error {
	r.Entries = append([]lifecycle.Entry{}, r.Entries...)
	if asOf == "" {
		asOf = r.EvaluatedOn
	}
	if r.Version != 1 {
		return fmt.Errorf("invalid lifecycle registry")
	}
	if e := lifecycle.Age(&r, asOf); e != nil {
		return e
	}
	v := view{Entries: r.Entries, AsOf: asOf, Engine: r.Previous.Engine, Revision: r.Previous.Revision, Owners: []string{}, Trends: []Trend{}, Script: template.JS(script)}
	owners := map[string]bool{}
	for _, e := range r.Entries {
		if e.Finding.Severity.Rank() < 0 {
			return fmt.Errorf("invalid finding severity")
		}
		switch e.State {
		case "new", "reopened":
			v.New++
		case "active":
			v.Active++
		case "resolved":
			v.Resolved++
		case "unobserved":
			v.Unobserved++
		default:
			return fmt.Errorf("invalid lifecycle state")
		}
		if e.Overdue {
			v.Overdue++
		}
		if e.Owner != "" {
			owners[e.Owner] = true
		}
	}
	for owner := range owners {
		v.Owners = append(v.Owners, owner)
	}
	slices.Sort(v.Owners)
	for _, scope := range r.Previous.Scopes {
		if !scope.Complete {
			v.Gaps++
		}
	}
	for _, f := range r.Previous.Report.Findings {
		if baseline.Incomplete(f) {
			v.Gaps++
		}
	}
	for i, run := range runs {
		n := run.Report.AtLeast("high")
		total := len(run.Report.Findings) - run.Report.Suppressed()
		label := run.Revision
		if len(label) > 12 {
			label = label[:12]
		}
		v.Trends = append(v.Trends, Trend{fmt.Sprintf("%d · %s", i+1, label), n, total, 0})
	}
	maximum := 1
	for _, t := range v.Trends {
		if t.High > maximum {
			maximum = t.High
		}
	}
	for i := range v.Trends {
		v.Trends[i].Width = v.Trends[i].High * 100 / maximum
	}
	sum := sha256.Sum256([]byte(script))
	v.CSP = "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'"
	tpl, e := template.New("dashboard").Funcs(template.FuncMap{"upper": func(v any) string { return strings.ToUpper(fmt.Sprint(v)) }}).Parse(page)
	if e != nil {
		return e
	}
	return tpl.Execute(w, v)
}
