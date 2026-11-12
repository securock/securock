package organization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"io"
	"slices"
	"strings"
	"time"
)

type Service struct {
	Owner            string         `json:"owner"`
	Criticality      int            `json:"criticality"`
	FailOn           string         `json:"fail_on"`
	SLADays          map[string]int `json:"sla_days"`
	RequireApprover  bool           `json:"require_approver"`
	Reviewers        []string       `json:"reviewers"`
	MaxExceptionDays int            `json:"max_exception_days"`
}
type Policy struct {
	Version  int                `json:"version"`
	Services map[string]Service `json:"services"`
}
type Task struct {
	Priority int    `json:"priority"`
	Key      string `json:"key"`
	Owner    string `json:"owner"`
	Due      string `json:"due"`
}
type Result struct {
	Criticality int            `json:"criticality"`
	Version     int            `json:"version"`
	Service     string         `json:"service"`
	Report      finding.Report `json:"report"`
	Tasks       []Task         `json:"tasks"`
}

func Read(r io.Reader) (Policy, error) {
	var p Policy
	raw, e := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return p, fmt.Errorf("organization policy exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || p.Version != 1 || len(p.Services) == 0 {
		return p, fmt.Errorf("invalid organization policy")
	}
	var encoded struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	json.Unmarshal(raw, &encoded)
	for name, s := range p.Services {
		required := string(bytes.TrimSpace(encoded.Services[name]["require_approver"]))
		if required != "true" && required != "false" {
			return p, fmt.Errorf("require_approver must be an explicit boolean")
		}
		for _, reviewer := range s.Reviewers {
			if strings.TrimSpace(reviewer) == "" {
				return p, fmt.Errorf("reviewer identities must not be empty")
			}
		}
		if name == "" || strings.TrimSpace(s.Owner) == "" || s.Criticality < 1 || s.Criticality > 5 || s.MaxExceptionDays < 1 || s.MaxExceptionDays > 3650 || (s.RequireApprover && len(s.Reviewers) == 0) {
			return p, fmt.Errorf("service requires owner, criticality 1..5, positive exception limit and approvers when required")
		}
		if _, e := finding.ParseSeverity(s.FailOn); e != nil {
			return p, e
		}
		for sev, days := range s.SLADays {
			if _, e := finding.ParseSeverity(sev); e != nil || days < 1 || days > 3650 {
				return p, fmt.Errorf("invalid severity SLA")
			}
		}
	}
	return p, nil
}
func Evaluate(r finding.Report, p Policy, service, asOf string) (Result, error) {
	s, ok := p.Services[service]
	if !ok {
		return Result{}, fmt.Errorf("unknown service")
	}
	day, e := time.Parse("2006-01-02", asOf)
	if e != nil {
		return Result{}, fmt.Errorf("organization evaluation requires --as-of/--policy-date YYYY-MM-DD")
	}
	found := append([]finding.Finding{}, r.Findings...)
	tasks := []Task{}
	for i := range found {
		f := &found[i]
		if f.Suppressed != nil {
			end, e := time.Parse("2006-01-02", f.Suppressed.Expires)
			invalid := e != nil || !end.After(day) || end.After(day.AddDate(0, 0, s.MaxExceptionDays)) || (s.RequireApprover && !slices.Contains(s.Reviewers, f.Suppressed.Approver))
			if invalid {
				f.Suppressed = nil
				found = append(found, finding.Finding{ID: "org:exception-rejected", Severity: finding.SeverityHigh, Subject: f.Subject, Title: "Accepted risk does not satisfy organization policy", Remediation: "Obtain an allowed reviewer and an expiry within the service exception limit."})
			}
		}
		if f.Suppressed == nil {
			if days, ok := s.SLADays[string(f.Severity)]; ok {
				tasks = append(tasks, Task{Priority: (f.Severity.Rank()+1)*10 + s.Criticality*3, Key: baseline.Key(*f), Owner: s.Owner, Due: day.AddDate(0, 0, days).Format("2006-01-02")})
			}
		}
	}
	return Result{Criticality: s.Criticality, Version: 1, Service: service, Report: finding.New(r.Tool, found), Tasks: tasks}, nil
}
