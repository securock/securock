// Package quality measures explicitly labeled rule-per-fixture detection outcomes.
package quality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/validation"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Result struct {
	Name       string       `json:"name"`
	TP         int          `json:"tp"`
	FP         int          `json:"fp"`
	FN         int          `json:"fn"`
	TN         int          `json:"tn"`
	Unlabeled  []string     `json:"unlabeled"`
	Incomplete bool         `json:"incomplete"`
	Rules      []RuleResult `json:"rules,omitempty"`
}
type Report struct {
	Version       int          `json:"version"`
	FixtureDigest string       `json:"fixture_digest"`
	Engine        string       `json:"engine"`
	TP            int          `json:"tp"`
	FP            int          `json:"fp"`
	FN            int          `json:"fn"`
	TN            int          `json:"tn"`
	Precision     *float64     `json:"precision"`
	Recall        *float64     `json:"recall"`
	Results       []Result     `json:"results"`
	Passed        bool         `json:"passed"`
	Rules         []RuleResult `json:"rules,omitempty"`
}

func Evaluate(step validation.Step, report finding.Report, err error) (Result, error) {
	out := Result{Name: step.Name, Unlabeled: []string{}, Incomplete: err != nil}
	labels := map[string]bool{}
	for _, id := range step.Expected {
		if _, ok := labels[id]; ok || id == "" {
			return out, fmt.Errorf("duplicate or empty truth label")
		}
		labels[id] = true
	}
	for _, id := range step.Forbidden {
		if _, ok := labels[id]; ok || id == "" {
			return out, fmt.Errorf("contradictory or duplicate truth label")
		}
		labels[id] = false
	}
	if len(labels) == 0 {
		return out, fmt.Errorf("each fixture needs explicit truth labels")
	}
	observed := map[string]bool{}
	for _, f := range report.Findings {
		observed[f.ID] = true
		if strings.Contains(f.ID, "incomplete") {
			out.Incomplete = true
		}
	}
	for id, positive := range labels {
		rule := RuleResult{ID: id}
		if positive {
			if observed[id] {
				rule.TP = 1
			} else {
				rule.FN = 1
			}
		} else {
			if observed[id] {
				rule.FP = 1
			} else {
				rule.TN = 1
			}
		}
		out.Rules = append(out.Rules, rule)
		if positive {
			if observed[id] {
				out.TP++
			} else {
				out.FN++
			}
		} else {
			if observed[id] {
				out.FP++
			} else {
				out.TN++
			}
		}
	}
	for id := range observed {
		if _, ok := labels[id]; !ok {
			out.Unlabeled = append(out.Unlabeled, id)
		}
	}
	slices.SortFunc(out.Rules, func(a, b RuleResult) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(out.Unlabeled)
	return out, nil
}
func Aggregate(results []Result, digest, engine string, minPrecision, minRecall float64) Report {
	r := Report{Version: 1, FixtureDigest: digest, Engine: engine, Results: results, Passed: true}
	for _, v := range results {
		r.TP += v.TP
		r.FP += v.FP
		r.FN += v.FN
		r.TN += v.TN
		if v.Incomplete || len(v.Unlabeled) > 0 {
			r.Passed = false
		}
	}
	if r.TP+r.FP > 0 {
		v := float64(r.TP) / float64(r.TP+r.FP)
		r.Precision = &v
	}
	if r.TP+r.FN > 0 {
		v := float64(r.TP) / float64(r.TP+r.FN)
		r.Recall = &v
	}
	if r.Precision == nil || r.Recall == nil || *r.Precision < minPrecision || *r.Recall < minRecall {
		r.Passed = false
	}
	byRule := map[string]RuleResult{}
	for _, result := range results {
		for _, item := range result.Rules {
			v := byRule[item.ID]
			v.ID = item.ID
			v.TP += item.TP
			v.FP += item.FP
			v.FN += item.FN
			v.TN += item.TN
			byRule[item.ID] = v
		}
	}
	for _, item := range byRule {
		r.Rules = append(r.Rules, item)
	}
	slices.SortFunc(r.Rules, func(a, b RuleResult) int { return strings.Compare(a.ID, b.ID) })
	return r
}

type RuleResult struct {
	ID string `json:"id"`
	TP int    `json:"tp"`
	FP int    `json:"fp"`
	FN int    `json:"fn"`
	TN int    `json:"tn"`
}

// GateRules prevents strong categories from hiding a weak category. Undefined
// precision/recall in safe-only or positive-only categories is not invented.
func GateRules(r *Report, precision, recall, maxFPR float64, perRule bool) {
	gate := func(tp, fp, fn, tn int) bool {
		if tp+fp > 0 && float64(tp)/float64(tp+fp) < precision {
			return false
		}
		if tp+fn > 0 && float64(tp)/float64(tp+fn) < recall {
			return false
		}
		if fp+tn > 0 && float64(fp)/float64(fp+tn) > maxFPR {
			return false
		}
		return true
	}
	if !gate(r.TP, r.FP, r.FN, r.TN) {
		r.Passed = false
	}
	if perRule {
		if len(r.Rules) == 0 {
			r.Passed = false
		}
		for _, v := range r.Rules {
			if !gate(v.TP, v.FP, v.FN, v.TN) {
				r.Passed = false
			}
		}
	}
}

func FixtureDigest(root string, suite validation.Suite) (string, error) {
	hash := sha256.New()
	raw, _ := json.Marshal(suite)
	_, _ = hash.Write(raw)
	total := int64(0)
	files := 0
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture symlinks unsupported")
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		total += info.Size()
		files++
		if total > 32<<20 || files > 10000 {
			return fmt.Errorf("fixture budget exceeded")
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		encoded, _ := json.Marshal([]string{filepath.ToSlash(rel), hex.EncodeToString(data)})
		_, _ = hash.Write(encoded)
		return nil
	})
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
