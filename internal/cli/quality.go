package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/quality"
	"github.com/securock/securock/internal/validation"
	"github.com/spf13/cobra"
	"math"
	"os"
	"path/filepath"
	"strings"
)

func newQualityCommand(opts *options) *cobra.Command {
	var fixtureRoot, baselineFile string
	var precision, recall, maxFPR float64
	var perRule bool
	c := &cobra.Command{Use: "quality SUITE.json", Short: "Gate offline fixture accuracy and compare regressions on identical fixture bytes", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if math.IsNaN(maxFPR) || math.IsNaN(precision) || math.IsNaN(recall) || maxFPR < 0 || maxFPR > 1 || precision < 0 || precision > 1 || recall < 0 || recall > 1 || fixtureRoot == "" {
			return opErr(fmt.Errorf("fixture root and precision/recall in [0,1] required"))
		}
		f, e := os.Open(a[0])
		if e != nil {
			return opErr(e)
		}
		suite, e := validation.Read(f)
		f.Close()
		if e != nil {
			return opErr(e)
		}
		root, e := filepath.Abs(fixtureRoot)
		if e != nil {
			return opErr(e)
		}
		for _, step := range suite.Steps {
			if step.Command != "security" && step.Command != "cspm" {
				return opErr(fmt.Errorf("quality supports reproducible offline security/cspm fixtures"))
			}
			for _, arg := range step.Args {
				if strings.Contains(arg, "--git-history") {
					return opErr(fmt.Errorf("history fixtures require separate provider validation"))
				}
				value := arg
				if _, v, ok := strings.Cut(arg, "="); ok {
					value = v
				}
				if _, e := os.Stat(value); e == nil {
					real, e := filepath.EvalSymlinks(value)
					if e != nil {
						return opErr(e)
					}
					abs, e := filepath.Abs(real)
					if e != nil {
						return opErr(e)
					}
					rel, e := filepath.Rel(root, abs)
					if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						return opErr(fmt.Errorf("fixture input outside fingerprint root"))
					}
				}
			}
		}
		fingerprint, e := quality.FixtureDigest(root, suite)
		if e != nil {
			return opErr(e)
		}
		exe, e := os.Executable()
		if e != nil {
			return opErr(e)
		}
		binary, e := os.ReadFile(exe)
		if e != nil {
			return opErr(e)
		}
		sum := sha256.Sum256(binary)
		results := []quality.Result{}
		for _, step := range suite.Steps {
			cmd := NewRoot(opts.toolVersion, "quality", "")
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(c.ErrOrStderr())
			cmd.SetContext(c.Context())
			cmd.SetArgs(append(append([]string{step.Command}, step.Args...), "--offline", "--no-fail", "--format", "json"))
			scanErr := cmd.Execute()
			report, readErr := baseline.Read(bytes.NewReader(out.Bytes()))
			if readErr != nil {
				scanErr = readErr
			}
			result, e := quality.Evaluate(step, report, scanErr)
			if e != nil {
				return opErr(e)
			}
			results = append(results, result)
		}
		r := quality.Aggregate(results, fingerprint, "sha256:"+hex.EncodeToString(sum[:]), precision, recall)
		quality.GateRules(&r, precision, recall, maxFPR, perRule)
		if baselineFile != "" {
			raw, e := os.ReadFile(baselineFile)
			if e != nil {
				return opErr(e)
			}
			var old quality.Report
			if json.Unmarshal(raw, &old) != nil || old.Version != 1 || old.FixtureDigest != fingerprint {
				return opErr(fmt.Errorf("baseline fixtures are not comparable"))
			}
			if r.FP > old.FP || r.FN > old.FN {
				r.Passed = false
			}
		}
		if e = json.NewEncoder(c.OutOrStdout()).Encode(r); e != nil {
			return opErr(e)
		}
		if !r.Passed {
			return trustErr("quality gate failed or evidence incomplete")
		}
		return nil
	}}
	c.Flags().StringVar(&fixtureRoot, "fixture-root", "", "root covering every local fixture input")
	c.Flags().StringVar(&baselineFile, "baseline", "", "quality report with the identical suite and fixture digest")
	c.Flags().Float64Var(&precision, "min-precision", 1, "minimum rule-per-fixture precision")
	c.Flags().Float64Var(&recall, "min-recall", 1, "minimum rule-per-fixture recall")
	c.Flags().Float64Var(&maxFPR, "max-fpr", 1, "maximum false-positive rate across explicitly labeled safe cases")
	c.Flags().BoolVar(&perRule, "per-rule", false, "also enforce precision, recall and false-positive thresholds for each rule")
	return c
}
