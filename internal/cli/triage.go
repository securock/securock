package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/lifecycle"
	"github.com/securock/securock/internal/runrecord"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func saveState(path string, v any) error {
	raw, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".securock-state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(append(raw, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func readRecord(path string) (runrecord.Record, error) {
	f, e := os.Open(path)
	if e != nil {
		return runrecord.Record{}, e
	}
	defer f.Close()
	return runrecord.Read(f)
}
func newTriageCommand(opts *options) *cobra.Command {
	var state, key, owner, due, asOf string
	c := &cobra.Command{Use: "triage RUN.json", Short: "Track new active resolved reopened and unobserved findings", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		current, e := readRecord(a[0])
		if e != nil {
			return opErr(e)
		}
		var old lifecycle.Registry
		if raw, e := os.ReadFile(state); e == nil {
			var err error
			old, err = lifecycle.Read(bytes.NewReader(raw))
			if err != nil {
				return opErr(fmt.Errorf("invalid lifecycle state"))
			}
		} else if !os.IsNotExist(e) {
			return opErr(e)
		}
		r := lifecycle.Step(old, current)
		if key != "" {
			if e := lifecycle.Assign(&r, key, owner, due); e != nil {
				return opErr(e)
			}
		} else if owner != "" || due != "" {
			return opErr(fmt.Errorf("assignment requires --finding KEY"))
		}
		if e := lifecycle.Age(&r, asOf); e != nil {
			return opErr(e)
		}
		if e := saveState(state, r); e != nil {
			return opErr(e)
		}
		if opts.format == "json" {
			return json.NewEncoder(c.OutOrStdout()).Encode(r)
		}
		if opts.format != "text" {
			return opErr(fmt.Errorf("triage supports text or json"))
		}
		for _, e := range r.Entries {
			fmt.Fprintf(c.OutOrStdout(), "%s %s %s owner=%s due=%s overdue=%t\n", e.Key, e.State, e.Finding.ID, e.Owner, e.Due, e.Overdue)
		}
		return nil
	}}
	c.Flags().StringVar(&state, "state", ".securock-issues.json", "lifecycle registry")
	c.Flags().StringVar(&key, "finding", "", "entry key to assign")
	c.Flags().StringVar(&owner, "owner", "", "responsible team or user")
	c.Flags().StringVar(&due, "due", "", "explicit deadline YYYY-MM-DD")
	c.Flags().StringVar(&asOf, "as-of", "", "evaluate overdue status at this explicit date")
	return c
}
