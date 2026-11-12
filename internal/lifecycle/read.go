package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/runrecord"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

func Read(r io.Reader) (Registry, error) {
	var state Registry
	raw, e := io.ReadAll(io.LimitReader(r, 32<<20+1))
	if e != nil || len(raw) > 32<<20 {
		return state, fmt.Errorf("lifecycle state exceeds limit")
	}
	if json.Unmarshal(raw, &state) != nil || state.Version != 1 {
		return state, fmt.Errorf("invalid lifecycle state")
	}
	previous, e := json.Marshal(state.Previous)
	if e != nil {
		return state, e
	}
	if _, e := runrecord.Read(bytes.NewReader(previous)); e != nil {
		return state, e
	}
	seen := map[string]bool{}
	for _, entry := range state.Entries {
		key, n, ok := strings.Cut(entry.Key, ":")
		count, e := strconv.Atoi(n)
		if !ok || e != nil || count < 1 || key != baseline.Key(entry.Finding) || seen[entry.Key] || entry.Finding.Severity.Rank() < 0 || entry.Finding.Title == "" || !slices.Contains([]string{"new", "active", "resolved", "reopened", "unobserved"}, entry.State) {
			return state, fmt.Errorf("invalid lifecycle entry")
		}
		seen[entry.Key] = true
		if entry.Due != "" {
			if _, e := time.Parse("2006-01-02", entry.Due); e != nil {
				return state, fmt.Errorf("invalid stored deadline")
			}
		}
	}
	if state.EvaluatedOn != "" {
		if _, e := time.Parse("2006-01-02", state.EvaluatedOn); e != nil {
			return state, e
		}
	}
	return state, nil
}
