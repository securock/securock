// Package protect enforces secret detection at Git commit and receive boundaries.
package protect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/history"
	"github.com/securock/securock/internal/sast"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

func Artifact(f finding.Finding) string {
	identity := f.ID + "\x00" + f.Subject
	if f.Location != nil {
		identity += fmt.Sprint("\x00", f.Location.File, ":", f.Location.Line)
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}
func Apply(r finding.Report, approvals map[string]control.Approval, now time.Time) finding.Report {
	for i, f := range r.Findings {
		artifact := Artifact(f)
		r.Findings[i].Detail += " Approval artifact: " + artifact + "."
		for _, a := range approvals {
			exp, e := time.Parse(time.RFC3339, a.Expires)
			if e == nil && a.Status == "approved" && a.Reviewer != "" && a.Requester != a.Reviewer && a.Rule == f.ID && a.Artifact == artifact && exp.After(now) {
				r.Findings[i].Suppressed = &finding.Suppression{Reason: a.Reason, Approver: a.Reviewer, Expires: a.Expires}
				break
			}
		}
	}
	return r
}
func Staged(ctx context.Context, path string) (finding.Report, error) {
	git := func(args ...string) ([]byte, error) {
		return external.Run(ctx, "git", append([]string{"-c", "core.fsmonitor=false", "-C", path}, args...)...)
	}
	raw, e := git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if e != nil {
		return finding.New("protect", nil), e
	}
	changed := map[string]bool{}
	for _, name := range bytes.Split(raw, []byte{0}) {
		if len(name) > 0 {
			changed[string(name)] = true
		}
	}
	index, e := git("ls-files", "--stage", "-z")
	if e != nil {
		return finding.New("protect", nil), e
	}
	found := []finding.Finding{}
	count := 0
	for _, entry := range bytes.Split(index, []byte{0}) {
		meta, name, ok := strings.Cut(string(entry), "\t")
		if !ok || !changed[name] {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[2] != "0" {
			return finding.New("protect", found), fmt.Errorf("unmerged or invalid index")
		}
		if fields[0] != "100644" && fields[0] != "100755" {
			continue
		}
		count++
		if count > 10000 {
			return finding.New("protect", found), fmt.Errorf("staged file quota exceeded")
		}
		size, e := git("cat-file", "-s", fields[1])
		if e != nil {
			return finding.New("protect", found), e
		}
		n, e := strconv.Atoi(strings.TrimSpace(string(size)))
		if e != nil || n > 512<<10 {
			return finding.New("protect", found), fmt.Errorf("staged blob exceeds secret scan limit")
		}
		body, e := git("cat-file", "blob", fields[1])
		if e != nil {
			return finding.New("protect", found), e
		}
		for _, f := range sast.SecretContent(name, body) {
			f.ID = "protect:" + strings.TrimPrefix(f.ID, "sast:")
			f.Subject = fields[1] + ":" + name
			found = append(found, f)
		}
	}
	return finding.New("protect", found), nil
}
func Receive(ctx context.Context, path string, input io.Reader) (finding.Report, error) {
	rawInput, readErr := io.ReadAll(io.LimitReader(input, 65537))
	if readErr != nil || len(rawInput) > 65536 {
		return finding.New("protect", nil), fmt.Errorf("receive input exceeds limit")
	}
	scanner := bufio.NewScanner(bytes.NewReader(rawInput))
	found := []finding.Finding{}
	revisions := map[string]bool{}
	refs := 0
	for scanner.Scan() {
		refs++
		if refs > 100 {
			return finding.New("protect", found), fmt.Errorf("receive ref quota exceeded")
		}
		parts := strings.Fields(scanner.Text())
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "refs/") {
			return finding.New("protect", found), fmt.Errorf("invalid receive command")
		}
		raw, e := hex.DecodeString(parts[1])
		if e != nil || len(raw) != 20 && len(raw) != 32 {
			return finding.New("protect", found), fmt.Errorf("invalid receive revision")
		}
		if bytes.Equal(raw, make([]byte, len(raw))) || revisions[parts[1]] {
			continue
		}
		revisions[parts[1]] = true
		r, e := history.Scan(ctx, history.Options{Path: path, Revision: parts[1], MaxCommits: 10000, MaxBlobs: 100000})
		found = append(found, r.Findings...)
		if e != nil {
			return finding.New("protect", found), e
		}
		for _, f := range r.Findings {
			if f.ID == "history:content-unchecked" {
				return finding.New("protect", found), fmt.Errorf("receive history has unchecked oversized blobs")
			}
		}
	}
	if e := scanner.Err(); e != nil {
		return finding.New("protect", found), e
	}
	if refs == 0 {
		return finding.New("protect", nil), fmt.Errorf("receive commands required")
	}
	slices.SortFunc(found, func(a, b finding.Finding) int { return strings.Compare(a.ID+a.Subject, b.ID+b.Subject) })
	found = slices.CompactFunc(found, func(a, b finding.Finding) bool { return a.ID == b.ID && a.Subject == b.Subject })
	return finding.New("protect", found), nil
}
