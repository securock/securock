package runrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Scope struct {
	ID       string `json:"id"`
	Complete bool   `json:"complete"`
}
type Record struct {
	RecordDigest  string         `json:"record_digest"`
	Version       int            `json:"version"`
	Engine        string         `json:"engine"`
	Revision      string         `json:"revision"`
	Dirty         bool           `json:"dirty"`
	Configuration string         `json:"configuration"`
	ReportDigest  string         `json:"report_digest"`
	Scopes        []Scope        `json:"scopes"`
	Files         []string       `json:"files"`
	Report        finding.Report `json:"report"`
}

func Digest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func New(engine, revision, configuration, scope string, dirty bool, files []string, r finding.Report, success bool) Record {
	complete := success && (strings.HasPrefix(engine, "sha256:") || (!strings.HasPrefix(engine, "dev") && !strings.Contains(engine, "none") && engine != "@"))
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "sast:") && strings.Contains(f.ID, "incomplete") {
			complete = false
		}
	}
	slices.Sort(files)
	record := Record{Version: 1, Engine: engine, Revision: revision, Dirty: dirty, Configuration: Digest(configuration), ReportDigest: Digest(r), Scopes: []Scope{{ID: "source:" + scope, Complete: complete && scope != ""}}, Files: files, Report: r}
	record.RecordDigest = Digest(record)
	return record
}
func Read(r io.Reader) (Record, error) {
	var v Record
	raw, e := io.ReadAll(io.LimitReader(r, 32<<20+1))
	if e != nil || len(raw) > 32<<20 {
		return v, fmt.Errorf("record exceeds limit")
	}
	if json.Unmarshal(raw, &v) != nil || v.Version != 1 || v.Engine == "" || v.Configuration == "" || v.ReportDigest != Digest(v.Report) || v.Report.Findings == nil {
		return v, fmt.Errorf("invalid or altered scan record")
	}
	expected := v.RecordDigest
	v.RecordDigest = ""
	if expected == "" || expected != Digest(v) {
		return v, fmt.Errorf("scan record metadata checksum mismatch")
	}
	v.RecordDigest = expected
	if v.Report.Tool != "security" || len(v.Scopes) == 0 {
		return v, fmt.Errorf("invalid security record scope")
	}
	for _, f := range v.Report.Findings {
		if f.ID == "" || f.Title == "" || f.Severity.Rank() < 0 {
			return v, fmt.Errorf("invalid recorded finding")
		}
	}
	for _, file := range v.Files {
		if filepath.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") {
			return v, fmt.Errorf("record contains a non-relative source path")
		}
	}
	return v, nil
}
func Write(path string, r Record) error {
	raw, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}
func SourceFiles(root string) ([]string, error) {
	files := []string{}
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if path != root && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if slices.Contains([]string{".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".kt", ".cs", ".php", ".rb"}, filepath.Ext(path)) {
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(files)
	return files, e
}
