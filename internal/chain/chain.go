// Package chain correlates the findings of a source scan into attack chains: where
// attacker-controlled data enters, the dangerous operations it reaches, and the
// credentials an attacker could read on the way. It reinterprets findings the sast
// command already produced and collects no new evidence, so it is exactly as offline
// and deterministic. A link between two findings is confirmed only when both are
// proven live inside the same function; findings that merely share a file give a
// possible chain, and anything weaker is left out rather than guessed.
package chain

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Stage is the role a finding plays in an attack chain.
type Stage string

const (
	StageEntry  Stage = "entry"  // the boundary attacker-controlled data crosses
	StagePivot  Stage = "pivot"  // a foothold short of full control
	StageImpact Stage = "impact" // execution on the host or a credential
)

// Status grades a chain. Confirmed means every link is proven inside a single
// function; possible means the link relies on the findings sharing a file only.
const (
	Confirmed = "confirmed"
	Possible  = "possible"
)

// Node is one finding inside a chain, in the role the chain gives it. The entry node
// of a dataflow chain points at the finding's trace source, not at its sink.
type Node struct {
	FindingID string            `json:"finding"`
	Stage     Stage             `json:"stage"`
	Subject   string            `json:"subject,omitempty"`
	Location  *finding.Location `json:"location,omitempty"`
	Detail    string            `json:"detail,omitempty"`
}

// Link records why two consecutive nodes belong to one chain and how sure that is.
type Link struct {
	From   int    `json:"from"`
	To     int    `json:"to"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// Chain is one attack path. It may come from a single finding whose trace proves the
// whole path, or from several findings that share a file or a function.
type Chain struct {
	ID       string           `json:"id"`
	Severity finding.Severity `json:"severity"`
	Status   string           `json:"status"`
	Summary  string           `json:"summary"`
	Nodes    []Node           `json:"nodes"`
	Links    []Link           `json:"links,omitempty"`
}

// Report is the chain command's output.
type Report struct {
	Tool   string  `json:"tool"`
	Chains []Chain `json:"chains"`
}

// impactSinks are dangerous operations that give the attacker execution on the host or
// hand out a credential.
var impactSinks = map[string]bool{
	"command-injection":        true,
	"code-injection":           true,
	"insecure-deserialization": true,
	"hardcoded-secret":         true,
	"hardcoded-key":            true,
	"hardcoded-signing-key":    true,
}

// pivotSinks are dangerous operations that give a foothold short of full control: read
// or write where the attacker should not reach, or bend a trusted decision.
var pivotSinks = map[string]bool{
	"sql-injection":                true,
	"nosql-injection":              true,
	"xpath-injection":              true,
	"ldap-injection":               true,
	"path-traversal":               true,
	"zip-slip":                     true,
	"ssrf":                         true,
	"open-redirect":                true,
	"xss":                          true,
	"log-injection":                true,
	"regex-injection":              true,
	"mass-assignment":              true,
	"prototype-pollution":          true,
	"variable-extraction":          true,
	"xxe":                          true,
	"prompt-injection":             true,
	"unescaped-output":             true,
	"template-autoescape-disabled": true,
	"actions-script-injection":     true,
	"docker-pipe-to-shell":         true,
	"docker-socket-mount":          true,
	"host-path-mount":              true,
	"host-namespace":               true,
	"privilege-escalation":         true,
	"privileged-container":         true,
	"dangerous-capability":         true,
	"toctou":                       true,
	"trust-boundary":               true,
	"world-writable":               true,
	"insecure-temp-file":           true,
}

// entryEnablers weaken a boundary an attacker crosses before reaching a sink.
var entryEnablers = map[string]bool{
	"csrf-disabled":           true,
	"jwt-unverified":          true,
	"permit-all":              true,
	"directory-listing":       true,
	"spring-actuator-exposed": true,
	"spring-h2-console":       true,
	"debug-enabled":           true,
	"cors-misconfiguration":   true,
	"insecure-cookie":         true,
	"open-ingress":            true,
	"public-bucket":           true,
	"public-database":         true,
	"weak-allowlist":          true,
}

// exfilSinks are the operations through which an attacker can read a credential
// committed in the same file: read the file, make the host fetch it, or run code.
var exfilSinks = map[string]bool{
	"path-traversal":    true,
	"ssrf":              true,
	"command-injection": true,
	"code-injection":    true,
}

// credentialNames are hard-coded credentials outside the secrets scanner.
var credentialNames = map[string]bool{
	"hardcoded-secret":      true,
	"hardcoded-key":         true,
	"hardcoded-signing-key": true,
}

// stageOf classifies a finding by its rule. Findings that fit no chain role are
// excluded rather than guessed into one.
func stageOf(id string) (family, name string, stage Stage) {
	rest, ok := strings.CutPrefix(id, "sast:")
	if !ok {
		return "", "", ""
	}
	family, name, _ = strings.Cut(rest, "/")
	switch {
	case family == "secrets" || impactSinks[name]:
		return family, name, StageImpact
	case pivotSinks[name]:
		return family, name, StagePivot
	case entryEnablers[name]:
		return family, name, StageEntry
	}
	return family, name, ""
}

// classified is a finding prepared for chain building.
type classified struct {
	f      finding.Finding
	stage  Stage
	name   string
	family string
	file   string
	fn     string // the enclosing function from the subject, when it names one
	source string // the trace source of a dataflow finding, without the prefix
}

func classify(f finding.Finding) classified {
	family, name, stage := stageOf(f.ID)
	c := classified{f: f, stage: stage, name: name, family: family}
	c.file, c.fn = subjectParts(f.Subject)
	if c.file == "" {
		if l := f.Location; l != nil {
			c.file = l.File
		}
	}
	if len(f.Trace) > 0 {
		c.source = strings.TrimPrefix(f.Trace[0].Message, "untrusted data: ")
	}
	return c
}

// subjectParts splits "file#label", where a dataflow label is "fn/sink".
func subjectParts(s string) (file, fn string) {
	file, rest, ok := strings.Cut(s, "#")
	if !ok {
		return "", ""
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	return file, rest
}

// external reports whether the trace source is attacker-reachable on its own: a
// request field rather than a parameter whose callers are out of sight, or a value
// that is merely predictable.
func external(c classified) bool {
	return c.source != "" &&
		!strings.HasPrefix(c.source, "parameter ") &&
		c.source != "predictable random value"
}

// isTaint reports whether the finding came from the dataflow engine, whose subjects
// carry a function label and whose sources can compose with other findings.
func isTaint(c classified) bool {
	switch c.family {
	case "config", "secrets", "iac", "template":
		return false
	}
	return c.stage != "" && c.f.Location != nil
}

// Analyze correlates findings into attack chains. Accepted (suppressed) findings and
// findings that fit no chain role are skipped. The result is sorted by severity, then
// certainty, so the IDs assigned here are stable for the same input.
func Analyze(findings []finding.Finding) []Chain {
	var cls []classified
	for _, f := range findings {
		if f.Suppressed != nil {
			continue
		}
		if c := classify(f); c.stage != "" {
			cls = append(cls, c)
		}
	}

	var cs []Chain
	seen := map[string]bool{}
	add := func(c Chain, key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		cs = append(cs, c)
	}
	for _, c := range cls {
		// One finding whose trace proves the whole path is a chain on its own:
		// attacker-controlled data straight into a dangerous operation.
		if c.stage != StageEntry && external(c) && len(c.f.Trace) > 0 {
			add(taintChain(c), chainKey([]Node{entryNode(c), nodeOf(c)}))
		}
	}
	for i := range cls {
		for j := i + 1; j < len(cls); j++ {
			x, y := cls[i], cls[j]
			if !sameFile(x, y) {
				continue
			}
			for _, p := range [][2]classified{{x, y}, {y, x}} {
				a, b := p[0], p[1]
				var nodes []Node
				switch {
				case a.stage == StageEntry && isSink(b) && !isCredential(b):
					// The weakened boundary sits in front of the sink.
					nodes = []Node{nodeOf(a), nodeOf(b)}
				case isSink(a) && exfilSinks[a.name] && isCredential(b):
					// The sink is a way to read back the committed credential.
					nodes = []Node{nodeOf(a), nodeOf(b)}
				case isSink(a) && !isCredential(a) && isTaint(b) && hasParamSource(b):
					// One untrusted entry composes with another finding's sink.
					nodes = []Node{entryNode(b), nodeOf(a)}
				default:
					continue
				}
				add(twoNodeChain(a, b, nodes), chainKey(nodes))
			}
		}
	}

	rank := map[string]int{Confirmed: 0, Possible: 1}
	slices.SortStableFunc(cs, func(a, b Chain) int {
		if n := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); n != 0 {
			return n
		}
		if n := cmp.Compare(rank[a.Status], rank[b.Status]); n != 0 {
			return n
		}
		return strings.Compare(chainKey(a.Nodes), chainKey(b.Nodes))
	})
	for i := range cs {
		cs[i].ID = fmt.Sprintf("chain:%d", i+1)
	}
	return cs
}

// sameFile compares where the findings live. The subject names the file for every
// source-backed finding; the location is the fallback for the rest.
func sameFile(a, b classified) bool {
	return a.file != "" && a.file == b.file
}

func isSink(c classified) bool { return c.stage == StagePivot || c.stage == StageImpact }

// hasParamSource reports whether the finding's untrusted data entered through a
// parameter, meaning its callers decide what reaches the sink.
func hasParamSource(c classified) bool {
	return strings.HasPrefix(c.source, "parameter ")
}

func isCredential(c classified) bool {
	return c.family == "secrets" || credentialNames[c.name]
}

func nodeOf(c classified) Node {
	return Node{FindingID: c.f.ID, Stage: c.stage, Subject: c.f.Subject, Location: c.f.Location, Detail: c.f.Detail}
}

// entryNode is the trace source of a dataflow finding: where untrusted data enters.
func entryNode(c classified) Node {
	src := c.f.Trace[0]
	return Node{FindingID: c.f.ID, Stage: StageEntry, Subject: c.f.Subject, Location: &src.Location, Detail: c.source}
}

// taintChain turns one dataflow finding into a chain. The trace is the proof, so the
// chain is confirmed.
func taintChain(c classified) Chain {
	return Chain{
		Severity: c.f.Severity,
		Status:   Confirmed,
		Summary:  c.f.Detail,
		Nodes:    []Node{entryNode(c), nodeOf(c)},
		Links: []Link{{
			From: 0, To: 1, Status: Confirmed,
			Reason: "the trace proves untrusted data flows from the source to the sink",
		}},
	}
}

// twoNodeChain joins two findings that share a file. Sharing the enclosing function
// makes the link confirmed; sharing only the file leaves it possible.
func twoNodeChain(a, b classified, nodes []Node) Chain {
	st := linkStatus(a, b)
	return Chain{
		Severity: maxSeverity(a.f, b.f),
		Status:   st,
		Summary:  summary(a, b),
		Nodes:    nodes,
		Links:    []Link{{From: 0, To: 1, Status: st, Reason: linkReason(a, b, st)}},
	}
}

// linkStatus grades a link between two findings. Sharing the enclosing function is
// proof both are live at the same entry point; sharing only a file is not.
func linkStatus(a, b classified) string {
	if a.fn != "" && a.fn == b.fn {
		return Confirmed
	}
	return Possible
}

func linkReason(a, b classified, st string) string {
	r := fmt.Sprintf("%s and %s share %s", a.f.ID, b.f.ID, a.file)
	if st == Confirmed {
		r += " and the same function"
	}
	return r
}

// summary describes what the chain means, not just which findings it holds.
func summary(a, b classified) string {
	switch {
	case a.stage == StageEntry:
		return fmt.Sprintf("untrusted input can reach %s in %s past %s", b.name, a.file, bareTitle(a.f.Title))
	case isCredential(b):
		return fmt.Sprintf("an attacker who reaches %s in %s can read the credential committed there", a.name, a.file)
	default:
		return fmt.Sprintf("untrusted %s enters %s and composes with %s there", b.source, a.file, a.name)
	}
}

// bareTitle drops the trailing CWE reference: "OS command injection (CWE-78)".
func bareTitle(t string) string {
	if i := strings.LastIndex(t, " (CWE-"); i > 0 {
		return t[:i]
	}
	return t
}

func maxSeverity(fs ...finding.Finding) finding.Severity {
	out := finding.SeverityInfo
	for _, f := range fs {
		if f.Severity.Rank() > out.Rank() {
			out = f.Severity
		}
	}
	return out
}

// chainKey identifies a chain by its nodes, so equivalent chains are added once.
func chainKey(nodes []Node) string {
	var b strings.Builder
	for _, n := range nodes {
		fmt.Fprintf(&b, "%s/%s/", n.FindingID, n.Stage)
	}
	return b.String()
}
