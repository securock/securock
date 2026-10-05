package evidence

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

// extractChain walks an npm attestations payload and pulls source/build
// identity fields from SLSA provenance predicates when present.
func extractChain(raw []byte) (lockfile.EvidenceState, lockfile.ChainEvidence) {
	var parsed struct {
		Attestations []json.RawMessage `json:"attestations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return lockfile.EvidenceUnknown, lockfile.ChainEvidence{State: lockfile.EvidenceUnknown}
	}
	if len(parsed.Attestations) == 0 {
		return lockfile.EvidenceMissing, lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	}

	foundProvenance := false
	chain := lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	for _, att := range parsed.Attestations {
		var envelope struct {
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
			Bundle        json.RawMessage `json:"bundle"`
		}
		if err := json.Unmarshal(att, &envelope); err != nil {
			continue
		}
		predType := envelope.PredicateType
		pred := envelope.Predicate
		if len(pred) == 0 && len(envelope.Bundle) > 0 {
			predType, pred = predicateFromBundle(envelope.Bundle)
		}
		if !isProvenance(predType) {
			continue
		}
		foundProvenance = true
		if filled := fillChainFromPredicate(pred); filled.Source != "" || filled.Commit != "" || filled.Builder != "" || filled.Workflow != "" {
			chain = filled
			chain.State = lockfile.EvidencePresent
			break
		}
		chain.State = lockfile.EvidencePresent
	}
	if !foundProvenance {
		return lockfile.EvidenceMissing, lockfile.ChainEvidence{State: lockfile.EvidenceMissing}
	}
	return lockfile.EvidencePresent, chain
}

// ExtractChainForTest exposes extractChain for unit tests.
func ExtractChainForTest(raw []byte) (lockfile.EvidenceState, lockfile.ChainEvidence) {
	return extractChain(raw)
}

func predicateFromBundle(raw []byte) (predicateType string, predicate json.RawMessage) {
	if t, p := findPredicate(raw); t != "" {
		return t, p
	}
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Payload != "" {
		if decoded, err := decodeBase64(envelope.Payload); err == nil {
			return findPredicate(decoded)
		}
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return "", nil
	}
	for _, key := range []string{"dsseEnvelope", "DsseEnvelope", "statement", "Statement", "bundle", "Bundle"} {
		child, ok := nested[key]
		if !ok {
			continue
		}
		if t, p := predicateFromBundle(child); t != "" {
			return t, p
		}
	}
	return "", nil
}

func findPredicate(raw []byte) (string, json.RawMessage) {
	var stmt struct {
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err == nil && isProvenance(stmt.PredicateType) && len(stmt.Predicate) > 0 {
		return stmt.PredicateType, stmt.Predicate
	}
	return "", nil
}

func decodeBase64(payload string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(payload); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(payload); err == nil {
		return raw, nil
	}
	if raw, err := base64.URLEncoding.DecodeString(payload); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(payload)
}

func fillChainFromPredicate(raw json.RawMessage) lockfile.ChainEvidence {
	if len(raw) == 0 {
		return lockfile.ChainEvidence{}
	}
	var pred map[string]any
	if err := json.Unmarshal(raw, &pred); err != nil {
		return lockfile.ChainEvidence{}
	}
	out := lockfile.ChainEvidence{}
	// Prefer well-known SLSA paths for deterministic lock output.
	fillFromKnownPaths(pred, &out)
	// Fill any remaining gaps with a deterministic key-ordered walk.
	walkChain(pred, &out)
	out.Source = normalizeSource(out.Source)
	out.Workflow = normalizeWorkflow(out.Workflow, out.Builder)
	return out
}

func fillFromKnownPaths(pred map[string]any, out *lockfile.ChainEvidence) {
	// SLSA provenance v1
	if bd, ok := asMap(pred["buildDefinition"]); ok {
		if params, ok := asMap(bd["externalParameters"]); ok {
			if wf, ok := asMap(params["workflow"]); ok {
				setSource(out, stringField(wf, "repository"))
				setWorkflow(out, stringField(wf, "path"))
			}
			setSource(out, stringField(params, "source"))
			setSource(out, stringField(params, "repository"))
		}
		if deps, ok := bd["resolvedDependencies"].([]any); ok {
			for _, dep := range deps {
				dm, ok := asMap(dep)
				if !ok {
					continue
				}
				uri := stringField(dm, "uri")
				if looksLikeSource(uri) {
					setSource(out, uri)
					if digests, ok := asMap(dm["digest"]); ok {
						setCommit(out, stringField(digests, "sha1"))
						setCommit(out, stringField(digests, "gitCommit"))
					}
					break
				}
			}
		}
	}
	if rd, ok := asMap(pred["runDetails"]); ok {
		if builder, ok := asMap(rd["builder"]); ok {
			setBuilder(out, stringField(builder, "id"))
		}
	}
	// SLSA provenance v0.2
	if materials, ok := pred["materials"].([]any); ok {
		for _, m := range materials {
			mm, ok := asMap(m)
			if !ok {
				continue
			}
			uri := stringField(mm, "uri")
			if looksLikeSource(uri) {
				setSource(out, uri)
				if digests, ok := asMap(mm["digest"]); ok {
					setCommit(out, stringField(digests, "sha1"))
					setCommit(out, stringField(digests, "gitCommit"))
				}
				break
			}
		}
	}
	if inv, ok := asMap(pred["invocation"]); ok {
		if cfg, ok := asMap(inv["configSource"]); ok {
			setSource(out, stringField(cfg, "uri"))
			setWorkflow(out, stringField(cfg, "entryPoint"))
			if digests, ok := asMap(cfg["digest"]); ok {
				setCommit(out, stringField(digests, "sha1"))
				setCommit(out, stringField(digests, "gitCommit"))
			}
		}
	}
	if builder, ok := asMap(pred["builder"]); ok {
		setBuilder(out, stringField(builder, "id"))
	}
}

func walkChain(v any, out *lockfile.ChainEvidence) {
	switch typed := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		// Deterministic visit order.
		slices.Sort(keys)
		for _, k := range keys {
			child := typed[k]
			switch k {
			case "id":
				if s, ok := child.(string); ok {
					setBuilder(out, s)
				}
			case "uri", "repository", "repo", "source":
				if s, ok := child.(string); ok {
					setSource(out, s)
				}
			case "entryPoint", "path", "workflow", "workflowPath":
				if s, ok := child.(string); ok {
					setWorkflow(out, s)
				}
			case "commit", "revision":
				if s, ok := child.(string); ok {
					setCommit(out, s)
				}
			case "digest":
				if digests, ok := asMap(child); ok {
					setCommit(out, stringField(digests, "sha1"))
					setCommit(out, stringField(digests, "gitCommit"))
				}
			}
			walkChain(child, out)
		}
	case []any:
		for _, child := range typed {
			walkChain(child, out)
		}
	}
}

func setSource(out *lockfile.ChainEvidence, s string) {
	if out.Source == "" && looksLikeSource(s) {
		out.Source = s
	}
}

func setBuilder(out *lockfile.ChainEvidence, s string) {
	if out.Builder == "" && looksLikeBuilder(s) {
		out.Builder = s
	}
}

func setWorkflow(out *lockfile.ChainEvidence, s string) {
	if out.Workflow == "" && looksLikeWorkflow(s) {
		out.Workflow = s
	}
}

func setCommit(out *lockfile.ChainEvidence, s string) {
	if out.Commit == "" && looksLikeCommit(s) {
		out.Commit = s
	}
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func looksLikeSource(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "github.com/") ||
		strings.Contains(low, "gitlab.com/") ||
		strings.HasPrefix(low, "git+") ||
		(strings.HasPrefix(low, "https://") && strings.Contains(low, ".git"))
}

func looksLikeBuilder(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "github.com/") ||
		strings.Contains(low, "gitlab.com/") ||
		strings.Contains(low, "actions") ||
		strings.Contains(low, "builder")
}

func looksLikeCommit(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func looksLikeWorkflow(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, ".yml") || strings.Contains(low, ".yaml") || strings.Contains(low, "workflow")
}

func normalizeSource(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "git+")
	if !strings.HasPrefix(s, "git@") {
		if i := strings.LastIndex(s, "@"); i > 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "ssh://git@")
	s = strings.TrimPrefix(s, "git@")
	s = strings.Replace(s, ":", "/", 1)
	return strings.TrimSuffix(s, "/")
}

func normalizeWorkflow(workflow, builder string) string {
	if workflow != "" {
		if i := strings.LastIndex(workflow, "/"); i >= 0 {
			return workflow[i+1:]
		}
		return workflow
	}
	if i := strings.Index(builder, "/.github/workflows/"); i >= 0 {
		rest := builder[i+len("/.github/workflows/"):]
		if j := strings.IndexAny(rest, "@?"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	return ""
}
