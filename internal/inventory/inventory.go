// Package inventory discovers repositories and records observed deployment identities.
package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/external"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Node struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Revision string `json:"revision,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Owner    string `json:"owner,omitempty"`
}
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Evidence string `json:"evidence"`
}
type Report struct {
	Version int      `json:"version"`
	Nodes   []Node   `json:"nodes"`
	Edges   []Edge   `json:"edges"`
	Gaps    []string `json:"gaps"`
}

func Discover(ctx context.Context, root string, pods []byte) (Report, error) {
	r := Report{Version: 1, Nodes: []Node{}, Edges: []Edge{}, Gaps: []string{}}
	repos := map[string]bool{}
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" || d.Name() == ".securock") {
			return filepath.SkipDir
		}
		if _, e := os.Stat(filepath.Join(path, ".git")); e != nil {
			return nil
		}
		if len(repos) >= 1000 {
			return fmt.Errorf("repository discovery quota exceeded")
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		id := "repo:" + filepath.ToSlash(rel)
		raw, e := external.Run(ctx, "git", "-c", "core.fsmonitor=false", "-C", path, "rev-parse", "--verify", "HEAD^{commit}")
		if e != nil {
			r.Gaps = append(r.Gaps, id+": unreadable revision")
			return nil
		}
		owner := ""
		for _, name := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
			b, e := os.ReadFile(filepath.Join(path, name))
			if e == nil {
				for _, line := range strings.Split(string(b), "\n") {
					fields := strings.Fields(line)
					if len(fields) > 1 && fields[0] == "*" {
						owner = strings.Join(fields[1:], " ")
					}
				}
				break
			}
		}
		r.Nodes = append(r.Nodes, Node{ID: id, Kind: "repository", Revision: strings.TrimSpace(string(raw)), Owner: owner})
		repos[id] = true
		r.Gaps = append(r.Gaps, id+": scan coverage and deployed artifact linkage not yet verified")
		return nil
	})
	if e != nil {
		return r, e
	}
	if len(pods) > 0 {
		if len(pods) > 16<<20 {
			return r, fmt.Errorf("pod inventory exceeds limit")
		}
		var list struct {
			Kind  string `json:"kind"`
			Items []struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name        string            `json:"name"`
					Namespace   string            `json:"namespace"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec struct {
					ServiceAccount string `json:"serviceAccountName"`
					Containers     []struct {
						Name  string `json:"name"`
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
				Status struct {
					Phase      string `json:"phase"`
					Containers []struct {
						Name    string `json:"name"`
						ImageID string `json:"imageID"`
						State   struct {
							Running json.RawMessage `json:"running"`
						} `json:"state"`
					} `json:"containerStatuses"`
				} `json:"status"`
			} `json:"items"`
		}
		if json.Unmarshal(pods, &list) != nil || list.Kind != "PodList" && list.Kind != "List" {
			return r, fmt.Errorf("Kubernetes PodList required")
		}
		if len(list.Items) > 10000 {
			return r, fmt.Errorf("pod inventory quota exceeded")
		}
		for _, pod := range list.Items {
			if pod.Metadata.Name == "" || pod.Metadata.Namespace == "" {
				return r, fmt.Errorf("pod identity incomplete")
			}
			id := "pod:" + pod.Metadata.Namespace + "/" + pod.Metadata.Name
			r.Nodes = append(r.Nodes, Node{ID: id, Kind: "workload"})
			if project := pod.Metadata.Annotations["securock.dev/project"]; project != "" && repos["repo:"+project] {
				r.Edges = append(r.Edges, Edge{"repo:" + project, id, "declared-source", "declared"})
			}
			if pod.Spec.ServiceAccount != "" {
				sa := "identity:" + pod.Metadata.Namespace + "/" + pod.Spec.ServiceAccount
				r.Nodes = append(r.Nodes, Node{ID: sa, Kind: "service-account"})
				r.Edges = append(r.Edges, Edge{id, sa, "uses-identity", "observed"})
			}
			observed := map[string]bool{}
			for _, container := range pod.Status.Containers {
				digest := container.ImageID
				at := strings.LastIndex(digest, "sha256:")
				if at < 0 || len(digest[at:]) != 71 || pod.Status.Phase != "Running" || len(container.State.Running) == 0 {
					continue
				}
				digest = digest[at:]
				valid := true
				for _, c := range digest[7:] {
					if !strings.ContainsRune("0123456789abcdef", c) {
						valid = false
					}
				}
				if !valid {
					continue
				}
				image := "image:" + digest
				r.Nodes = append(r.Nodes, Node{ID: image, Kind: "image", Digest: digest})
				r.Edges = append(r.Edges, Edge{id, image, "runs", "observed"})
				observed[container.Name] = true
			}
			for _, c := range pod.Spec.Containers {
				if !observed[c.Name] {
					r.Gaps = append(r.Gaps, id+"/"+c.Name+": running image digest unknown")
				}
			}
			r.Gaps = append(r.Gaps, id+": external reachability, effective cloud IAM and data access unknown")
		}
	} else {
		r.Gaps = append(r.Gaps, "deployment inventory not collected")
	}
	slices.SortFunc(r.Nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	r.Nodes = slices.CompactFunc(r.Nodes, func(a, b Node) bool { return a.ID == b.ID })
	slices.SortFunc(r.Edges, func(a, b Edge) int {
		return strings.Compare(a.From+"/"+a.To+"/"+a.Relation, b.From+"/"+b.To+"/"+b.Relation)
	})
	slices.Sort(r.Gaps)
	return r, nil
}
