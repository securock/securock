// Package graph draws the dependency graph recorded in a lock document, colored by the
// trust status of each package.
package graph

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type Node struct {
	ID     string
	Label  string
	Status lockfile.Status
	Scope  lockfile.Scope
}

type Graph struct {
	// Nodes are sorted by ID.
	Nodes []Node
	// Edges maps a node ID to the sorted IDs it depends on directly.
	Edges map[string][]string
	// Roots are the nodes nothing depends on, sorted. With no edges recorded every node is a root.
	Roots []string
	// HasEdges is false when the lockfile gave no dependency information, so a flat graph
	// is not mistaken for a project with no transitive dependencies.
	HasEdges bool
}

// Build reads nodes and edges from the document. Dependencies that name no artifact in the
// document are dropped.
func Build(doc lockfile.Document) Graph {
	g := Graph{Edges: map[string][]string{}}
	known := map[string]bool{}
	for _, a := range doc.Artifacts {
		id := a.ArtifactID()
		if known[id] {
			continue
		}
		known[id] = true
		g.Nodes = append(g.Nodes, Node{ID: id, Label: label(a), Status: a.Trust.Status, Scope: a.Scope})
	}
	slices.SortFunc(g.Nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })

	hasParent := map[string]bool{}
	seen := map[string]bool{}
	for _, a := range doc.Artifacts {
		id := a.ArtifactID()
		if seen[id] {
			continue
		}
		seen[id] = true
		var out []string
		for _, dep := range a.Dependencies {
			if known[dep] && dep != id {
				out = append(out, dep)
				hasParent[dep] = true
			}
		}
		slices.Sort(out)
		out = slices.Compact(out)
		if len(out) > 0 {
			g.Edges[id] = out
			g.HasEdges = true
		}
	}
	for _, n := range g.Nodes {
		if !hasParent[n.ID] {
			g.Roots = append(g.Roots, n.ID)
		}
	}
	// A graph that is one big cycle has no root; start from everything rather than draw nothing.
	if len(g.Roots) == 0 {
		for _, n := range g.Nodes {
			g.Roots = append(g.Roots, n.ID)
		}
	}
	return g
}

func label(a lockfile.Artifact) string {
	if a.Version == "" {
		return a.Subject.Name
	}
	return a.Subject.Name + "@" + a.Version
}

// Problems keeps the packages that are not trusted, and every package that leads to one,
// so the result reads as "why is this untrusted package here".
func (g Graph) Problems() Graph {
	keep := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Status != lockfile.StatusTrusted {
			keep[n.ID] = true
		}
	}
	// Walk edges backwards until nothing new is added.
	for changed := true; changed; {
		changed = false
		for from, tos := range g.Edges {
			if keep[from] {
				continue
			}
			if slices.ContainsFunc(tos, func(to string) bool { return keep[to] }) {
				keep[from] = true
				changed = true
			}
		}
	}
	return g.restrict(keep)
}

func (g Graph) restrict(keep map[string]bool) Graph {
	out := Graph{Edges: map[string][]string{}}
	hasParent := map[string]bool{}
	for _, n := range g.Nodes {
		if keep[n.ID] {
			out.Nodes = append(out.Nodes, n)
		}
	}
	for from, tos := range g.Edges {
		if !keep[from] {
			continue
		}
		for _, to := range tos {
			if keep[to] {
				out.Edges[from] = append(out.Edges[from], to)
				hasParent[to] = true
				out.HasEdges = true
			}
		}
	}
	for _, n := range out.Nodes {
		if !hasParent[n.ID] {
			out.Roots = append(out.Roots, n.ID)
		}
	}
	if len(out.Roots) == 0 {
		for _, n := range out.Nodes {
			out.Roots = append(out.Roots, n.ID)
		}
	}
	return out
}

// Write draws the graph as "text" (a tree), "mermaid", or "dot".
func Write(w io.Writer, g Graph, format string) error {
	switch strings.ToLower(format) {
	case "text", "":
		writeTree(w, g)
	case "mermaid":
		writeMermaid(w, g)
	case "dot":
		writeDot(w, g)
	default:
		return fmt.Errorf("unsupported graph format %q: use text, mermaid, or dot", format)
	}
	return nil
}

func (g Graph) node(id string) Node {
	i, ok := slices.BinarySearchFunc(g.Nodes, id, func(n Node, id string) int { return strings.Compare(n.ID, id) })
	if !ok {
		return Node{ID: id, Label: id}
	}
	return g.Nodes[i]
}

// writeTree prints each package under its parents. A package met a second time is marked
// and not expanded again, which also stops a dependency cycle.
func writeTree(w io.Writer, g Graph) {
	if len(g.Nodes) == 0 {
		fmt.Fprintln(w, "no packages")
		return
	}
	printed := map[string]bool{}
	repeated := false
	var walk func(id, prefix string, last, top bool)
	walk = func(id, prefix string, last, top bool) {
		n := g.node(id)
		line := n.Label + "  [" + string(n.Status) + "]"
		if n.Scope != "" {
			line += " " + string(n.Scope)
		}
		again := printed[id] && len(g.Edges[id]) > 0
		if again {
			line += " (*)"
			repeated = true
		}
		switch {
		case top:
			fmt.Fprintln(w, line)
		case last:
			fmt.Fprintln(w, prefix+"└── "+line)
		default:
			fmt.Fprintln(w, prefix+"├── "+line)
		}
		printed[id] = true
		if again {
			return
		}
		childPrefix := prefix
		if !top {
			if last {
				childPrefix += "    "
			} else {
				childPrefix += "│   "
			}
		}
		kids := g.Edges[id]
		for i, kid := range kids {
			walk(kid, childPrefix, i == len(kids)-1, false)
		}
	}
	for _, root := range g.Roots {
		walk(root, "", true, true)
	}
	if !g.HasEdges {
		fmt.Fprintln(w, "\nthe lockfile records no dependency edges, so only top-level packages are listed")
		return
	}
	if repeated {
		fmt.Fprintln(w, "\n(*) already shown above")
	}
}

func writeMermaid(w io.Writer, g Graph) {
	fmt.Fprintln(w, "graph LR")
	index := map[string]string{}
	for i, n := range g.Nodes {
		index[n.ID] = "n" + strconv.Itoa(i)
		fmt.Fprintf(w, "  %s[\"%s\"]:::%s\n", index[n.ID], mermaidText(n.Label), class(n.Status))
	}
	for _, n := range g.Nodes {
		for _, to := range g.Edges[n.ID] {
			fmt.Fprintf(w, "  %s --> %s\n", index[n.ID], index[to])
		}
	}
	fmt.Fprintln(w, "  classDef trusted fill:#d9f2e0,stroke:#2f7d4a,color:#10351e")
	fmt.Fprintln(w, "  classDef untrusted fill:#f9d6d5,stroke:#b3261e,color:#410e0b")
	fmt.Fprintln(w, "  classDef unknown fill:#fdf0c8,stroke:#8a6d00,color:#3d2f00")
}

func writeDot(w io.Writer, g Graph) {
	fmt.Fprintln(w, "digraph securock {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=filled];")
	for _, n := range g.Nodes {
		fmt.Fprintf(w, "  %s [label=%s, fillcolor=%q];\n", strconv.Quote(n.ID), strconv.Quote(n.Label), fill(n.Status))
	}
	for _, n := range g.Nodes {
		for _, to := range g.Edges[n.ID] {
			fmt.Fprintf(w, "  %s -> %s;\n", strconv.Quote(n.ID), strconv.Quote(to))
		}
	}
	fmt.Fprintln(w, "}")
}

// class names the style of a status. Anything that is not trusted or untrusted is drawn
// as unknown, so a status this code does not know is never drawn as trusted.
func class(s lockfile.Status) string {
	switch s {
	case lockfile.StatusTrusted, lockfile.StatusUntrusted:
		return string(s)
	default:
		return string(lockfile.StatusUnknown)
	}
}

func fill(s lockfile.Status) string {
	switch class(s) {
	case "trusted":
		return "#d9f2e0"
	case "untrusted":
		return "#f9d6d5"
	default:
		return "#fdf0c8"
	}
}

// mermaidText keeps a label inside its quotes: a double quote would end the string.
func mermaidText(s string) string {
	return strings.NewReplacer(`"`, "#quot;", "\n", " ").Replace(s)
}
