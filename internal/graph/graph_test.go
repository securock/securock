package graph_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/securock/securock/internal/graph"
	"github.com/securock/securock/pkg/lockfile"
)

func art(name string, status lockfile.Status, deps ...string) lockfile.Artifact {
	return lockfile.Artifact{
		Subject:      lockfile.Subject{Ecosystem: "npm", Name: name},
		Version:      "1.0.0",
		Scope:        lockfile.ScopeRuntime,
		Dependencies: deps,
		Trust:        lockfile.Trust{Status: status},
	}
}

func id(name string) string { return "npm:" + name + "@1.0.0" }

func doc(arts ...lockfile.Artifact) lockfile.Document { return lockfile.Document{Artifacts: arts} }

func render(t *testing.T, g graph.Graph, format string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := graph.Write(&buf, g, format); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestBuildFindsRootsAndDropsDanglingEdges(t *testing.T) {
	g := graph.Build(doc(
		art("b", lockfile.StatusTrusted),
		art("a", lockfile.StatusTrusted, id("b"), id("missing"), id("a")),
	))
	if len(g.Roots) != 1 || g.Roots[0] != id("a") {
		t.Fatalf("roots = %v", g.Roots)
	}
	if got := g.Edges[id("a")]; len(got) != 1 || got[0] != id("b") {
		t.Fatalf("edges = %v", got)
	}
	if !g.HasEdges {
		t.Fatal("HasEdges should be set")
	}
}

func TestBuildWithoutEdgesSaysSo(t *testing.T) {
	g := graph.Build(doc(art("a", lockfile.StatusTrusted), art("b", lockfile.StatusTrusted)))
	if g.HasEdges || len(g.Roots) != 2 {
		t.Fatalf("graph = %+v", g)
	}
	if out := render(t, g, "text"); !strings.Contains(out, "records no dependency edges") {
		t.Fatalf("a flat graph must say edges are unknown:\n%s", out)
	}
}

func TestTreeMarksRepeatsAndSurvivesCycles(t *testing.T) {
	g := graph.Build(doc(
		art("app", lockfile.StatusTrusted, id("x"), id("y")),
		art("x", lockfile.StatusTrusted, id("shared")),
		art("y", lockfile.StatusTrusted, id("shared")),
		art("shared", lockfile.StatusTrusted, id("x")),
	))
	out := render(t, g, "text")
	if strings.Count(out, "shared@1.0.0") != 2 || !strings.Contains(out, "(*)") {
		t.Fatalf("repeated package should be marked and not expanded:\n%s", out)
	}
	if !strings.Contains(out, "├── x@1.0.0") || !strings.Contains(out, "└── y@1.0.0") {
		t.Fatalf("unexpected tree:\n%s", out)
	}
}

func TestProblemsKeepsPathsToUntrustedPackages(t *testing.T) {
	g := graph.Build(doc(
		art("app", lockfile.StatusTrusted, id("good"), id("mid")),
		art("good", lockfile.StatusTrusted),
		art("mid", lockfile.StatusTrusted, id("bad")),
		art("bad", lockfile.StatusUntrusted),
		art("other", lockfile.StatusUnknown),
	)).Problems()
	var names []string
	for _, n := range g.Nodes {
		names = append(names, n.Label)
	}
	if got := strings.Join(names, ","); got != "app@1.0.0,bad@1.0.0,mid@1.0.0,other@1.0.0" {
		t.Fatalf("nodes = %s", got)
	}
	if strings.Contains(render(t, g, "text"), "good") {
		t.Fatal("a trusted package off the path must be dropped")
	}
}

func TestMermaid(t *testing.T) {
	g := graph.Build(doc(art(`we"ird`, lockfile.StatusUntrusted, id("b")), art("b", lockfile.Status("surprise"))))
	out := render(t, g, "mermaid")
	for _, want := range []string{
		"graph LR",
		`n0["b@1.0.0"]:::unknown`, // a status the graph does not know is never drawn as trusted
		`n1["we#quot;ird@1.0.0"]:::untrusted`,
		"n1 --> n0",
		"classDef untrusted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDot(t *testing.T) {
	g := graph.Build(doc(art("a", lockfile.StatusTrusted, id("b")), art("b", lockfile.StatusUnknown)))
	out := render(t, g, "dot")
	for _, want := range []string{
		"digraph securock {",
		`"npm:a@1.0.0" [label="a@1.0.0", fillcolor="#d9f2e0"];`,
		`"npm:b@1.0.0" [label="b@1.0.0", fillcolor="#fdf0c8"];`,
		`"npm:a@1.0.0" -> "npm:b@1.0.0";`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	d := doc(art("c", lockfile.StatusTrusted), art("a", lockfile.StatusTrusted, id("c"), id("b")), art("b", lockfile.StatusTrusted))
	for _, format := range []string{"text", "mermaid", "dot"} {
		first := render(t, graph.Build(d), format)
		for range 5 {
			if render(t, graph.Build(d), format) != first {
				t.Fatalf("%s output changed between runs", format)
			}
		}
	}
}

func TestUnsupportedFormat(t *testing.T) {
	if err := graph.Write(&bytes.Buffer{}, graph.Graph{}, "svg"); err == nil {
		t.Fatal("expected an error")
	}
}
