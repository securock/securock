package reachability_test

import (
	"reflect"
	"testing"

	"github.com/securock/securock/internal/reachability"
	"github.com/securock/securock/pkg/lockfile"
)

func art(name string, scope lockfile.Scope, deps []string, vulns ...string) lockfile.Artifact {
	a := lockfile.Artifact{
		Subject:      lockfile.Subject{Ecosystem: "npm", Name: name},
		Version:      "1.0.0",
		Scope:        scope,
		Dependencies: deps,
	}
	a.Evidence.Vulnerabilities.State = lockfile.VulnChecked
	for _, id := range vulns {
		a.Evidence.Vulnerabilities.Items = append(a.Evidence.Vulnerabilities.Items, lockfile.Vulnerability{ID: id})
	}
	return a
}

func annotate(arts ...lockfile.Artifact) map[string]lockfile.Vulnerability {
	doc := lockfile.Document{Artifacts: arts}
	reachability.Annotate(&doc)
	out := map[string]lockfile.Vulnerability{}
	for _, a := range doc.Artifacts {
		for _, v := range a.Evidence.Vulnerabilities.Items {
			out[v.ID] = v
		}
	}
	return out
}

func TestRuntimePackageIsReachable(t *testing.T) {
	got := annotate(art("a", lockfile.ScopeRuntime, nil, "V-A"))
	if got["V-A"].Reachable != lockfile.ReachYes || got["V-A"].Via != nil {
		t.Fatalf("direct runtime package: %+v", got["V-A"])
	}
}

func TestTransitivePackageRecordsShortestPath(t *testing.T) {
	got := annotate(
		art("app", lockfile.ScopeRuntime, []string{"npm:mid@1.0.0", "npm:leaf@1.0.0"}),
		art("mid", "", []string{"npm:leaf@1.0.0"}),
		art("leaf", "", nil, "V-LEAF"),
		art("deep", "", nil, "V-DEEP"),
	)
	want := []string{"npm:app@1.0.0", "npm:leaf@1.0.0"}
	if v := got["V-LEAF"]; v.Reachable != lockfile.ReachYes || !reflect.DeepEqual(v.Via, want) {
		t.Fatalf("V-LEAF = %+v, want yes via %v", v, want)
	}
	if v := got["V-DEEP"]; v.Reachable != lockfile.ReachUnknown {
		t.Fatalf("a package with no scope and no path stays unknown: %+v", v)
	}
}

func TestDevOnlyPackageIsNotReachable(t *testing.T) {
	got := annotate(
		art("app", lockfile.ScopeRuntime, []string{"npm:lib@1.0.0"}),
		art("lib", lockfile.ScopeRuntime, nil),
		art("jest", lockfile.ScopeDev, []string{"npm:jest-util@1.0.0"}),
		art("jest-util", lockfile.ScopeDev, nil, "V-DEV"),
	)
	if v := got["V-DEV"]; v.Reachable != lockfile.ReachNo || v.Via != nil {
		t.Fatalf("V-DEV = %+v", v)
	}
}

func TestRuntimePathOverridesDevScope(t *testing.T) {
	got := annotate(
		art("app", lockfile.ScopeRuntime, []string{"npm:shared@1.0.0"}),
		art("shared", lockfile.ScopeDev, nil, "V-SHARED"),
	)
	if v := got["V-SHARED"]; v.Reachable != lockfile.ReachYes {
		t.Fatalf("a package a runtime package depends on is reachable whatever its flag says: %+v", v)
	}
}

func TestOptionalAndUnscopedStayUnknown(t *testing.T) {
	got := annotate(
		art("fsevents", lockfile.ScopeOptional, nil, "V-OPT"),
		art("plain", "", nil, "V-PLAIN"),
	)
	for _, id := range []string{"V-OPT", "V-PLAIN"} {
		if got[id].Reachable != lockfile.ReachUnknown {
			t.Fatalf("%s = %+v, want unknown", id, got[id])
		}
	}
}

func TestUncheckedVulnerabilitiesAreLeftAlone(t *testing.T) {
	a := art("a", lockfile.ScopeRuntime, nil, "V-A")
	a.Evidence.Vulnerabilities.State = lockfile.VulnUnknown
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{a}}
	reachability.Annotate(&doc)
	if got := doc.Artifacts[0].Evidence.Vulnerabilities.Items[0].Reachable; got != "" {
		t.Fatalf("reachable = %q for an unchecked artifact", got)
	}
}

func TestCyclesAndDanglingEdgesTerminate(t *testing.T) {
	got := annotate(
		art("a", lockfile.ScopeRuntime, []string{"npm:b@1.0.0", "npm:ghost@9.9.9"}),
		art("b", "", []string{"npm:a@1.0.0", "npm:c@1.0.0"}),
		art("c", "", []string{"npm:b@1.0.0"}, "V-C"),
	)
	if v := got["V-C"]; v.Reachable != lockfile.ReachYes || len(v.Via) != 3 {
		t.Fatalf("V-C = %+v", v)
	}
}

func TestAnnotateIsDeterministic(t *testing.T) {
	build := func() []lockfile.Artifact {
		return []lockfile.Artifact{
			art("r1", lockfile.ScopeRuntime, []string{"npm:t@1.0.0"}),
			art("r2", lockfile.ScopeRuntime, []string{"npm:t@1.0.0"}),
			art("t", "", nil, "V-T"),
		}
	}
	first := annotate(build()...)
	for i := 0; i < 20; i++ {
		if got := annotate(build()...); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs: %+v vs %+v", i, got, first)
		}
	}
	if first["V-T"].Via[0] != "npm:r1@1.0.0" {
		t.Fatalf("ties break by sorted order: %+v", first["V-T"])
	}
}

func TestPathStartsAtTheTopOfTheRuntimePackages(t *testing.T) {
	// A lockfile that marks every installed package runtime, as npm does.
	got := annotate(
		art("app-lib", lockfile.ScopeRuntime, []string{"npm:mid@1.0.0"}),
		art("mid", lockfile.ScopeRuntime, []string{"npm:leaf@1.0.0"}),
		art("leaf", lockfile.ScopeRuntime, nil, "V-LEAF"),
		art("standalone", lockfile.ScopeRuntime, nil, "V-ALONE"),
	)
	want := []string{"npm:app-lib@1.0.0", "npm:mid@1.0.0", "npm:leaf@1.0.0"}
	if v := got["V-LEAF"]; v.Reachable != lockfile.ReachYes || !reflect.DeepEqual(v.Via, want) {
		t.Fatalf("V-LEAF = %+v, want yes via %v", v, want)
	}
	if v := got["V-ALONE"]; v.Reachable != lockfile.ReachYes || v.Via != nil {
		t.Fatalf("a runtime package nobody depends on is its own top: %+v", v)
	}
}

func TestRuntimeCycleWithoutATopIsStillReachable(t *testing.T) {
	got := annotate(
		art("a", lockfile.ScopeRuntime, []string{"npm:b@1.0.0"}, "V-A"),
		art("b", lockfile.ScopeRuntime, []string{"npm:a@1.0.0"}, "V-B"),
	)
	for _, id := range []string{"V-A", "V-B"} {
		if got[id].Reachable != lockfile.ReachYes {
			t.Fatalf("%s = %+v", id, got[id])
		}
	}
}
