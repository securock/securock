package cocoapods_test

import (
	"reflect"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cocoapods"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestDependencies(t *testing.T) {
	eco := cocoapods.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected Podfile.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	var order []string
	for _, dep := range deps {
		got[dep.Name] = dep
		order = append(order, dep.Name)
		if dep.Ecosystem != "cocoapods" || dep.Resolver != "cocoapods" {
			t.Fatalf("%s ecosystem/resolver = %s/%s", dep.Name, dep.Ecosystem, dep.Resolver)
		}
		if dep.Digest != "" {
			t.Fatalf("%s digest = %q, podspec checksums are not artifact digests", dep.Name, dep.Digest)
		}
	}

	wantOrder := []string{"Alamofire", "Firebase", "FirebaseAnalytics", "GitPod", "LocalPod", "PrivatePod"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %v, want %v (subspecs collapse into the root pod)", order, wantOrder)
	}

	tests := []struct {
		name     string
		version  string
		kind     string
		registry string
		artifact string
		resolved string
	}{
		{"Alamofire", "5.8.0", core.SourceRegistry, "https://cdn.cocoapods.org", "", ""},
		{"Firebase", "10.0.0", core.SourceRegistry, "https://cdn.cocoapods.org", "", ""},
		{"GitPod", "1.2.0", core.SourceGit, "", "https://github.com/acme/GitPod.git", "0123456789abcdef0123456789abcdef01234567"},
		{"LocalPod", "0.1.0", core.SourceFile, "", "", ""},
		// A private spec repo is not provably public: no registry, so nothing is queried.
		{"PrivatePod", "2.0.0", core.SourceRegistry, "", "", ""},
	}
	for _, tt := range tests {
		dep := got[tt.name]
		if dep.Version != tt.version || dep.SourceKind != tt.kind || dep.Registry != tt.registry ||
			dep.Artifact != tt.artifact || dep.Resolved != tt.resolved {
			t.Errorf("%s = %+v", tt.name, dep)
		}
	}
}

func TestDependsOn(t *testing.T) {
	deps, err := cocoapods.New().Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range deps {
		if dep.Name != "Firebase" {
			if len(dep.DependsOn) != 0 {
				t.Errorf("%s DependsOn = %v", dep.Name, dep.DependsOn)
			}
			continue
		}
		want := []string{"cocoapods:Alamofire@5.8.0", "cocoapods:FirebaseAnalytics@10.0.1"}
		if !reflect.DeepEqual(dep.DependsOn, want) {
			t.Errorf("Firebase DependsOn = %v, want %v", dep.DependsOn, want)
		}
		if dep.Scope != "" {
			t.Errorf("Firebase scope = %q, lockfile does not record one", dep.Scope)
		}
	}
}

func TestMalformed(t *testing.T) {
	dir := t.TempDir()
	if _, err := cocoapods.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for a missing lockfile")
	}
}
