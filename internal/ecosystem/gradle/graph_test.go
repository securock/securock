package gradle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/gradle"
)

func TestScopeFromConfigurations(t *testing.T) {
	dir := t.TempDir()
	lock := `# This is a Gradle generated file for dependency locking.
empty=annotationProcessor
com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:2.0.9=runtimeClasspath,testCompileClasspath,testRuntimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.mockito:mockito-core:5.0.0=testRuntimeClasspath
javax.servlet:servlet-api:3.0=compileClasspath
org.projectlombok:lombok:1.18.30=annotationProcessor,compileClasspath
com.android.tools:desugar:1.0=androidTestRuntimeClasspath
androidx.core:core:1.12.0=releaseRuntimeClasspath
`
	if err := os.WriteFile(filepath.Join(dir, "gradle.lockfile"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := gradle.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"com.google.guava:guava":    core.ScopeRuntime,
		"org.slf4j:slf4j-api":       core.ScopeRuntime,
		"junit:junit":               core.ScopeDev,
		"org.mockito:mockito-core":  core.ScopeDev,
		"com.android.tools:desugar": core.ScopeDev,
		"androidx.core:core":        core.ScopeRuntime,
		// Compile-only and annotation processor dependencies are neither shipped nor tests.
		"javax.servlet:servlet-api": "",
		"org.projectlombok:lombok":  "",
	}
	if len(list) != len(want) {
		t.Fatalf("got %d dependencies, want %d", len(list), len(want))
	}
	for _, dep := range list {
		if dep.Scope != want[dep.Name] {
			t.Errorf("%s = %q, want %q", dep.Name, dep.Scope, want[dep.Name])
		}
	}
}
