package sast_test

import (
	"github.com/securock/securock/internal/sast"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDirectCallReachabilityAndUnknownAlternatives(t *testing.T) {
	d := t.TempDir()
	source := `package main
import "fmt"
func main(){helper()}
func helper(){fmt.Println("hello")}
func unused(){fmt.Printf("unused")}
func hidden(){ callback:=func(){fmt.Sprintf("hidden")}; _=callback }
`
	os.WriteFile(filepath.Join(d, "main.go"), []byte(source), 0600)
	symbols := []sast.Symbol{{ID: "ADV-1", Name: "fmt.Println"}, {ID: "ADV-2", Name: "fmt.Printf"}, {ID: "ADV-3", Name: "fmt.Sprintf"}}
	a, err := sast.Calls(d, []string{"main.main"}, symbols)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sast.Calls(d, []string{"main.main"}, symbols)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic graph", err)
	}
	states := map[string]string{}
	for _, f := range a.Findings {
		states[f.Subject] = f.ID
		if f.ID == "reachability:symbol-reachable" && len(f.Trace) != 2 {
			t.Fatalf("missing helper path: %+v", f)
		}
	}
	if states["ADV-1/fmt.Println"] != "reachability:symbol-reachable" || states["ADV-2/fmt.Printf"] != "reachability:symbol-unknown" || states["ADV-3/fmt.Sprintf"] != "reachability:symbol-unknown" {
		t.Fatal(states)
	}
	r, err := sast.Calls(d, []string{"missing.entry"}, symbols)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "reachability:entry-unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing entrypoint was silently accepted")
	}
}
