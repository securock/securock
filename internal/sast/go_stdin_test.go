package sast_test

import (
	"slices"
	"testing"
)

func TestGoStandardInputAndExecVariants(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"fmt.Scanln fills its arguments", `package main
import ("database/sql"; "fmt")
func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	var name string
	fmt.Scanln(&name)
	db.Query("SELECT * FROM t WHERE n = '" + name + "'")
}`, []string{"sast:go/sql-injection"}},
		{"bufio reader on stdin", `package main
import ("bufio"; "net/http"; "os")
func main() {
	in := bufio.NewReader(os.Stdin)
	u, _ := in.ReadString('\n')
	http.Get(u)
}`, []string{"sast:go/ssrf"}},
		{"bufio reader on a file is not input", `package main
import ("bufio"; "net/http"; "os")
func main() {
	f, _ := os.Open("urls.txt")
	in := bufio.NewReader(f)
	u, _ := in.ReadString('\n')
	http.Get(u)
}`, nil},
		{"pq.QuoteIdentifier sanitizes", `package main
import ("database/sql"; "fmt"; "os"; "github.com/lib/pq")
func main() {
	db, _ := sql.Open("postgres", "x")
	db.Query(fmt.Sprintf("SELECT * FROM %s", pq.QuoteIdentifier(os.Args[1])))
}`, nil},
		{"execabs.Command", `package main
import ("os"; exec "golang.org/x/sys/execabs")
func main() {
	exec.Command("sh", "-c", os.Args[1]).Run()
}`, []string{"sast:go/command-injection"}},
		{"syscall.ForkExec", `package main
import ("os"; "syscall")
func main() {
	syscall.ForkExec(os.Args[1], nil, nil)
}`, []string{"sast:go/command-injection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(t, map[string]string{"main.go": tt.src})
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
