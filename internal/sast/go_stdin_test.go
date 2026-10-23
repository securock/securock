package sast_test

import (
	"slices"
	"testing"
)

func TestGoStandardInputExecAndCryptoVariants(t *testing.T) {
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
		{"aes key as a byte conversion", `package main
import "crypto/aes"
func main() { aes.NewCipher([]byte("0123456789abcdef")) }`, []string{"sast:go/hardcoded-key"}},
		{"aes key as a constant", `package main
import "crypto/aes"
const key = "0123456789abcdef"
func main() { aes.NewCipher([]byte(key)) }`, []string{"sast:go/hardcoded-key"}},
		{"aes key from the environment", `package main
import ("crypto/aes"; "os")
func main() { aes.NewCipher([]byte(os.Getenv("KEY"))) }`, nil},
		{"hmac key literal", `package main
import ("crypto/hmac"; "crypto/sha256")
func main() { hmac.New(sha256.New, []byte("shared-secret")) }`, []string{"sast:go/hardcoded-key"}},
		{"rsa key too small", `package main
import ("crypto/rand"; "crypto/rsa")
func main() { rsa.GenerateKey(rand.Reader, 1<<10) }`, []string{"sast:go/weak-crypto"}},
		{"rsa 2048 is fine", `package main
import ("crypto/rand"; "crypto/rsa")
func main() { rsa.GenerateKey(rand.Reader, 2048) }`, nil},
		{"tls MinVersion assigned low", `package main
import "crypto/tls"
func main() { cfg := &tls.Config{}; cfg.MinVersion = tls.VersionTLS10; _ = cfg }`, []string{"sast:go/tls-verification-disabled"}},
		{"tls MaxVersion low", `package main
import "crypto/tls"
func main() { _ = &tls.Config{MaxVersion: tls.VersionTLS11} }`, []string{"sast:go/tls-verification-disabled"}},
		{"tls 1.2 is fine", `package main
import "crypto/tls"
func main() { cfg := &tls.Config{MinVersion: tls.VersionTLS12}; cfg.MaxVersion = tls.VersionTLS13 }`, nil},
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
