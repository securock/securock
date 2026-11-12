package sast_test

import (
	"slices"
	"testing"
)

func TestPHPRegexReplacementResult(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      []string
	}{
		{"filtered subject", `<?php echo preg_replace('/<script/i', '', $_GET['name']);`, []string{"sast:php/xss"}},
		{"untrusted replacement", `<?php echo preg_replace('/hello/', $_GET['name'], 'hello');`, []string{"sast:php/xss"}},
		{"encoded result", `<?php echo htmlspecialchars(preg_replace('/<script/i', '', $_GET['name']));`, nil},
		{"constant result", `<?php echo preg_replace('/hello/', 'world', 'hello');`, nil},
		{"untrusted pattern", `<?php echo preg_replace($_GET['pattern'], '', 'hello');`, []string{"sast:php/regex-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{"app.php": tt.src}))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
