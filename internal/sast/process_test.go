package sast_test

import (
	"slices"
	"testing"
)

func TestPythonExplicitShell(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		bad        bool
	}{
		{"shell literal", `subprocess.run(['/bin/sh', '-c', value])`, true},
		{"combined shell flags", `subprocess.check_output(['/bin/bash', '-lc', value])`, true},
		{"keyword argv", `subprocess.Popen(args=['sh', '-c', value])`, true},
		{"normal argv", `subprocess.run(['echo', value])`, false},
		{"shell positional data", `subprocess.run(['sh', '-c', 'echo "$1"', 'name', value])`, false},
		{"script argument without command mode", `subprocess.run(['sh', '/srv/task.sh', value])`, false},
		{"built argv", "argv = []\n    argv.append('sh')\n    argv.append('-c')\n    argv.append(value)\n    subprocess.run(argv)", true},
		{"conditional shell choice", "argv = []\n    if flag:\n        argv.append('cmd.exe')\n        argv.append('/c')\n    else:\n        argv.append('sh')\n        argv.append('-c')\n    argv.append(value)\n    subprocess.run(argv)", true},
		{"overwritten program", "argv = ['sh', '-c', value]\n    argv[0] = 'echo'\n    subprocess.run(argv)", false},
		{"overwritten script", "argv = ['sh', '-c', value]\n    argv[2] = 'echo fixed'\n    subprocess.run(argv)", false},
		{"new script assignment", "argv = ['sh', '-c', 'echo fixed']\n    argv[2] = value\n    subprocess.run(argv)", true},
		{"cmd parses remaining arguments", `subprocess.run(['cmd.exe', '/c', 'echo', value])`, true},
		{"powershell parses remaining arguments", `subprocess.run(['pwsh', '-Command', 'Write-Output', value])`, true},
		{"executable override", `subprocess.run(['tool', '-c', value], executable='/bin/sh')`, true},
		{"non-shell executable override", `subprocess.run(['sh', '-c', value], executable='/bin/echo')`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "import subprocess\nfrom flask import request\ndef route(flag):\n    value = request.args['command']\n    " + tt.body + "\n"
			var want []string
			if tt.bad {
				want = []string{"sast:py/command-injection"}
			}
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}
