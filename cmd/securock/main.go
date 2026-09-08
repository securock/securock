package main

import "github.com/securock/securock/internal/cli"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.Execute(version, commit, date)
}
