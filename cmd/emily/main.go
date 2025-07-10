package main

import (
	"fmt"
	"os"

	"github.com/null/emily/internal/cli"
)

// These can be overridden at build time with -ldflags
var (
	version = "1.0.0"
	commit  = "a753988"
	date    = "2025-07-10"
)

func main() {
	if err := cli.Execute(version, commit, date); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
