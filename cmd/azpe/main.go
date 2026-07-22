package main

import (
	"os"

	"github.com/azpe/azpe/internal/cli"
)

func main() {
	exitCode := cli.Run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
