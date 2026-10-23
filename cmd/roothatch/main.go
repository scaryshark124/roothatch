package main

import (
	"os"

	"github.com/scaryshark124/roothatch/internal/cli"
)

var version = "0.0.0-dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
