// Package cli implements the nonprivileged Roothatch command interface.
package cli

import (
	"fmt"
	"io"
)

const usage = `Roothatch — Build it. Fix it. Boot it.

Usage: roothatch [help|version]

Only help and version are implemented in this pre-alpha foundation.
Native entry, diagnostics, image management and VM boot are not implemented.
Do not run this scaffold as root or use it to repair an installation.
`

// Run returns 0 for success, 1 for output failure, or 2 for invalid usage.
// It does not inspect targets, execute subprocesses, or require privileges.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	command := "help"
	if len(args) > 0 {
		command = args[0]
	}
	var output string
	switch command {
	case "help", "--help", "-h":
		output = usage
	case "version", "--version":
		output = "Roothatch " + version + "\n"
	default:
		fmt.Fprintf(stderr, "roothatch: unknown command %q; use 'roothatch help'\n", command)
		return 2
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "roothatch: %q does not accept arguments\n", command)
		return 2
	}
	if _, err := io.WriteString(stdout, output); err != nil {
		fmt.Fprintln(stderr, "roothatch: cannot write output")
		return 1
	}
	return 0
}
