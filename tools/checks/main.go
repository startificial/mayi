// Command checks enforces Mayi's repository boundaries and dependency policy.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "repository root")
	only := flag.String("only", "all", "check to run: all, architecture, licenses")
	flag.Parse()
	abs, err := filepath.Abs(*root)
	if err == nil {
		switch *only {
		case "all":
			err = errors.Join(checkArchitecture(abs), checkDependencies(abs))
		case "architecture":
			err = checkArchitecture(abs)
		case "licenses":
			err = checkDependencies(abs)
		default:
			err = fmt.Errorf("unknown check %q", *only)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Repository checks passed (%s).\n", *only)
}
