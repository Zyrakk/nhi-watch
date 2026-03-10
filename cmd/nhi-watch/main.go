// NHI-Watch — Discover, audit and score Non-Human Identities
// in Kubernetes and OpenShift clusters.
//
// This is the CLI entry point. All business logic lives in internal/.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Zyrakk/nhi-watch/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		var exitErr *cli.ExitCodeError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, exitErr.Message)
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
