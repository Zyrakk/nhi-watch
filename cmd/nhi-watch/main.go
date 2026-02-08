// NHI-Watch — Discover, audit and score Non-Human Identities
// in Kubernetes and OpenShift clusters.
//
// This is the CLI entry point. All business logic lives in internal/.
package main

import (
	"fmt"
	"os"

	"github.com/Zyrakk/nhi-watch/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
