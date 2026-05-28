// Command certctl-agent is the in-network agent.
//
// The agent registers with the control plane (bootstrap token or attestation),
// communicates over mTLS with a short-lived, auto-rotating client certificate,
// and performs all key operations locally so that private keys never leave the
// host. Discovery, deployment, SSH trust, and drift reconciliation run here.
//
// The implementation begins in sprint S5.1. For sprint S0.1 this is a
// compile-clean placeholder that reports its version and otherwise exits.
package main

import (
	"flag"
	"fmt"
	"os"

	"certctl.io/certctl/internal/buildinfo"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("certctl-agent"))
		return
	}

	fmt.Fprintln(os.Stdout, "certctl-agent: not yet implemented (tracked by sprint S5.1)")
}
