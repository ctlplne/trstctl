// Command certctl-signer is the isolated signing service (AN-4).
//
// It is a separate, sacred process: reached over gRPC on a Unix domain socket
// (or mTLS across nodes), with no HTTP server, no SQL driver, no third-party
// logging, and a minimal, fully-audited transport dependency. It is never run
// in-process with the control plane.
//
// The implementation lands in sprint S1.4 (after the S1.3 design spike). For
// sprint S0.1 this is a compile-clean placeholder that reports its version and
// otherwise exits without doing key operations. It intentionally depends only
// on the standard library and internal/buildinfo.
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
		fmt.Println(buildinfo.String("certctl-signer"))
		return
	}

	fmt.Fprintln(os.Stdout, "certctl-signer: not yet implemented (tracked by sprint S1.4)")
}
