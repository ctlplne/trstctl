// Command certctl-signer is the isolated signing service (AN-4).
//
// It is a separate, sacred process: it serves the SignerService over gRPC on a
// Unix domain socket, performs all private-key operations behind that boundary,
// and has no HTTP server, no SQL driver, and no third-party logging. In
// single-node mode the control plane launches it as a child process (see
// internal/signing.StartChild). The design is in docs/design/signing-service.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"certctl.io/certctl/internal/buildinfo"
	"certctl.io/certctl/internal/crypto/kek"
	"certctl.io/certctl/internal/signing"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	socket := flag.String("socket", "", "path to the Unix domain socket to listen on")
	keystore := flag.String("keystore", "", "directory for sealed key persistence; keys survive a restart (R3.2)")
	kekFile := flag.String("kek", "", "path to the key-encryption key file that seals persisted keys (required with --keystore)")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("certctl-signer"))
		return
	}
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "certctl-signer: --socket is required")
		os.Exit(2)
	}

	// Process-level memory protection before any key touches memory (AN-8).
	if err := signing.Harden(); err != nil {
		fmt.Fprintf(os.Stderr, "certctl-signer: harden: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// With a key store, persist keys sealed at rest so a restart preserves the
	// issuing CA instead of silently rotating it (R3.2). Without one, keys are
	// in-memory only.
	var serveErr error
	if *keystore != "" {
		if *kekFile == "" {
			fmt.Fprintln(os.Stderr, "certctl-signer: --kek is required with --keystore")
			os.Exit(2)
		}
		wrapper, err := kek.LoadOrCreate(*kekFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certctl-signer: load KEK: %v\n", err)
			os.Exit(1)
		}
		srv, err := signing.NewPersistentServer(signing.NewKeyStore(*keystore, wrapper))
		if err != nil {
			fmt.Fprintf(os.Stderr, "certctl-signer: open key store: %v\n", err)
			os.Exit(1)
		}
		serveErr = signing.ServeServer(ctx, *socket, srv)
	} else {
		serveErr = signing.Serve(ctx, *socket)
	}
	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "certctl-signer: %v\n", serveErr)
		os.Exit(1)
	}
}
