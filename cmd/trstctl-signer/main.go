// Command trstctl-signer is the isolated signing service (AN-4).
//
// It is a separate, sacred process: it serves the SignerService over gRPC on a
// Unix domain socket, performs all private-key operations behind that boundary,
// and has no HTTP server, no SQL driver, and no third-party logging. In
// single-node mode the control plane launches it as a child process (see
// internal/signing.StartChild). The design is in docs/design/signing-service.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	socket := flag.String("socket", "", "path to the Unix domain socket to listen on (single-node/sidecar transport)")
	keystore := flag.String("keystore", "", "directory for sealed key persistence; keys survive a restart (R3.2)")
	kekFile := flag.String("kek", "", "path to the key-encryption key file that seals persisted keys (required with --keystore)")
	kmsProvider := flag.String("kms-provider", "", "external KMS/HSM provider for signer keystore DEK wrapping (awskms|gcpkms|azurekv|pkcs11)")
	kmsKeyRef := flag.String("kms-key-ref", "", "external KMS/HSM key identifier used by the signer keystore wrapper")
	kmsWrapCommand := flag.String("kms-wrap-command", "", "absolute path to signer-local KMS/HSM wrapper command; receives wrap|unwrap provider keyRef and DEK bytes on stdin")
	kmsTimeout := flag.Duration("kms-timeout", 10*time.Second, "deadline for each external KMS/HSM wrap/unwrap operation")
	authSecret := flag.String("auth-secret", "", "path to the signer content-authorization secret (required for dual-control CA handles)")
	allowInsecureDevNonLinux := flag.Bool("allow-insecure-dev-nonlinux", false, "development-only: allow signer startup on non-Linux where process hardening, UDS peer UID checks, and locked memory are unavailable")

	// Cross-node mTLS transport (AN-4 multi-node mode, SIGNER-005 / design §3,§5.2).
	// When --mtls-listen is set the signer serves the SAME gRPC SignerService over
	// a mutually-authenticated, mutually-pinned TLS 1.3 channel instead of the UDS,
	// so a separately-hosted signer pod is reachable across nodes. It remains AN-4:
	// no HTTP server, no SQL driver — mTLS is only a transport credential.
	mtlsListen := flag.String("mtls-listen", "", "host:port to serve the cross-node mTLS gRPC channel on (e.g. :9443); alternative to --socket")
	mtlsCert := flag.String("mtls-cert", "", "PEM certificate the signer presents on the mTLS channel (required with --mtls-listen)")
	mtlsKey := flag.String("mtls-key", "", "PEM private key for --mtls-cert (required with --mtls-listen)")
	mtlsPeerCA := flag.String("mtls-peer-ca", "", "PEM CA bundle that anchors the control plane's client certificate (required with --mtls-listen)")
	mtlsPeerPin := flag.String("mtls-peer-pin", "", "hex SHA-256 of the control plane client certificate's public key, pinned both ways (required with --mtls-listen)")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-signer"))
		return
	}

	useMTLS := *mtlsListen != ""
	if !useMTLS && *socket == "" {
		fmt.Fprintln(os.Stderr, "trstctl-signer: one of --socket (UDS) or --mtls-listen (cross-node mTLS) is required")
		os.Exit(2)
	}
	if useMTLS && *socket != "" {
		// A single listener (AN-4): refuse an ambiguous both-transports invocation
		// rather than silently picking one.
		fmt.Fprintln(os.Stderr, "trstctl-signer: --socket and --mtls-listen are mutually exclusive (the signer has one listener)")
		os.Exit(2)
	}

	// Process-level memory protection before any key touches memory (AN-8).
	if err := signing.Harden(); err != nil {
		if !*allowInsecureDevNonLinux || !errors.Is(err, signing.ErrUnsupportedHardening) {
			fmt.Fprintf(os.Stderr, "trstctl-signer: harden: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "trstctl-signer: WARNING: non-Linux development hardening override active; process hardening, UDS peer UID checks, and locked memory are unavailable\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var opts []signing.ServerOption
	if *authSecret != "" {
		authz, err := signing.LoadOrCreateAuthorizer(*authSecret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: load sign authorizer: %v\n", err)
			os.Exit(1)
		}
		defer authz.Destroy()
		opts = append(opts, signing.WithAuthorizer(authz))
	}

	// With a key store, persist keys sealed at rest so a restart preserves the
	// issuing CA instead of silently rotating it (R3.2). Without one, keys are
	// in-memory only.
	var srv *signing.Server
	if *keystore != "" {
		wrapper, cleanup, err := signerKeystoreWrapper(*kekFile, *kmsProvider, *kmsKeyRef, *kmsWrapCommand, *kmsTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: configure key store wrapper: %v\n", err)
			os.Exit(1)
		}
		defer cleanup()
		srv, err = signing.NewPersistentServer(signing.NewKeyStore(*keystore, wrapper), opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: open key store: %v\n", err)
			os.Exit(1)
		}
	} else {
		srv = signing.NewServer(opts...)
	}

	var serveErr error
	serveOpts := signing.ServeOptions{AllowInsecureDevNonLinux: *allowInsecureDevNonLinux}
	if useMTLS {
		serveErr = signing.ServeServerMTLS(ctx, *mtlsListen, srv, mtls.SignerPeerConfig{
			CertFile:   *mtlsCert,
			KeyFile:    *mtlsKey,
			PeerCAFile: *mtlsPeerCA,
			PeerPinHex: *mtlsPeerPin,
		}, serveOpts)
	} else {
		serveErr = signing.ServeServerWithOptions(ctx, *socket, srv, serveOpts)
	}
	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: %v\n", serveErr)
		os.Exit(1)
	}
}

func signerKeystoreWrapper(kekFile, provider, keyRef, wrapCommand string, timeout time.Duration) (seal.KeyWrapper, func(), error) {
	external := provider != "" || keyRef != "" || wrapCommand != ""
	if external {
		if kekFile != "" {
			return nil, func() {}, fmt.Errorf("--kek and --kms-* are mutually exclusive for signer key-store custody")
		}
		wrapper, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
			Provider:    provider,
			KeyRef:      keyRef,
			WrapCommand: wrapCommand,
			Timeout:     timeout,
		})
		if err != nil {
			return nil, func() {}, err
		}
		return wrapper, func() {}, nil
	}
	if kekFile == "" {
		return nil, func() {}, fmt.Errorf("--kek or --kms-provider/--kms-key-ref/--kms-wrap-command is required with --keystore")
	}
	wrapper, err := kek.LoadOrCreate(kekFile)
	if err != nil {
		return nil, func() {}, fmt.Errorf("load KEK: %w", err)
	}
	return wrapper, wrapper.Destroy, nil
}
