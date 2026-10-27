// SPDX-License-Identifier: BUSL-1.1

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
	"strings"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/signing"
)

func main() {
	// The runtime distrust list guards the process default transport too (eMudhra, Part 2).
	netsec.HardenProcessDefaults()
	showVersion := flag.Bool("version", false, "print version information and exit")
	fipsRequired := flag.Bool("fips", false, "require an active Go FIPS 140-3 module before the signer loads or serves keys")
	socket := flag.String("socket", "", "path to the Unix domain socket to listen on (single-node/sidecar transport)")
	keystore := flag.String("keystore", "", "directory for sealed key persistence; keys survive a restart (R3.2)")
	kekFile := flag.String("kek", "", "path to the key-encryption key file that seals persisted keys (required with --keystore)")
	kmsProvider := flag.String("kms-provider", "", "external KMS/HSM provider for signer keystore DEK wrapping (awskms|gcpkms|azurekv|pkcs11)")
	kmsKeyRef := flag.String("kms-key-ref", "", "external KMS/HSM key identifier used by the signer keystore wrapper")
	kmsWrapCommand := flag.String("kms-wrap-command", "", "absolute path to signer-local KMS/HSM wrapper command; receives wrap|unwrap provider keyRef and DEK bytes on stdin")
	kmsTimeout := flag.Duration("kms-timeout", 10*time.Second, "deadline for each external KMS/HSM wrap/unwrap operation")
	managedKeysConfig := flag.String("managed-keys-config", "", "path to signer-local managed-key provider JSON (credentials must be file references, never argv/env)")
	tenantKEKConfig := flag.String("tenant-kek-config", "", "path to signer-local tenant KEK custody JSON: the PKCS#11 token and the HSM AES keys that wrap tenant domain KEKs (credentials must be file references)")
	authSecret := flag.String("auth-secret", "", "path to the signer content-authorization secret (required for dual-control CA handles)")
	legacyAuditKey := flag.String("legacy-audit-key", "", "signer-local path to a historical audit PKCS#8 PEM; migrated once into the sealed audit-export handle, then deleted")
	offlineInitPolicy := flag.String("offline-init-policy", "", "initialize a separate sealed offline recovery authority from a public policy JSON file")
	offlineCATTL := flag.Duration("offline-ca-ttl", 365*24*time.Hour, "lifetime of a newly initialized offline recovery CA")
	offlineIssueRequest := flag.String("offline-issue-request", "", "signed offline recovery request JSON; runs one-shot without the control plane")
	offlineIssueApprovals := flag.String("offline-issue-approvals", "", "JSON list of independently signed custodian approvals")
	offlineApproveRequest := flag.String("offline-approve-request", "", "request JSON to approve using a custodian key held only by this signer process")
	offlineApproveKey := flag.String("offline-approve-key", "", "0600 PEM private key for --offline-approve-request")
	offlineApproveCustodian := flag.String("offline-approve-custodian", "", "enrolled custodian ID for --offline-approve-request")
	offlineGenerateCustodian := flag.String("offline-generate-custodian", "", "generate a distinct custodian signing key and public roster entry")
	offlineCustodianPrivateOut := flag.String("offline-custodian-private-out", "", "0600 output path for a new custodian private key")
	offlineCustodianPublicOut := flag.String("offline-custodian-public-out", "", "output path for a new public custodian roster entry")
	offlinePrepareKit := flag.String("offline-prepare-kit", "", "public offline kit JSON used to prepare an exact request")
	offlinePrepareCSR := flag.String("offline-prepare-csr", "", "signed PKCS#10 CSR PEM used in an offline request")
	offlinePrepareRequester := flag.String("offline-prepare-requester", "", "authenticated requester identity included in offline approval evidence")
	offlinePrepareSubject := flag.String("offline-prepare-subject", "", "reviewed subject, which must equal the signed CSR common name")
	offlinePrepareReason := flag.String("offline-prepare-reason", "", "incident reason bound to the offline request")
	offlinePrepareTTL := flag.Duration("offline-prepare-ttl", 10*time.Minute, "requested offline emergency certificate lifetime")
	offlineOutput := flag.String("offline-output", "", "0600 output path for an offline bundle or approval")
	pcasRecoveryMode := flag.String("pcas-recovery-mode", "", "one-shot PCAS recovery ceremony: keygen|statement|roster|approve|assemble")
	pcasRecoveryID := flag.String("pcas-recovery-id", "", "custodian ID for keygen or approve")
	pcasRecoveryKey := flag.String("pcas-recovery-key", "", "owner-only PKCS#8 private key for roster or approve")
	pcasRecoveryPrivateOut := flag.String("pcas-recovery-private-out", "", "new owner-only PKCS#8 private-key output for keygen")
	pcasRecoveryPublicOut := flag.String("pcas-recovery-public-out", "", "new public roster-entry output for keygen")
	pcasRecoveryPolicy := flag.String("pcas-recovery-policy", "", "public exact recovery policy JSON from the tenant readback")
	pcasRecoveryChain := flag.String("pcas-recovery-chain", "", "public current PCAS chain JSON")
	pcasRecoverySuccessor := flag.String("pcas-recovery-successor", "", "public signer-prepared successor JSON")
	pcasRecoveryPinnedRoot := flag.String("pcas-recovery-pinned-root", "", "independently pinned genesis trust-root public entry")
	pcasRecoveryStatement := flag.String("pcas-recovery-statement", "", "public statement JSON for approve or assemble")
	pcasRecoveryRosterSignature := flag.String("pcas-recovery-roster-signature", "", "root-signed roster JSON for assemble")
	pcasRecoveryApprovals := flag.String("pcas-recovery-approvals", "", "JSON array of separately produced custodian approvals")
	pcasRecoveryNonce := flag.String("pcas-recovery-nonce", "", "incident-unique nonce for statement; generated when omitted")
	pcasRecoveryOutput := flag.String("pcas-recovery-output", "", "new owner-only public output for statement, roster, approve or assemble")
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

	// The tagged Enterprise seam uses the license for managed-key providers.
	// Core family mechanisms, including PCAS succession, attach independently.
	licenseFile := flag.String("license", "", "path to the signed license file for Enterprise managed-key providers (BYOK); PCAS succession is included in core")
	licenseDeploymentID := flag.String("license-deployment-id", "", "stable deployment ID bound by a version 2 license")
	licenseEnvironment := flag.String("license-environment", "", "licensed deployment environment: production or non_production")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "trstctl-signer: unexpected command or argument; use --help for usage")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-signer"))
		return
	}

	offlineMode := *offlineInitPolicy != "" || *offlineIssueRequest != "" || *offlineApproveRequest != "" || *offlineGenerateCustodian != "" || *offlinePrepareKit != "" || *pcasRecoveryMode != ""
	useMTLS := *mtlsListen != ""
	if !offlineMode && !useMTLS && *socket == "" {
		fmt.Fprintln(os.Stderr, "trstctl-signer: one of --socket (UDS) or --mtls-listen (cross-node mTLS) is required")
		os.Exit(2)
	}
	if useMTLS && *socket != "" {
		// A single listener (AN-4): refuse an ambiguous both-transports invocation
		// rather than silently picking one.
		fmt.Fprintln(os.Stderr, "trstctl-signer: --socket and --mtls-listen are mutually exclusive (the signer has one listener)")
		os.Exit(2)
	}
	if offlineMode && (*socket != "" || useMTLS) {
		fmt.Fprintln(os.Stderr, "trstctl-signer: offline one-shot mode cannot serve a signing socket")
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
	// The signer is a separate process, so the control plane's startup check
	// cannot prove the module loaded here. Assert this process's module before
	// opening a key store or listening, and always run the boundary KAT.
	if _, err := crypto.PowerOnSelfTest(*fipsRequired || signerFIPSEnvRequired(os.Getenv("TRSTCTL_FIPS"))); err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: crypto power-on self-test: %v\n", err)
		os.Exit(1)
	}
	if offlineMode {
		if *pcasRecoveryMode != "" {
			if *offlineInitPolicy != "" || *offlineIssueRequest != "" || *offlineApproveRequest != "" || *offlineGenerateCustodian != "" || *offlinePrepareKit != "" {
				fmt.Fprintln(os.Stderr, "trstctl-signer: PCAS and break-glass one-shot modes are mutually exclusive")
				os.Exit(2)
			}
			if err := runOfflinePCASRecovery(pcasOfflineOptions{Mode: *pcasRecoveryMode, ID: *pcasRecoveryID,
				PrivateKey: *pcasRecoveryKey, PrivateOut: *pcasRecoveryPrivateOut, PublicOut: *pcasRecoveryPublicOut,
				PolicyFile: *pcasRecoveryPolicy, ChainFile: *pcasRecoveryChain, SuccessorFile: *pcasRecoverySuccessor,
				PinnedRootFile: *pcasRecoveryPinnedRoot, StatementFile: *pcasRecoveryStatement,
				RosterSignatureFile: *pcasRecoveryRosterSignature, ApprovalsFile: *pcasRecoveryApprovals,
				Nonce: *pcasRecoveryNonce, Output: *pcasRecoveryOutput}); err != nil {
				fmt.Fprintf(os.Stderr, "trstctl-signer: PCAS recovery ceremony: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if *offlinePrepareKit != "" {
			if *offlineInitPolicy != "" || *offlineIssueRequest != "" || *offlineApproveRequest != "" || *offlineGenerateCustodian != "" {
				fmt.Fprintln(os.Stderr, "trstctl-signer: choose one offline mode")
				os.Exit(2)
			}
			if err := runOfflinePrepare(*offlinePrepareKit, *offlinePrepareCSR, *offlinePrepareRequester,
				*offlinePrepareSubject, *offlinePrepareReason, *offlinePrepareTTL, *offlineOutput); err != nil {
				fmt.Fprintf(os.Stderr, "trstctl-signer: offline preparation: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if err := runOfflineBreakglass(*offlineInitPolicy, *offlineCATTL, *offlineIssueRequest,
			*offlineIssueApprovals, *offlineApproveRequest, *offlineApproveKey,
			*offlineApproveCustodian, *offlineGenerateCustodian, *offlineCustodianPrivateOut,
			*offlineCustodianPublicOut, *offlineOutput, *keystore, *kekFile,
			*kmsProvider, *kmsKeyRef, *kmsWrapCommand, *kmsTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: offline recovery: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Verify any supplied license before the Enterprise managed-key attach seam.
	// An absent license leaves those providers unavailable; core families still attach.
	var lic *license.Manager
	if *licenseFile != "" {
		m, err := loadSignerLicense(*licenseFile, license.DeploymentIdentity{
			ID:          *licenseDeploymentID,
			Environment: license.Environment(*licenseEnvironment),
		}, license.TrustedKeys())
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: load license: %v\n", err)
			os.Exit(1)
		}
		lic = m
	}

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
	managedOpts, err := appendManagedKeyOptions(opts, lic, *managedKeysConfig, *keystore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: configure managed-key provider: %v\n", err)
		os.Exit(1)
	}
	opts = managedOpts
	opts, err = appendTenantKEKOptions(opts, lic, *tenantKEKConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-signer: configure tenant KEK custody: %v\n", err)
		os.Exit(1)
	}
	// With a key store, persist keys sealed at rest so a restart preserves the
	// issuing CA instead of silently rotating it (R3.2). Without one, keys are
	// in-memory only.
	var srv *signing.Server
	var wrapper seal.KeyWrapper
	cleanup := func() {}
	if *keystore != "" {
		var err error
		wrapper, cleanup, err = signerKeystoreWrapper(*kekFile, *kmsProvider, *kmsKeyRef, *kmsWrapCommand, *kmsTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: configure key store wrapper: %v\n", err)
			os.Exit(1)
		}
	}
	defer cleanup()
	opts = appendFamilyOptions(opts, *keystore, wrapper)
	if *keystore != "" {
		var err error
		srv, err = signing.NewPersistentServer(signing.NewKeyStore(*keystore, wrapper), opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: open key store: %v\n", err)
			os.Exit(1)
		}
	} else {
		srv = signing.NewServer(opts...)
	}
	if *legacyAuditKey != "" {
		if _, err := srv.MigrateLegacySigningKeyFile(*legacyAuditKey, "audit-export", []signing.KeyPurpose{signing.PurposeAuditEvidence}); err != nil {
			fmt.Fprintf(os.Stderr, "trstctl-signer: migrate legacy audit key: %v\n", err)
			os.Exit(1)
		}
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

func signerFIPSEnvRequired(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func loadSignerLicense(path string, identity license.DeploymentIdentity, trustedPubPEMs [][]byte) (*license.Manager, error) {
	return license.LoadForDeployment(path, trustedPubPEMs, identity)
}

// probeKeystoreWrapper wraps and unwraps a random value through the external
// KMS/HSM adapter before the signer serves. The key store reports any unwrap
// failure as one generic seal error, so without the probe a missing, disabled
// or unreachable key surfaces only at the first key load, without the
// adapter's reason; with it, startup stops with that reason.
func probeKeystoreWrapper(w seal.KeyWrapper) error {
	probe, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	defer secret.Wipe(probe)
	wrapped, err := w.WrapDEK(probe)
	if err != nil {
		return fmt.Errorf("external KMS custody probe: %w", err)
	}
	opened, err := w.UnwrapDEK(wrapped)
	if err != nil {
		return fmt.Errorf("external KMS custody probe: %w", err)
	}
	defer secret.Wipe(opened)
	if !crypto.ConstantTimeEqual(opened, probe) {
		return errors.New("external KMS custody probe: the adapter unwrapped a different value than it wrapped")
	}
	return nil
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
		if err := probeKeystoreWrapper(wrapper); err != nil {
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
