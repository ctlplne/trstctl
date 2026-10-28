// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A220: with --edge-renew, a host agent renews its delegated edge CA over the
// agent channel when the certificate in --edge-ca-cert is within
// --edge-renew-before of expiry. The TPM key the handle names signs a fresh
// CSR, TPM2_Certify vouches for it over the new challenge, and the control
// plane renews under the same gate as a mint, where the segment's operator
// allowed renewal. The renewed chain replaces --edge-ca-cert, so --edge-issue
// moves to it. A refused renewal is logged and retried hourly; nothing is
// extended, so a delegation whose attestation keeps failing expires.

const edgeRenewRetry = time.Hour

// edgeRenewalOptions carries --edge-renew into the daemon.
type edgeRenewalOptions struct {
	edge    edgeCAOptions
	enabled bool
	before  time.Duration
}

type edgeRenewalSender interface {
	RenewEdgeDelegation(ctx context.Context, req *transport.EdgeRenewalRequest) (*transport.EdgeRenewalResponse, error)
}

// edgeRenewer decides when to renew. It is used from the agent's heartbeat
// loop only.
type edgeRenewer struct {
	certPath string
	before   time.Duration
	// prepare has the delegated CA key sign a fresh CSR and attests it.
	prepare     func(ctx context.Context) (csrDER, credentialJSON []byte, err error)
	now         func() time.Time
	lastAttempt time.Time
}

// newEdgeRenewer is nil unless --edge-renew is on.
func newEdgeRenewer(opts edgeCAOptions, enabled bool, before time.Duration) *edgeRenewer {
	if !enabled {
		return nil
	}
	if before <= 0 {
		before = 7 * 24 * time.Hour
	}
	return &edgeRenewer{certPath: opts.caCert, before: before, prepare: tpmEdgeRenewalPrepare(opts), now: time.Now}
}

// afterHeartbeat renews when the delegation is due and the last attempt is
// at least an hour old.
func (r *edgeRenewer) afterHeartbeat(ctx context.Context, sender edgeRenewalSender) {
	if r == nil {
		return
	}
	certPEM, err := os.ReadFile(r.certPath) // #nosec G304 -- operator-configured delegation certificate path on the agent's own host (CWE-22)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: edge renewal cannot read the delegation certificate:", err)
		return
	}
	facts, err := crypto.CertificateFactsFromPEM(certPEM)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: edge renewal cannot parse the delegation certificate:", err)
		return
	}
	now := r.now()
	if facts.NotAfter.Sub(now) > r.before || (!r.lastAttempt.IsZero() && now.Sub(r.lastAttempt) < edgeRenewRetry) {
		return
	}
	r.lastAttempt = now
	csrDER, credentialJSON, err := r.prepare(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: edge renewal could not attest a fresh CSR:", err)
		return
	}
	resp, err := sender.RenewEdgeDelegation(ctx, &transport.EdgeRenewalRequest{
		Serial: facts.SerialHex, CSRDER: csrDER, AttestationCredentialJSON: credentialJSON,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-agent: edge delegation renewal refused (the delegation expires %s): %v\n",
			facts.NotAfter.UTC().Format(time.RFC3339), err)
		return
	}
	if !strings.Contains(resp.CertificatePEM, "BEGIN CERTIFICATE") {
		fmt.Fprintln(os.Stderr, "trstctl-agent: edge delegation renewal returned no certificate chain")
		return
	}
	if err := writeEdgePrivateFile(r.certPath, []byte(resp.CertificatePEM)); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: install the renewed edge delegation:", err)
		return
	}
	r.lastAttempt = time.Time{}
	fmt.Printf("trstctl-agent: edge delegation renewed as %s (serial %s, expires %s)\n",
		resp.DelegationID, resp.Serial, resp.NotAfter.UTC().Format(time.RFC3339))
}

// tpmEdgeRenewalPrepare signs a fresh CSR with the TPM key the edge handle
// names and certifies it with the AIK, as --edge-attest does for a mint.
func tpmEdgeRenewalPrepare(opts edgeCAOptions) func(ctx context.Context) ([]byte, []byte, error) {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if normalizedEdgeKeyProvider(opts.keyProvider) != "tpm2" {
			return nil, nil, fmt.Errorf("edge renewal attests with TPM2_Certify and needs a TPM2 edge CA key")
		}
		edgeHandle, err := readEdgeKeyHandle(opts.caKeyHandle)
		if err != nil {
			return nil, nil, fmt.Errorf("read edge TPM handle: %w", err)
		}
		aikHandle, err := readEdgeKeyHandle(opts.aikKeyHandle)
		if err != nil {
			return nil, nil, fmt.Errorf("read AIK TPM handle: %w", err)
		}
		chain, err := os.ReadFile(opts.aikCertChain) // #nosec G304 -- explicit operator file path
		if err != nil {
			return nil, nil, fmt.Errorf("read AIK certificate chain: %w", err)
		}
		aikAuth, err := readEdgeSecretFile(opts.aikAuthFile, false)
		if err != nil {
			return nil, nil, fmt.Errorf("read AIK authorization: %w", err)
		}
		defer secret.Wipe(aikAuth)
		provider, closeProvider, err := openEdgeCAKeyProvider(opts)
		if err != nil {
			return nil, nil, fmt.Errorf("open TPM2 edge CA provider: %w", err)
		}
		defer func() { _ = closeProvider() }()
		cn := strings.TrimSpace(opts.commonName)
		if cn == "" {
			cn = "trstctl-edge-ca"
		}
		csrDER, err := crypto.EdgeCSRForKeyHandle(ctx, edgeHandle, provider, cn)
		if err != nil {
			return nil, nil, err
		}
		certifier, ok := provider.(crypto.EdgeTPMCertifier)
		if !ok {
			return nil, nil, fmt.Errorf("TPM2 provider cannot certify a persistent edge key")
		}
		credential, err := deviceattest.CreateEdgeTPMCredential(opts.tenantID, opts.segmentID, csrDER, edgeHandle, aikHandle, chain, aikAuth, certifier)
		if err != nil {
			return nil, nil, err
		}
		return csrDER, credential, nil
	}
}

// readEdgeKeyHandle reads a public edge key handle written by --edge-csr.
func readEdgeKeyHandle(path string) (crypto.EdgeCAKeyHandle, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- explicit operator file path
	if err != nil {
		return crypto.EdgeCAKeyHandle{}, err
	}
	var handle crypto.EdgeCAKeyHandle
	if err := json.Unmarshal(raw, &handle); err != nil {
		return crypto.EdgeCAKeyHandle{}, err
	}
	return handle, nil
}
